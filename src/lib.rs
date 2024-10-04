//! Resolve addresses to function names, and to file name and line number
//! information, with the help of a PDB file. Inline stacks are supported.
//!
//! The API of this crate is intended to be similar to the API of the
//! [`addr2line` crate](https://docs.rs/addr2line/); the two [`Context`] APIs
//! have comparable functionality. This crate is for PDB files whereas `addr2line`
//! is for DWARF data (which is used in ELF and mach-o binaries, for example).
//!
//! This crate also has a [`TypeFormatter`] API which can be used to get function signature
//! strings independently from a [`Context`].
//!
//! To create a [`Context`], use [`ContextPdbData`].
//!
//! # Example
//!
//! ```
//! use pdb_addr2line::pdb; // (this is a re-export of the pdb crate)
//!
//! fn look_up_addresses<'s, S: pdb::Source<'s> + Send + 's>(stream: S, addresses: &[u32]) -> std::result::Result<(), pdb_addr2line::Error> {
//!     let pdb = pdb::PDB::open(stream)?;
//!     let context_data = pdb_addr2line::ContextPdbData::try_from_pdb(pdb)?;
//!     let context = context_data.make_context()?;
//!
//!     for address in addresses {
//!         if let Some(procedure_frames) = context.find_frames(*address)? {
//!             eprintln!("0x{:x} - {} frames:", address, procedure_frames.frames.len());
//!             for frame in procedure_frames.frames {
//!                 let line_str = frame.line.map(|l| format!("{}", l));
//!                 eprintln!(
//!                     "     {} at {}:{}",
//!                     frame.function.as_deref().unwrap_or("<unknown>"),
//!                     frame.file.as_deref().unwrap_or("??"),
//!                     line_str.as_deref().unwrap_or("??"),
//!                 )
//!             }
//!         } else {
//!             eprintln!("{:x} - no frames found", address);
//!         }
//!     }
//!     Ok(())
//! }
//! ```

pub use maybe_owned;
pub use pdb;

mod constants;
mod error;
mod type_formatter;

pub use error::Error;
pub use type_formatter::*;

use constants::*;
use elsa::sync::FrozenMap;
use maybe_owned::{MaybeOwned, MaybeOwnedMut};
use pdb::{
    AddressMap, DebugInformation, FallibleIterator, FileIndex, IdIndex, IdInformation,
    ImageSectionHeader, InlineSiteSymbol, Inlinee, LineProgram, Module, ModuleInfo,
    PdbInternalSectionOffset, PublicSymbol, RawString, Rva, Source, StringTable, SymbolData,
    SymbolIndex, SymbolIter, SymbolTable, TypeIndex, TypeInformation, PDB,
};
use range_collections::range_set::RangeSetRange;
use range_collections::{RangeSet, RangeSet2};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::LowerHex;
use std::mem;
use std::sync::{Arc, Mutex};
use std::{borrow::Cow, cell::RefCell, collections::BTreeMap};

type Result<V> = std::result::Result<V, Error>;

/// Allows to easily create a [`Context`] directly from a [`pdb::PDB`].
///
/// ```
/// # fn wrapper<'s, S: pdb::Source<'s> + Send + 's>(stream: S) -> std::result::Result<(), pdb_addr2line::Error> {
/// let pdb = pdb::PDB::open(stream)?;
/// let context_data = pdb_addr2line::ContextPdbData::try_from_pdb(pdb)?;
/// let context = context_data.make_context()?;
/// # Ok(())
/// # }
/// ```
///
/// Implementation note:
/// It would be nice if a [`Context`] could be created from a [`PDB`] directly, without
/// going through an intermediate [`ContextPdbData`] object. However, there doesn't
/// seem to be an easy way to do this, due to certain lifetime dependencies: The
/// [`Context`] object wants to store certain objects inside itself (mostly for caching)
/// which have a lifetime dependency on [`pdb::ModuleInfo`], so the [`ModuleInfo`] has to be
/// owned outside of the [`Context`]. So the [`ContextPdbData`] object acts as that external
/// [`ModuleInfo`] owner.
pub struct ContextPdbData<'p, 's, S: Source<'s> + Send + 's> {
    pdb: Mutex<MaybeOwnedMut<'p, PDB<'s, S>>>,

    /// ModuleInfo objects are stored on this object (outside Context) so that the
    /// Context can internally store objects which have a lifetime dependency on
    /// ModuleInfo, such as Inlinees, LinePrograms, and RawStrings from modules.
    module_infos: FrozenMap<usize, Box<ModuleInfo<'s>>>,

    address_map: AddressMap<'s>,
    string_table: Option<StringTable<'s>>,
    global_symbols: SymbolTable<'s>,
    debug_info: DebugInformation<'s>,
    type_info: TypeInformation<'s>,
    id_info: IdInformation<'s>,
}

// Assert that `ContextPdbData` is Send.
const _: fn() = || {
    fn assert<T: ?Sized + Send>() {}
    // Use `File` as `S` since it implements `Source` and is `Send`.
    assert::<ContextPdbData<std::fs::File>>();
};

impl<'p, 's, S: Source<'s> + Send + 's> ContextPdbData<'p, 's, S> {
    /// Create a [`ContextPdbData`] from a [`PDB`](pdb::PDB). This parses many of the PDB
    /// streams and stores them in the [`ContextPdbData`].
    /// This creator function takes ownership of the pdb object and never gives it back.
    pub fn try_from_pdb(pdb: PDB<'s, S>) -> Result<Self> {
        Self::try_from_maybe_owned(MaybeOwnedMut::Owned(pdb))
    }

    /// Create a [`ContextPdbData`] from a [`PDB`](pdb::PDB). This parses many of the PDB
    /// streams and stores them in the [`ContextPdbData`].
    /// This creator function takes an exclusive reference to the pdb object, for consumers
    /// that want to keep using the pdb object once the `ContextPdbData` object is dropped.
    pub fn try_from_pdb_ref(pdb: &'p mut PDB<'s, S>) -> Result<Self> {
        Self::try_from_maybe_owned(MaybeOwnedMut::Borrowed(pdb))
    }

    fn try_from_maybe_owned(mut pdb: MaybeOwnedMut<'p, PDB<'s, S>>) -> Result<Self> {
        let global_symbols = pdb.global_symbols()?;
        let debug_info = pdb.debug_information()?;
        let type_info = pdb.type_information()?;
        let id_info = pdb.id_information()?;
        let address_map = pdb.address_map()?;
        let string_table = pdb.string_table().ok();

        Ok(Self {
            pdb: Mutex::new(pdb),
            module_infos: FrozenMap::new(),
            global_symbols,
            debug_info,
            type_info,
            id_info,
            address_map,
            string_table,
        })
    }

    /// Create a [`TypeFormatter`]. This uses the default [`TypeFormatter`] settings.
    pub fn make_type_formatter(&self) -> Result<TypeFormatter<'_, 's>> {
        self.make_type_formatter_with_flags(Default::default())
    }

    /// Create a [`TypeFormatter`], using the specified [`TypeFormatter`] flags.
    pub fn make_type_formatter_with_flags(
        &self,
        flags: TypeFormatterFlags,
    ) -> Result<TypeFormatter<'_, 's>> {
        // Get the list of all modules. This only reads the list, not the actual module
        // info. To get the module info, you need to call pdb.module_info(&module), and
        // that's when the actual module stream is read. We use the list of modules so
        // that we can call pdb.module_info with the right module, which we look up based
        // on its module_index.
        let modules = self.debug_info.modules()?.collect::<Vec<_>>()?;

        Ok(TypeFormatter::new_from_parts(
            self,
            modules,
            &self.debug_info,
            &self.type_info,
            &self.id_info,
            self.string_table.as_ref(),
            flags,
        )?)
    }

    /// Create a [`Context`]. This uses the default [`TypeFormatter`] settings.
    pub fn make_context(&self) -> Result<Context<'_, 's>> {
        self.make_context_with_formatter_flags(Default::default())
    }

    /// Create a [`Context`], using the specified [`TypeFormatterFlags`].
    pub fn make_context_with_formatter_flags(
        &self,
        flags: TypeFormatterFlags,
    ) -> Result<Context<'_, 's>> {
        let type_formatter = self.make_type_formatter_with_flags(flags)?;
        let sections = self.pdb.lock().unwrap().sections()?;

        Context::new_from_parts(
            self,
            sections.as_deref().unwrap_or(&[]),
            &self.address_map,
            &self.global_symbols,
            self.string_table.as_ref(),
            &self.debug_info,
            MaybeOwned::Owned(type_formatter),
        )
    }
}

impl<'p, 's, S: Source<'s> + Send + 's> ModuleProvider<'s> for ContextPdbData<'p, 's, S> {
    fn get_module_info(
        &self,
        module_index: usize,
        module: &Module,
    ) -> std::result::Result<Option<&ModuleInfo<'s>>, pdb::Error> {
        if let Some(module_info) = self.module_infos.get(&module_index) {
            return Ok(Some(module_info));
        }

        let mut pdb = self.pdb.lock().unwrap();
        Ok(pdb.module_info(module)?.map(|module_info| {
            self.module_infos
                .insert(module_index, Box::new(module_info))
        }))
    }
}

/// Basic information about a function.
#[derive(Clone)]
pub struct Function {
    /// The start address of the function, as a relative address (rva).
    pub start_rva: u32,
    /// The end address of the function, if known.
    pub end_rva: Option<u32>,
    /// The function name. `None` if there was an error during stringification.
    /// If this function is based on a public symbol, the consumer may need to demangle
    /// ("undecorate") the name. This can be detected based on a leading '?' byte.
    pub name: Option<String>,
}

/// The result of an address lookup from [`Context::find_frames`].
#[derive(Clone)]
pub struct FunctionFrames<'a> {
    /// The start address of the function which contained the looked-up address.
    pub start_rva: u32,
    /// The end address of the function which contained the looked-up address, if known.
    pub end_rva: Option<u32>,
    /// The inline stack at the looked-up address, ordered from inside to outside.
    /// Always contains at least one entry: the last element is always the function
    /// which contains the looked-up address.
    pub frames: Vec<Frame<'a>>,
}

/// One frame of the inline stack at the looked-up address.
#[derive(Clone)]
pub struct Frame<'a> {
    /// The function name. `None` if there was an error during stringification.
    pub function: Option<String>,
    /// The file name, if known.
    pub file: Option<Cow<'a, str>>,
    /// The line number, if known. This is the source line inside this function
    /// that is associated with the instruction at the looked-up address.
    pub line: Option<u32>,
}

/// The main API of this crate. Resolves addresses to function information.
pub struct Context<'a, 's> {
    address_map: &'a AddressMap<'s>,
    section_contributions: Vec<ModuleSectionContribution>,
    string_table: Option<&'a StringTable<'s>>,
    type_formatter: MaybeOwned<'a, TypeFormatter<'a, 's>>,
    /// Contains an entry for hopefully every function in an executable section.
    /// The entries come from the public function symbols, and from the section
    /// contributions: We create an unnamed "placeholder" entry for each section
    /// contribution.
    global_functions: Vec<PublicSymbolFunctionOrPlaceholder<'a>>,
    cache: RefCell<ContextCache<'a, 's>>,
}

// Assert that `Context` is Send.
const _: fn() = || {
    fn assert<T: ?Sized + Send>() {}
    assert::<Context>();
};

impl<'a, 's> Context<'a, 's> {
    /// Create a [`Context`] manually. Most consumers will want to use
    /// [`ContextPdbData::make_context`] instead.
    ///
    /// However, if you interact with a PDB directly and parse some of its contents
    /// for other uses, you may want to call this method in order to avoid overhead
    /// from repeatedly parsing the same streams.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_parts(
        module_info_provider: &'a (dyn ModuleProvider<'s> + Sync),
        sections: &[ImageSectionHeader],
        address_map: &'a AddressMap<'s>,
        global_symbols: &'a SymbolTable<'s>,
        string_table: Option<&'a StringTable<'s>>,
        debug_info: &'a DebugInformation,
        type_formatter: MaybeOwned<'a, TypeFormatter<'a, 's>>,
    ) -> Result<Self> {
        let mut global_functions = Vec::new();

        // Start with the public function symbols.
        let mut symbol_iter = global_symbols.iter();
        while let Some(symbol) = symbol_iter.next()? {
            if let S_PUB32 | S_PUB32_ST = symbol.raw_kind() {
                if let Ok(SymbolData::Public(PublicSymbol { name, offset, .. })) = symbol.parse() {
                    if is_executable_section(offset.section, sections) {
                        global_functions.push(PublicSymbolFunctionOrPlaceholder {
                            start_offset: offset,
                            name: Some(name),
                        });
                    }
                }
            }
        }

        // Read the section contributions. This will let us find the right module
        // based on the PdbSectionInternalOffset that corresponds to the looked-up
        // address. This allows reading module info on demand.
        // The section contributions also give us more function start addresses. We
        // create placeholder symbols for them so we don't account missing functions to
        // the nearest public function, and so that we can find line information for
        // those missing functions if present.
        let section_contributions =
            compute_section_contributions(debug_info, sections, &mut global_functions)?;

        // Add a few more placeholder entries for the end addresses of executable sections.
        // These act as terminator addresses for the last function in a section.
        for (section_index_zero_based, section) in sections.iter().enumerate() {
            let section_index = (section_index_zero_based + 1) as u16;
            if !is_executable_section(section_index, sections) {
                continue;
            }
            let size = section.virtual_size;
            let section_end_offset = PdbInternalSectionOffset::new(section_index, size);
            global_functions.push(PublicSymbolFunctionOrPlaceholder {
                start_offset: section_end_offset,
                name: None,
            });
        }

        // Sort and de-duplicate, so that we can use binary search during lookup.
        // If we have both a public symbol and a placeholder symbol at the same offset,
        // make it so that the symbol with name comes first, so that we keep it during
        // the deduplication.
        global_functions.sort_unstable_by_key(|p| {
            (
                p.start_offset.section,
                p.start_offset.offset,
                p.name.is_none(),
            )
        });
        global_functions.dedup_by_key(|p| p.start_offset);

        Ok(Self {
            address_map,
            section_contributions,
            string_table,
            type_formatter,
            global_functions,
            cache: RefCell::new(ContextCache {
                module_cache: BasicModuleInfoCache {
                    cache: Default::default(),
                    module_info_provider,
                },
                function_line_cache: Default::default(),
                procedure_cache: Default::default(),
                extended_module_cache: Default::default(),
                inline_name_cache: Default::default(),
                full_rva_list: Default::default(),
            }),
        })
    }

    /// The number of functions found in public symbols.
    pub fn function_count(&self) -> usize {
        self.global_functions.len()
    }

    /// Iterate over all functions in the modules.
    pub fn functions(&self) -> FunctionIter<'_, 'a, 's> {
        let mut cache = self.cache.borrow_mut();
        let ContextCache {
            full_rva_list,
            module_cache,
            ..
        } = &mut *cache;
        let full_rva_list = full_rva_list
            .get_or_insert_with(|| Arc::new(self.compute_full_rva_list(module_cache)))
            .clone();
        FunctionIter {
            context: self,
            full_rva_list,
            cur_index: 0,
        }
    }

    /// Find the function whose code contains the provided address.
    /// The return value only contains the function name and the rva range, but
    /// no file or line information.
    pub fn find_function(&self, probe: u32) -> Result<Option<Function>> {
        let offset = match Rva(probe).to_internal_offset(self.address_map) {
            Some(offset) => offset,
            None => return Ok(None),
        };

        let mut cache = self.cache.borrow_mut();
        let ContextCache {
            module_cache,
            procedure_cache,
            ..
        } = &mut *cache;

        let func = match self.lookup_function(offset, module_cache) {
            Some(func) => func,
            None => return Ok(None),
        };

        match func {
            PublicOrProcedureSymbol::Public(_, _, global_function_index) => {
                let func = &self.global_functions[global_function_index];
                let name = func.name.map(|name| name.to_string().to_string());
                let start_rva = match func.start_offset.to_rva(self.address_map) {
                    Some(rva) => rva.0,
                    None => return Ok(None),
                };
                // Get the end address from the address of the next entry in the global function list.
                let end_rva = match self.global_functions.get(global_function_index + 1) {
                    Some(next_entry)
                        if next_entry.start_offset.section == func.start_offset.section =>
                    {
                        match next_entry.start_offset.to_rva(self.address_map) {
                            Some(rva) => Some(rva.0),
                            None => return Ok(None),
                        }
                    }
                    _ => None,
                };
                Ok(Some(Function {
                    start_rva,
                    end_rva,
                    name,
                }))
            }
            PublicOrProcedureSymbol::Procedure(module_index, _, func) => {
                let extended_info = procedure_cache.entry(func.offset).or_default();
                let name = extended_info
                    .get_name(
                        func,
                        &self.type_formatter,
                        &self.global_functions,
                        module_index,
                    )
                    .map(String::from);
                let start_rva = match func.offset.to_rva(self.address_map) {
                    Some(rva) => rva.0,
                    None => return Ok(None),
                };
                let end_rva = start_rva + func.len;
                Ok(Some(Function {
                    start_rva,
                    end_rva: Some(end_rva),
                    name,
                }))
            }
        }
    }

    /// Find information about the source code which generated the instruction at the
    /// provided address. This information includes the function name, file name and
    /// line number, of the containing procedure and of any functions that were inlined
    /// into the procedure by the compiler, at that address.
    ///
    /// A lot of information is cached so that repeated calls are fast.
    pub fn find_frames(&self, probe: u32) -> Result<Option<FunctionFrames>> {
        let offset = match Rva(probe).to_internal_offset(self.address_map) {
            Some(offset) => offset,
            None => return Ok(None),
        };

        let mut cache = self.cache.borrow_mut();
        let ContextCache {
            module_cache,
            procedure_cache,
            function_line_cache,
            extended_module_cache,
            inline_name_cache,
            ..
        } = &mut *cache;

        let func = match self.lookup_function(offset, module_cache) {
            Some(func) => func,
            None => return Ok(None),
        };

        // We can have a pretty wild mix of available information, depending on what's in
        // the PDB file.
        //  - Some PDBs have everything.
        //  - Some PDBs only have public symbols and no modules at all, so no procedures
        //    and no file / line info.
        //  - Some PDBs have public symbols and modules, but the modules only have file /
        //    line info and no procedures.
        let (module_index, module_info, func_offset, func_size, func_name, proc_stuff) = match func
        {
            PublicOrProcedureSymbol::Public(module_index, module_info, global_function_index) => {
                let func = &self.global_functions[global_function_index];
                let func_name = func.name.map(|name| name.to_string().to_string());
                // Get the function size from the address of the next entry in the global function list.
                let size = match self.global_functions.get(global_function_index + 1) {
                    Some(next_entry)
                        if next_entry.start_offset.section == func.start_offset.section =>
                    {
                        Some(next_entry.start_offset.offset - func.start_offset.offset)
                    }
                    _ => None,
                };
                (
                    module_index,
                    module_info,
                    func.start_offset,
                    size,
                    func_name,
                    None,
                )
            }
            PublicOrProcedureSymbol::Procedure(module_index, module_info, proc) => {
                let proc_extended_info = procedure_cache.entry(proc.offset).or_default();
                let func_name = proc_extended_info
                    .get_name(
                        proc,
                        &self.type_formatter,
                        &self.global_functions,
                        module_index,
                    )
                    .map(String::from);
                (
                    module_index,
                    Some(module_info),
                    proc.offset,
                    Some(proc.len),
                    func_name,
                    Some((proc, proc_extended_info)),
                )
            }
        };

        let extended_module_info = match module_info {
            Some(module_info) => Some(
                extended_module_cache
                    .entry(module_index)
                    .or_insert_with(|| self.compute_extended_module_info(module_info))
                    .as_mut()
                    .map_err(|err| mem::replace(err, Error::ExtendedModuleInfoUnsuccessful))?,
            ),
            None => None,
        };

        let (file, line) = if let Some(ExtendedModuleInfo { line_program, .. }) =
            &extended_module_info
        {
            let function_line_info = function_line_cache.entry(func_offset).or_default();
            let lines = function_line_info.get_lines(func_offset, line_program)?;
            let search = match lines.binary_search_by_key(&offset.offset, |li| li.start_offset) {
                Err(0) => None,
                Ok(i) => Some(i),
                Err(i) => Some(i - 1),
            };
            match search {
                Some(index) => {
                    let line_info = &lines[index];
                    (
                        self.resolve_filename(line_program, line_info.file_index),
                        Some(line_info.line_start),
                    )
                }
                None => (None, None),
            }
        } else {
            (None, None)
        };

        let frame = Frame {
            function: func_name,
            file,
            line,
        };

        // Ordered outside to inside, until just before the end of this function.
        let mut frames = vec![frame];

        if let (Some((proc, proc_extended_info)), Some(extended_module_info)) =
            (proc_stuff, extended_module_info)
        {
            let ExtendedModuleInfo {
                inlinees,
                line_program,
                module_info,
                ..
            } = extended_module_info;
            let mut inline_ranges =
                proc_extended_info.get_inline_ranges(module_info, proc, inlinees)?;

            loop {
                let current_depth = (frames.len() - 1) as u16;

                // Look up (offset.offset, current_depth) in inline_ranges.
                // `inlined_addresses` is sorted in "breadth-first traversal order", i.e.
                // by `call_depth` first, and then by `start_offset`. See the comment at
                // the sort call for more information about why.
                let search = inline_ranges.binary_search_by(|range| {
                    if range.call_depth > current_depth {
                        Ordering::Greater
                    } else if range.call_depth < current_depth {
                        Ordering::Less
                    } else if range.start_offset > offset.offset {
                        Ordering::Greater
                    } else if range.end_offset <= offset.offset {
                        Ordering::Less
                    } else {
                        Ordering::Equal
                    }
                });
                let (inline_range, remainder) = match search {
                    Ok(index) => (&inline_ranges[index], &inline_ranges[index + 1..]),
                    Err(_) => break,
                };

                let function = inline_name_cache
                    .entry(inline_range.inlinee)
                    .or_insert_with(|| {
                        self.type_formatter
                            .format_id(module_index, inline_range.inlinee)
                    })
                    .as_ref()
                    .ok()
                    .cloned();
                let file = inline_range
                    .file_index
                    .and_then(|file_index| self.resolve_filename(line_program, file_index));
                let line = inline_range.line_start;
                frames.push(Frame {
                    function,
                    file,
                    line,
                });

                inline_ranges = remainder;
            }

            // Now order from inside to outside.
            frames.reverse();
        }

        let start_rva = match func_offset.to_rva(self.address_map) {
            Some(rva) => rva.0,
            None => return Ok(None),
        };
        let end_rva = func_size.and_then(|size| start_rva.checked_add(size));

        Ok(Some(FunctionFrames {
            start_rva,
            end_rva,
            frames,
        }))
    }

    fn compute_full_rva_list(&self, module_cache: &mut BasicModuleInfoCache<'a, 's>) -> Vec<u32> {
        let mut list = Vec::new();
        for func in &self.global_functions {
            if let Some(rva) = func.start_offset.to_rva(self.address_map) {
                list.push(rva.0);
            }
        }
        for module_index in 0..self.type_formatter.modules().len() {
            if let Some(BasicModuleInfo { procedures, .. }) =
                module_cache.get_basic_module_info(self.type_formatter.modules(), module_index)
            {
                for proc in procedures {
                    if let Some(rva) = proc.offset.to_rva(self.address_map) {
                        list.push(rva.0);
                    }
                }
            }
        }
        list.sort_unstable();
        list.dedup();
        list
    }

    fn lookup_function<'m>(
        &self,
        offset: PdbInternalSectionOffset,
        module_cache: &'m mut BasicModuleInfoCache<'a, 's>,
    ) -> Option<PublicOrProcedureSymbol<'a, 's, 'm>> {
        let sc_index = match self.section_contributions.binary_search_by(|sc| {
            if sc.section_index < offset.section {
                Ordering::Less
            } else if sc.section_index > offset.section {
                Ordering::Greater
            } else if sc.end_offset <= offset.offset {
                Ordering::Less
            } else if sc.start_offset > offset.offset {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        }) {
            Ok(sc_index) => sc_index,
            Err(_) => {
                // The requested address is not present in any section contribution.
                return None;
            }
        };

        let sc = &self.section_contributions[sc_index];
        let basic_module_info =
            module_cache.get_basic_module_info(self.type_formatter.modules(), sc.module_index);

        let module_info = if let Some(BasicModuleInfo {
            procedures,
            module_info,
        }) = basic_module_info
        {
            if let Ok(procedure_index) = procedures.binary_search_by(|p| {
                if p.offset.section < offset.section {
                    Ordering::Less
                } else if p.offset.section > offset.section {
                    Ordering::Greater
                } else if p.offset.offset + p.len <= offset.offset {
                    Ordering::Less
                } else if p.offset.offset > offset.offset {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            }) {
                // Found a procedure at the requested offset.
                return Some(PublicOrProcedureSymbol::Procedure(
                    sc.module_index,
                    module_info,
                    &procedures[procedure_index],
                ));
            }
            Some(*module_info)
        } else {
            None
        };

        // No procedure was found at this offset in the module that the section
        // contribution pointed us at.
        // This is not uncommon.
        // Fall back to the public symbols.

        let last_global_function_starting_lte_address = match self
            .global_functions
            .binary_search_by_key(&(offset.section, offset.offset), |p| {
                (p.start_offset.section, p.start_offset.offset)
            }) {
            Err(0) => return None,
            Ok(i) => i,
            Err(i) => i - 1,
        };
        let fun = &self.global_functions[last_global_function_starting_lte_address];
        debug_assert!(
            fun.start_offset.section < offset.section
                || (fun.start_offset.section == offset.section
                    && fun.start_offset.offset <= offset.offset)
        );
        if fun.start_offset.section != offset.section {
            return None;
        }
        // Ignore symbols outside the section contribution.
        if fun.start_offset.offset < sc.start_offset {
            return None;
        }

        Some(PublicOrProcedureSymbol::Public(
            sc.module_index,
            module_info,
            last_global_function_starting_lte_address,
        ))
    }

    fn compute_extended_module_info(
        &self,
        module_info: &'a ModuleInfo<'s>,
    ) -> Result<ExtendedModuleInfo<'a, 's>> {
        let line_program = module_info.line_program()?;

        let inlinees: BTreeMap<IdIndex, Inlinee> = module_info
            .inlinees()?
            .map(|i| Ok((i.index(), i)))
            .collect()?;

        Ok(ExtendedModuleInfo {
            module_info,
            inlinees,
            line_program,
        })
    }

    fn resolve_filename(
        &self,
        line_program: &LineProgram,
        file_index: FileIndex,
    ) -> Option<Cow<'a, str>> {
        if let Some(string_table) = self.string_table {
            if let Ok(file_info) = line_program.get_file_info(file_index) {
                return file_info.name.to_string_lossy(string_table).ok();
            }
        }
        None
    }
}

/// An iterator over all functions in a [`Context`].
#[derive(Clone)]
pub struct FunctionIter<'c, 'a, 's> {
    context: &'c Context<'a, 's>,
    full_rva_list: Arc<Vec<u32>>,
    cur_index: usize,
}

impl<'c, 'a, 's> Iterator for FunctionIter<'c, 'a, 's> {
    type Item = Function;

    fn next(&mut self) -> Option<Function> {
        loop {
            if self.cur_index >= self.full_rva_list.len() {
                return None;
            }
            let rva = self.full_rva_list[self.cur_index];
            self.cur_index += 1;
            if let Ok(Some(fun)) = self.context.find_function(rva) {
                return Some(fun);
            }
        }
    }
}

struct ContextCache<'a, 's> {
    module_cache: BasicModuleInfoCache<'a, 's>,
    function_line_cache: HashMap<PdbInternalSectionOffset, FunctionLineInfo>,
    procedure_cache: HashMap<PdbInternalSectionOffset, ExtendedProcedureInfo>,
    extended_module_cache: BTreeMap<usize, Result<ExtendedModuleInfo<'a, 's>>>,
    inline_name_cache: BTreeMap<IdIndex, Result<String>>,
    full_rva_list: Option<Arc<Vec<u32>>>,
}

struct BasicModuleInfoCache<'a, 's> {
    cache: HashMap<usize, Option<BasicModuleInfo<'a, 's>>>,
    module_info_provider: &'a (dyn ModuleProvider<'s> + Sync),
}

impl<'a, 's> BasicModuleInfoCache<'a, 's> {
    pub fn get_basic_module_info(
        &mut self,
        modules: &[Module<'a>],
        module_index: usize,
    ) -> Option<&BasicModuleInfo<'a, 's>> {
        // TODO: 2021 edition
        let module_info_provider = self.module_info_provider;

        self.cache
            .entry(module_index)
            .or_insert_with(|| {
                let module = modules.get(module_index)?;
                let module_info = module_info_provider
                    .get_module_info(module_index, module)
                    .ok()??;
                BasicModuleInfo::try_from_module_info(module_info).ok()
            })
            .as_ref()
    }
}

struct BasicModuleInfo<'a, 's> {
    module_info: &'a ModuleInfo<'s>,
    procedures: Vec<ProcedureSymbolFunction<'a>>,
}

impl<'a, 's> BasicModuleInfo<'a, 's> {
    pub fn try_from_module_info(
        module_info: &'a ModuleInfo<'s>,
    ) -> Result<BasicModuleInfo<'a, 's>> {
        let mut symbols_iter = module_info.symbols()?;
        let mut functions = Vec::new();
        while let Some(symbol) = symbols_iter.next()? {
            if let S_LPROC32 | S_LPROC32_ST | S_GPROC32 | S_GPROC32_ST | S_LPROC32_ID
            | S_GPROC32_ID | S_LPROC32_DPC | S_LPROC32_DPC_ID | S_THUNK32 | S_THUNK32_ST
            | S_SEPCODE = symbol.raw_kind()
            {
                match symbol.parse() {
                    Ok(SymbolData::Procedure(proc)) => {
                        if proc.len == 0 {
                            continue;
                        }

                        functions.push(ProcedureSymbolFunction {
                            offset: proc.offset,
                            len: proc.len,
                            name: proc.name,
                            symbol_index: symbol.index(),
                            end_symbol_index: proc.end,
                            type_index: proc.type_index,
                        });
                    }
                    Ok(SymbolData::SeparatedCode(data)) => {
                        if data.len == 0 {
                            continue;
                        }

                        // SeparatedCode references another procedure with data.parent_offset.
                        // Usually the SeparatedCode symbol comes right after the referenced symbol.
                        // Take the name and type_index from the referenced procedure.
                        let (name, type_index) = match functions.last() {
                            Some(proc) if proc.offset == data.parent_offset => {
                                (proc.name, proc.type_index)
                            }
                            _ => continue,
                        };

                        functions.push(ProcedureSymbolFunction {
                            offset: data.offset,
                            len: data.len,
                            name,
                            symbol_index: symbol.index(),
                            end_symbol_index: data.end,
                            type_index,
                        });
                    }
                    Ok(SymbolData::Thunk(thunk)) => {
                        if thunk.len == 0 {
                            continue;
                        }

                        // Treat thunks as procedures. This isn't perfectly accurate but it
                        // doesn't cause any harm.
                        functions.push(ProcedureSymbolFunction {
                            offset: thunk.offset,
                            len: thunk.len as u32,
                            name: thunk.name,
                            symbol_index: symbol.index(),
                            end_symbol_index: thunk.end,
                            type_index: TypeIndex(0),
                        });
                    }
                    _ => {}
                }
            }
        }
        // Sort and de-duplicate, so that we can use binary search during lookup.
        functions.sort_unstable_by_key(|p| (p.offset.section, p.offset.offset));
        functions.dedup_by_key(|p| p.offset);

        Ok(BasicModuleInfo {
            module_info,
            procedures: functions,
        })
    }
}

/// The order of the fields matters for the lexicographical sort.
#[derive(Debug, Clone, PartialOrd, PartialEq, Eq, Ord)]
pub struct ModuleSectionContribution {
    section_index: u16,
    start_offset: u32,
    end_offset: u32,
    module_index: usize,
}

/// Returns an array of non-overlapping `ModuleSectionContribution` objects,
/// sorted by section and then by start offset.
/// Contributions from the same module to the same section are combined into
/// one contiguous contribution. The hope is that there is no interleaving,
/// and this function returns an error if any interleaving is detected.
fn compute_section_contributions(
    debug_info: &DebugInformation<'_>,
    sections: &[ImageSectionHeader],
    placeholder_functions: &mut Vec<PublicSymbolFunctionOrPlaceholder>,
) -> Result<Vec<ModuleSectionContribution>> {
    let mut section_contribution_iter = debug_info
        .section_contributions()?
        .filter(|sc| Ok(sc.size != 0 && is_executable_section(sc.offset.section, sections)));
    let mut section_contributions = Vec::new();

    if let Some(first_sc) = section_contribution_iter.next()? {
        let mut current_combined_sc = ModuleSectionContribution {
            section_index: first_sc.offset.section,
            start_offset: first_sc.offset.offset,
            end_offset: first_sc.offset.offset + first_sc.size,
            module_index: first_sc.module,
        };
        let mut is_executable = is_executable_section(first_sc.offset.section, sections);

        // Assume that section contributions from the same section and module are
        // sorted and non-interleaved.
        while let Some(sc) = section_contribution_iter.next()? {
            let section_index = sc.offset.section;
            let start_offset = sc.offset.offset;
            let end_offset = start_offset + sc.size;
            let module_index = sc.module;
            if section_index == current_combined_sc.section_index
                && module_index == current_combined_sc.module_index
            {
                // Enforce ordered contributions. If you find a pdb where this errors out,
                // please file an issue.
                if end_offset < current_combined_sc.end_offset {
                    return Err(Error::UnorderedSectionContributions(
                        module_index,
                        section_index,
                    ));
                }

                // Combine with current section contribution.
                current_combined_sc.end_offset = end_offset;
            } else {
                section_contributions.push(current_combined_sc);
                current_combined_sc = ModuleSectionContribution {
                    section_index: sc.offset.section,
                    start_offset: sc.offset.offset,
                    end_offset,
                    module_index: sc.module,
                };
                is_executable = is_executable_section(sc.offset.section, sections);
            }

            if is_executable {
                placeholder_functions.push(PublicSymbolFunctionOrPlaceholder {
                    start_offset: sc.offset,
                    name: None,
                });
            }
        }
        section_contributions.push(current_combined_sc);
    }

    // Sort. This sorts by section index first, and then start offset within the section.
    section_contributions.sort_unstable();

    // Enforce no overlap. If you encounter a PDB where this errors out, please file an issue.
    if let Some((first_sc, rest)) = section_contributions.split_first() {
        let mut prev_sc = first_sc;
        for sc in rest {
            if sc.section_index == prev_sc.section_index && sc.start_offset < prev_sc.end_offset {
                return Err(Error::OverlappingSectionContributions(
                    sc.section_index,
                    prev_sc.module_index,
                    sc.module_index,
                ));
            }
            prev_sc = sc;
        }
    }

    Ok(section_contributions)
}

/// section_index is a 1-based index from PdbInternalSectionOffset.
fn get_section(section_index: u16, sections: &[ImageSectionHeader]) -> Option<&ImageSectionHeader> {
    if section_index == 0 {
        None
    } else {
        sections.get((section_index - 1) as usize)
    }
}

/// section_index is a 1-based index from PdbInternalSectionOffset.
fn is_executable_section(section_index: u16, sections: &[ImageSectionHeader]) -> bool {
    match get_section(section_index, sections) {
        Some(section) => section.characteristics.execute(), // TODO: should this use .executable()?
        None => false,
    }
}

/// Offset and name of a function from a public symbol, or from a placeholder symbol from
/// the section contributions.
#[derive(Clone, Debug)]
struct PublicSymbolFunctionOrPlaceholder<'s> {
    /// The address at which this function starts, as a section internal offset. The end
    /// address for global function symbols is not known. During symbol lookup, if the address
    /// is not covered by a procedure symbol (for those, the end addresses are known), then
    /// we assume that functions with no end address cover the range up to the next function.
    start_offset: PdbInternalSectionOffset,
    /// The symbol name of the public symbol. This is the mangled ("decorated") function signature.
    /// None if this is a placeholder.
    name: Option<RawString<'s>>,
}

#[derive(Clone, Debug)]
struct ProcedureSymbolFunction<'a> {
    /// The address at which this function starts, as a section internal offset.
    offset: PdbInternalSectionOffset,
    /// The length of this function, in bytes, beginning from start_offset.
    len: u32,
    /// The symbol name. If type_index is 0, then this can be the mangled ("decorated")
    /// function signature from a PublicSymbol or from a Thunk. If type_index is non-zero,
    /// name is just the function name, potentially including class scope and namespace,
    /// but no args. The args are then found in the type.
    name: RawString<'a>,
    /// The index of the ProcedureSymbol. This allows starting a symbol iteration
    /// cheaply from this symbol, for example to find subsequent symbols about
    /// inlines in this procedure.
    symbol_index: SymbolIndex,
    /// The index of the symbol that ends this procedure. This is where the symbol
    /// iteration should stop.
    end_symbol_index: SymbolIndex,
    /// The type of this procedure, or 0. This is needed to get the arguments for the
    /// function signature.
    type_index: TypeIndex,
}

enum PublicOrProcedureSymbol<'a, 's, 'm> {
    Public(usize, Option<&'a ModuleInfo<'s>>, usize),
    Procedure(usize, &'a ModuleInfo<'s>, &'m ProcedureSymbolFunction<'a>),
}

#[derive(Default)]
struct FunctionLineInfo {
    lines: Option<Result<Vec<CachedLineInfo>>>,
}

impl FunctionLineInfo {
    fn get_lines(
        &mut self,
        function_offset: PdbInternalSectionOffset,
        line_program: &LineProgram,
    ) -> Result<&[CachedLineInfo]> {
        let lines = self
            .lines
            .get_or_insert_with(|| {
                let mut iterator = line_program.lines_for_symbol(function_offset);
                let mut lines = Vec::new();
                let mut next_item = iterator.next()?;
                while let Some(line_info) = next_item {
                    next_item = iterator.next()?;
                    lines.push(CachedLineInfo {
                        start_offset: line_info.offset.offset,
                        file_index: line_info.file_index,
                        line_start: line_info.line_start,
                    });
                }
                Ok(lines)
            })
            .as_mut()
            .map_err(|e| mem::replace(e, Error::ProcedureLinesUnsuccessful))?;
        Ok(lines)
    }
}

#[derive(Default)]
struct ExtendedProcedureInfo {
    name: Option<Option<String>>,
    inline_ranges: Option<Result<Vec<InlineRange>>>,
}

impl ExtendedProcedureInfo {
    fn get_name(
        &mut self,
        proc: &ProcedureSymbolFunction,
        type_formatter: &TypeFormatter,
        global_functions: &[PublicSymbolFunctionOrPlaceholder],
        module_index: usize,
    ) -> Option<&str> {
        self.name
            .get_or_insert_with(|| {
                if proc.type_index == TypeIndex(0) && !proc.name.as_bytes().starts_with(b"?") {
                    // We have no type, so proc.name might be an argument-less string.
                    // If we have a public symbol at this address which is a decorated name
                    // (starts with a '?'), prefer to use that because it'll usually include
                    // the arguments.
                    if let Ok(public_fun_index) = global_functions
                        .binary_search_by_key(&(proc.offset.section, proc.offset.offset), |f| {
                            (f.start_offset.section, f.start_offset.offset)
                        })
                    {
                        if let Some(name) = global_functions[public_fun_index].name {
                            if name.as_bytes().starts_with(b"?") {
                                return Some(name.to_string().to_string());
                            }
                        }
                    }
                }
                type_formatter
                    .format_function(&proc.name.to_string(), module_index, proc.type_index)
                    .ok()
            })
            .as_deref()
    }

    fn get_inline_ranges(
        &mut self,
        module_info: &ModuleInfo,
        proc: &ProcedureSymbolFunction,
        inlinees: &BTreeMap<IdIndex, Inlinee>,
    ) -> Result<&[InlineRange]> {
        let inline_ranges = self
            .inline_ranges
            .get_or_insert_with(|| compute_procedure_inline_ranges(module_info, proc, inlinees))
            .as_mut()
            .map_err(|e| mem::replace(e, Error::ProcedureInlineRangesUnsuccessful))?;
        Ok(inline_ranges)
    }
}

fn compute_procedure_inline_ranges(
    module_info: &ModuleInfo,
    proc: &ProcedureSymbolFunction,
    inlinees: &BTreeMap<IdIndex, Inlinee>,
) -> Result<Vec<InlineRange>> {
    let mut lines = Vec::new();
    let mut symbols_iter = module_info.symbols_at(proc.symbol_index)?;
    let _proc_sym = symbols_iter.next()?;
    while let Some(symbol) = symbols_iter.next()? {
        if symbol.index() >= proc.end_symbol_index {
            break;
        }
        if let S_LPROC32 | S_LPROC32_ST | S_GPROC32 | S_GPROC32_ST | S_LPROC32_ID | S_GPROC32_ID
        | S_LPROC32_DPC | S_LPROC32_DPC_ID | S_INLINESITE | S_INLINESITE2 = symbol.raw_kind()
        {
            match symbol.parse() {
                Ok(SymbolData::Procedure(p)) => {
                    // This is a nested procedure. Skip it.
                    symbols_iter.skip_to(p.end)?;
                }
                Ok(SymbolData::InlineSite(site)) => {
                    process_inlinee_symbols(
                        &mut symbols_iter,
                        inlinees,
                        proc.offset,
                        site,
                        0,
                        &mut lines,
                    )?;
                }
                _ => {}
            }
        }
    }

    lines.sort_unstable_by(|r1, r2| {
        if r1.call_depth < r2.call_depth {
            Ordering::Less
        } else if r1.call_depth > r2.call_depth {
            Ordering::Greater
        } else if r1.start_offset < r2.start_offset {
            Ordering::Less
        } else if r1.start_offset > r2.start_offset {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    });

    Ok(lines)
}

fn process_inlinee_symbols(
    symbols_iter: &mut SymbolIter,
    inlinees: &BTreeMap<IdIndex, Inlinee>,
    proc_offset: PdbInternalSectionOffset,
    site: InlineSiteSymbol,
    call_depth: u16,
    lines: &mut Vec<InlineRange>,
) -> Result<RangeSet2<u32>> {
    let mut ranges = RangeSet2::empty();
    let mut file_index = None;
    if let Some(inlinee) = inlinees.get(&site.inlinee) {
        let mut iter = inlinee.lines(proc_offset, &site);
        while let Ok(Some(line_info)) = iter.next() {
            let length = match line_info.length {
                Some(0) | None => {
                    continue;
                }
                Some(l) => l,
            };
            let start_offset = line_info.offset.offset;
            let end_offset = line_info.offset.offset + length;
            lines.push(InlineRange {
                start_offset,
                end_offset,
                call_depth,
                inlinee: site.inlinee,
                file_index: Some(line_info.file_index),
                line_start: Some(line_info.line_start),
            });
            ranges |= RangeSet::from(start_offset..end_offset);
            if file_index.is_none() {
                file_index = Some(line_info.file_index);
            }
        }
    }

    let mut callee_ranges = RangeSet2::empty();
    while let Some(symbol) = symbols_iter.next()? {
        if symbol.index() >= site.end {
            break;
        }
        if let S_LPROC32 | S_LPROC32_ST | S_GPROC32 | S_GPROC32_ST | S_LPROC32_ID | S_GPROC32_ID
        | S_LPROC32_DPC | S_LPROC32_DPC_ID | S_INLINESITE | S_INLINESITE2 = symbol.raw_kind()
        {
            match symbol.parse() {
                Ok(SymbolData::Procedure(p)) => {
                    // This is a nested procedure. Skip it.
                    symbols_iter.skip_to(p.end)?;
                }
                Ok(SymbolData::InlineSite(site)) => {
                    callee_ranges |= process_inlinee_symbols(
                        symbols_iter,
                        inlinees,
                        proc_offset,
                        site,
                        call_depth + 1,
                        lines,
                    )?;
                }
                _ => {}
            }
        }
    }

    if !ranges.is_superset(&callee_ranges) {
        // Workaround bad debug info.
        let missing_ranges: RangeSet2<u32> = &callee_ranges - &ranges;
        for range in missing_ranges.iter() {
            let (start_offset, end_offset) = match range {
                RangeSetRange::Range(r) => (*r.start, *r.end),
                other => {
                    panic!("Unexpected range bounds {:?}", other);
                }
            };
            lines.push(InlineRange {
                start_offset,
                end_offset,
                call_depth,
                inlinee: site.inlinee,
                file_index,
                line_start: None,
            });
        }
        ranges |= missing_ranges;
    }

    Ok(ranges)
}

struct ExtendedModuleInfo<'a, 's> {
    module_info: &'a ModuleInfo<'s>,
    inlinees: BTreeMap<IdIndex, Inlinee<'a>>,
    line_program: LineProgram<'a>,
}

#[derive(Clone, Debug)]
struct CachedLineInfo {
    pub start_offset: u32,
    pub file_index: FileIndex,
    pub line_start: u32,
}

struct HexNum<N: LowerHex>(pub N);

impl<N: LowerHex> std::fmt::Debug for HexNum<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

/// A contiguous address range covering a line record inside an
/// inlined function call. These are meaningful in the context of the
/// outer function which contains these inline calls; specifically, the
/// offsets are expressed relative to the same section that the outer
/// function is in.
#[derive(Clone)]
struct InlineRange {
    /// The section-internal offset of the start of the range,
    /// relative to the section that the outer function is in.
    pub start_offset: u32,
    /// The section-internal offset of the end of the range,
    /// relative to the section that the outer function is in.
    pub end_offset: u32,
    pub call_depth: u16,
    pub inlinee: IdIndex,
    pub file_index: Option<FileIndex>,
    pub line_start: Option<u32>,
}

impl std::fmt::Debug for InlineRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineRange")
            .field("start_offset", &HexNum(self.start_offset))
            .field("end_offset", &HexNum(self.end_offset))
            .field("call_depth", &self.call_depth)
            .field("inlinee", &self.inlinee)
            .field("file_index", &self.file_index)
            .field("line_start", &self.line_start)
            .finish()
    }
}
