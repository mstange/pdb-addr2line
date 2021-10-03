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
//! use pdb_addr2line::pdb;
//!
//! fn look_up_addresses<'s, S: pdb::Source<'s> + 's>(stream: S, addresses: &[u32]) -> std::result::Result<(), pdb_addr2line::Error> {
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

mod error;
mod type_formatter;

pub use error::Error;
pub use type_formatter::*;

use elsa::FrozenMap;
use maybe_owned::{MaybeOwned, MaybeOwnedMut};
use pdb::{
    AddressMap, DebugInformation, FallibleIterator, FileIndex, IdIndex, IdInformation,
    ImageSectionHeader, InlineSiteSymbol, Inlinee, LineProgram, Module, ModuleInfo,
    PdbInternalSectionOffset, PublicSymbol, RawString, Rva, Source, StringTable, SymbolData,
    SymbolIndex, SymbolIter, SymbolTable, TypeIndex, TypeInformation, PDB,
};
use range_collections::RangeSet;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::mem;
use std::ops::Bound;
use std::rc::Rc;
use std::{borrow::Cow, cell::RefCell, collections::BTreeMap};

type Result<V> = std::result::Result<V, Error>;

/// Allows to easily create a [`Context`] directly from a [`pdb::PDB`].
///
/// ```
/// # fn wrapper<'s, S: pdb::Source<'s> + 's>(stream: S) -> std::result::Result<(), pdb_addr2line::Error> {
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
pub struct ContextPdbData<'p, 's, S: Source<'s> + 's> {
    pdb: RefCell<MaybeOwnedMut<'p, PDB<'s, S>>>,

    /// ModuleInfo objects are stored on this object (outside Context) so that the
    /// Context can internally store objects which have a lifetime dependency on
    /// ModuleInfo, such as Inlinees, LinePrograms, and RawStrings from modules.
    module_infos: FrozenMap<u16, Box<ModuleInfo<'s>>>,

    address_map: AddressMap<'s>,
    string_table: Option<StringTable<'s>>,
    global_symbols: SymbolTable<'s>,
    debug_info: DebugInformation<'s>,
    type_info: TypeInformation<'s>,
    id_info: IdInformation<'s>,
}

impl<'p, 's, S: Source<'s> + 's> ContextPdbData<'p, 's, S> {
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
            pdb: RefCell::new(pdb),
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
        let modules = Rc::new(modules);

        Ok(TypeFormatter::new_from_parts(
            self,
            modules.clone(),
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

    /// Create a [`Context`], using the specified [`TypeFormatter`] flags.
    pub fn make_context_with_formatter_flags(
        &self,
        flags: TypeFormatterFlags,
    ) -> Result<Context<'_, 's>> {
        let type_formatter = self.make_type_formatter_with_flags(flags)?;
        let modules = type_formatter.modules.clone();
        let sections = self.pdb.borrow_mut().sections()?;

        Context::new_from_parts(
            self,
            sections.as_deref().unwrap_or(&[]),
            &self.address_map,
            &self.global_symbols,
            self.string_table.as_ref(),
            &self.debug_info,
            MaybeOwned::Owned(type_formatter),
            modules,
        )
    }
}

impl<'p, 's, S: Source<'s> + 's> ModuleProvider<'s> for ContextPdbData<'p, 's, S> {
    fn get_module_info(
        &self,
        module_index: u16,
        module: &Module,
    ) -> std::result::Result<Option<&ModuleInfo<'s>>, pdb::Error> {
        if let Some(module_info) = self.module_infos.get(&module_index) {
            return Ok(Some(module_info));
        }

        let mut pdb = self.pdb.borrow_mut();
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
    public_functions: Vec<PublicSymbolFunction<'a>>,
    cache: RefCell<ContextCache<'a, 's>>,
}

impl<'a, 's> Context<'a, 's> {
    /// Create a [`Context`] manually. Most consumers will want to use
    /// [`ContextPdbData::make_context`] instead.
    ///
    /// However, if you interact with a PDB directly and parse some of its contents
    /// for other uses, you may want to call this method in order to avoid overhead
    /// from repeatedly parsing the same streams.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_parts(
        module_info_provider: &'a dyn ModuleProvider<'s>,
        sections: &[ImageSectionHeader],
        address_map: &'a AddressMap<'s>,
        global_symbols: &'a SymbolTable<'s>,
        string_table: Option<&'a StringTable<'s>>,
        debug_info: &'a DebugInformation,
        type_formatter: MaybeOwned<'a, TypeFormatter<'a, 's>>,
        modules: Rc<Vec<Module<'a>>>,
    ) -> Result<Self> {
        let mut public_functions = Vec::new();

        // Start with the public function symbols.
        let mut symbol_iter = global_symbols.iter();
        while let Some(symbol) = symbol_iter.next()? {
            if let Ok(SymbolData::Public(PublicSymbol {
                name,
                offset,
                ..
            })) = symbol.parse()
            {
                if is_executable_section(offset.section, sections) {
                    public_functions.push(PublicSymbolFunction {
                        start_offset: offset,
                        name,
                    });
                }
            }
        }
        // Sort and de-duplicate, so that we can use binary search during lookup.
        public_functions.sort_unstable_by_key(|p| (p.start_offset.section, p.start_offset.offset));
        public_functions.dedup_by_key(|p| p.start_offset);

        // Read the section contributions. This will let us find the right module
        // based on the PdbSectionInternalOffset that corresponds to the looked-up
        // address. This allows reading module info on demand.
        let section_contributions = compute_section_contributions(debug_info)?;

        Ok(Self {
            address_map,
            section_contributions,
            string_table,
            type_formatter,
            public_functions,
            cache: RefCell::new(ContextCache {
                module_cache: BasicModuleInfoCache {
                    cache: Default::default(),
                    modules,
                    module_info_provider,
                },
                procedure_cache: Default::default(),
                extended_module_cache: Default::default(),
                inline_name_cache: Default::default(),
                full_rva_list: Default::default(),
            }),
        })
    }

    /// The number of functions found in public symbols.
    pub fn function_count(&self) -> usize {
        self.public_functions.len()
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
            .get_or_insert_with(|| Rc::new(self.compute_full_rva_list(module_cache)))
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
            PublicOrProcedureSymbol::Public(func) => {
                let name = Some(func.name.to_string().to_string());
                let start_rva = match func.start_offset.to_rva(self.address_map) {
                    Some(rva) => rva.0,
                    None => return Ok(None),
                };
                Ok(Some(Function {
                    start_rva,
                    end_rva: None,
                    name,
                }))
            }
            PublicOrProcedureSymbol::Procedure(module_index, _, func) => {
                let extended_info = procedure_cache.entry(func.offset).or_default();
                let name = extended_info
                    .get_name(
                        func,
                        &self.type_formatter,
                        &self.public_functions,
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
            extended_module_cache,
            inline_name_cache,
            ..
        } = &mut *cache;

        let func = match self.lookup_function(offset, module_cache) {
            Some(func) => func,
            None => return Ok(None),
        };

        let (module_index, module_info, proc) = match func {
            PublicOrProcedureSymbol::Public(func) => {
                let function = Some(func.name.to_string().to_string());
                let start_rva = match func.start_offset.to_rva(self.address_map) {
                    Some(rva) => rva.0,
                    None => return Ok(None),
                };
                // This is a public symbol. We only have the function name and no file / line info,
                // and no inline frames.
                return Ok(Some(FunctionFrames {
                    start_rva,
                    end_rva: None,
                    frames: vec![Frame {
                        function,
                        file: None,
                        line: None,
                    }],
                }));
            }
            PublicOrProcedureSymbol::Procedure(module_index, module_info, proc) => {
                (module_index, module_info, proc)
            }
        };

        let proc_extended_info = procedure_cache.entry(proc.offset).or_default();
        let function = proc_extended_info
            .get_name(
                proc,
                &self.type_formatter,
                &self.public_functions,
                module_index,
            )
            .map(String::from);
        let start_rva = match proc.offset.to_rva(self.address_map) {
            Some(rva) => rva.0,
            None => return Ok(None),
        };
        let end_rva = start_rva + proc.len;

        let ExtendedModuleInfo {
            line_program,
            inlinees,
        } = extended_module_cache
            .entry(module_index)
            .or_insert_with(|| self.compute_extended_module_info(module_info))
            .as_mut()
            .map_err(|err| mem::replace(err, Error::ExtendedModuleInfoUnsuccessful))?;

        let lines = proc_extended_info.get_lines(proc, line_program)?;
        let search = match lines.binary_search_by_key(&offset.offset, |li| li.start_offset) {
            Err(0) => None,
            Ok(i) => Some(i),
            Err(i) => Some(i - 1),
        };
        let (file, line) = match search {
            Some(index) => {
                let line_info = &lines[index];
                (
                    self.resolve_filename(line_program, line_info.file_index),
                    Some(line_info.line_start),
                )
            }
            None => (None, None),
        };

        let frame = Frame {
            function,
            file,
            line,
        };

        // Ordered outside to inside, until just before the end of this function.
        let mut frames = vec![frame];

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

        Ok(Some(FunctionFrames {
            start_rva,
            end_rva: Some(end_rva),
            frames,
        }))
    }

    fn compute_full_rva_list(&self, module_cache: &mut BasicModuleInfoCache<'a, 's>) -> Vec<u32> {
        let mut list = Vec::new();
        for func in &self.public_functions {
            if let Some(rva) = func.start_offset.to_rva(self.address_map) {
                list.push(rva.0);
            }
        }
        for module_index in 0..module_cache.module_count() {
            if let Some(BasicModuleInfo { procedures, .. }) =
                module_cache.get_basic_module_info(module_index)
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
    ) -> Option<PublicOrProcedureSymbol<'_, 'a, 's, 'm>> {
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

        let module_index = self.section_contributions[sc_index].module_index;
        let basic_module_info = module_cache.get_basic_module_info(module_index);

        if let Some(BasicModuleInfo {
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
                    module_index,
                    module_info,
                    &procedures[procedure_index],
                ));
            }
        }

        // No procedure was found at this offset in the module that the section
        // contribution pointed us at.
        // This is not uncommon.
        // Fall back to the public symbols.

        let last_public_function_starting_lte_address = match self
            .public_functions
            .binary_search_by_key(&(offset.section, offset.offset), |p| {
                (p.start_offset.section, p.start_offset.offset)
            }) {
            Err(0) => return None,
            Ok(i) => i,
            Err(i) => i - 1,
        };
        let fun = &self.public_functions[last_public_function_starting_lte_address];
        debug_assert!(
            fun.start_offset.section < offset.section
                || (fun.start_offset.section == offset.section
                    && fun.start_offset.offset <= offset.offset)
        );
        if fun.start_offset.section != offset.section {
            return None;
        }

        Some(PublicOrProcedureSymbol::Public(fun))
    }

    fn compute_extended_module_info(
        &self,
        module_info: &'a ModuleInfo,
    ) -> Result<ExtendedModuleInfo<'a>> {
        let line_program = module_info.line_program()?;

        let inlinees: BTreeMap<IdIndex, Inlinee> = module_info
            .inlinees()?
            .map(|i| Ok((i.index(), i)))
            .collect()?;

        Ok(ExtendedModuleInfo {
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
    full_rva_list: Rc<Vec<u32>>,
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
    procedure_cache: HashMap<PdbInternalSectionOffset, ExtendedProcedureInfo>,
    extended_module_cache: BTreeMap<u16, Result<ExtendedModuleInfo<'a>>>,
    inline_name_cache: BTreeMap<IdIndex, Result<String>>,
    full_rva_list: Option<Rc<Vec<u32>>>,
}

struct BasicModuleInfoCache<'a, 's> {
    cache: HashMap<u16, Option<BasicModuleInfo<'a, 's>>>,
    modules: Rc<Vec<Module<'a>>>,
    module_info_provider: &'a dyn ModuleProvider<'s>,
}

impl<'a, 's> BasicModuleInfoCache<'a, 's> {
    pub fn module_count(&self) -> u16 {
        self.modules.len() as u16
    }

    pub fn get_basic_module_info(&mut self, module_index: u16) -> Option<&BasicModuleInfo<'a, 's>> {
        // TODO: 2021 edition
        let modules = &self.modules;
        let module_info_provider = self.module_info_provider;

        self.cache
            .entry(module_index)
            .or_insert_with(|| {
                let module = modules.get(module_index as usize)?;
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
    module_index: u16,
}

/// Returns an array of non-overlapping `ModuleSectionContribution` objects,
/// sorted by section and then by start offset.
/// Contributions from the same module to the same section are combined into
/// one contiguous contribution. The hope is that there is no interleaving,
/// and this function returns an error if any interleaving is detected.
fn compute_section_contributions(
    debug_info: &DebugInformation<'_>,
) -> Result<Vec<ModuleSectionContribution>> {
    let mut section_contribution_iter = debug_info
        .section_contributions()?
        .filter(|sc| Ok(sc.size != 0));
    let mut section_contributions = Vec::new();

    if let Some(first_sc) = section_contribution_iter.next()? {
        let mut current_combined_sc = ModuleSectionContribution {
            section_index: first_sc.offset.section,
            start_offset: first_sc.offset.offset,
            end_offset: first_sc.offset.offset + first_sc.size,
            module_index: first_sc.module,
        };
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
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    match get_section(section_index, sections) {
        Some(section) => section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
        None => false,
    }
}

/// Offset and name of a function from a public symbol.
#[derive(Clone, Debug)]
struct PublicSymbolFunction<'s> {
    /// The address at which this function starts, as a section internal offset. The end
    /// address for global function symbols is not known. During symbol lookup, if the address
    /// is not covered by a procedure symbol (for those, the  end addresses are known), then
    /// we assume that functions with no end address cover the range up to the next function.
    start_offset: PdbInternalSectionOffset,
    /// The symbol name. This is the mangled ("decorated") function signature.
    name: RawString<'s>,
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

enum PublicOrProcedureSymbol<'c, 'a, 's, 'm> {
    Public(&'c PublicSymbolFunction<'a>),
    Procedure(u16, &'a ModuleInfo<'s>, &'m ProcedureSymbolFunction<'a>),
}

#[derive(Default)]
struct ExtendedProcedureInfo {
    name: Option<Option<String>>,
    lines: Option<Result<Vec<CachedLineInfo>>>,
    inline_ranges: Option<Result<Vec<InlineRange>>>,
}

impl ExtendedProcedureInfo {
    fn get_name(
        &mut self,
        proc: &ProcedureSymbolFunction,
        type_formatter: &TypeFormatter,
        public_functions: &[PublicSymbolFunction],
        module_index: u16,
    ) -> Option<&str> {
        self.name
            .get_or_insert_with(|| {
                if proc.type_index == TypeIndex(0) && !proc.name.as_bytes().starts_with(&[b'?']) {
                    // We have no type, so proc.name might be an argument-less string.
                    // If we have a public symbol at this address which is a decorated name
                    // (starts with a '?'), prefer to use that because it'll usually include
                    // the arguments.
                    if let Ok(public_fun_index) = public_functions
                        .binary_search_by_key(&(proc.offset.section, proc.offset.offset), |f| {
                            (f.start_offset.section, f.start_offset.offset)
                        })
                    {
                        let name = public_functions[public_fun_index].name;
                        if name.as_bytes().starts_with(&[b'?']) {
                            return Some(name.to_string().to_string());
                        }
                    }
                }
                type_formatter
                    .format_function(&proc.name.to_string(), module_index, proc.type_index)
                    .ok()
            })
            .as_deref()
    }

    fn get_lines(
        &mut self,
        proc: &ProcedureSymbolFunction,
        line_program: &LineProgram,
    ) -> Result<&[CachedLineInfo]> {
        let lines = self
            .lines
            .get_or_insert_with(|| {
                let mut iterator = line_program.lines_at_offset(proc.offset);
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
) -> Result<RangeSet<u32>> {
    let mut ranges = RangeSet::empty();
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

    let mut callee_ranges = RangeSet::empty();
    while let Some(symbol) = symbols_iter.next()? {
        if symbol.index() >= site.end {
            break;
        }
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

    if !ranges.is_superset(&callee_ranges) {
        // Workaround bad debug info.
        let missing_ranges: RangeSet<u32> = &callee_ranges - &ranges;
        for range in missing_ranges.iter() {
            let (start_offset, end_offset) = match range {
                (Bound::Included(s), Bound::Excluded(e)) => (*s, *e),
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

struct ExtendedModuleInfo<'a> {
    inlinees: BTreeMap<IdIndex, Inlinee<'a>>,
    line_program: LineProgram<'a>,
}

#[derive(Clone)]
struct CachedLineInfo {
    pub start_offset: u32,
    pub file_index: FileIndex,
    pub line_start: u32,
}

#[derive(Clone, Debug)]
struct InlineRange {
    pub start_offset: u32,
    pub end_offset: u32,
    pub call_depth: u16,
    pub inlinee: IdIndex,
    pub file_index: Option<FileIndex>,
    pub line_start: Option<u32>,
}
