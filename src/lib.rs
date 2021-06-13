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
//! fn look_up_addresses<'s, S: pdb::Source<'s> + 's>(stream: S, addresses: &[u32]) -> pdb::Result<()> {
//!     let mut pdb = pdb::PDB::open(stream)?;
//!     let context_data = pdb_addr2line::ContextPdbData::try_from_pdb(&mut pdb)?;
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

mod type_formatter;
use pdb::PublicSymbol;
use pdb::SymbolTable;
pub use type_formatter::*;

use maybe_owned::MaybeOwned;
use pdb::DebugInformation;
use pdb::IdInformation;
use pdb::TypeInformation;

use pdb::{
    AddressMap, FallibleIterator, FileIndex, IdIndex, InlineSiteSymbol, Inlinee, LineProgram,
    ModuleInfo, PdbInternalSectionOffset, RawString, Result, Source, StringTable, SymbolData,
    SymbolIndex, SymbolIter, TypeIndex, PDB,
};
use range_collections::RangeSet;
use std::cmp::Ordering;
use std::collections::btree_map::Entry;
use std::ops::Bound;
use std::ops::Deref;
use std::rc::Rc;
use std::{borrow::Cow, cell::RefCell, collections::BTreeMap};

/// Allows to easily create a [`Context`] directly from a [`pdb::PDB`].
///
/// ```
/// # fn wrapper<'s, S: pdb::Source<'s> + 's>(stream: S) -> pdb::Result<()> {
/// let mut pdb = pdb::PDB::open(stream)?;
/// let context_data = pdb_addr2line::ContextPdbData::try_from_pdb(&mut pdb)?;
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
pub struct ContextPdbData<'s> {
    modules: Vec<ModuleInfo<'s>>,
    address_map: AddressMap<'s>,
    string_table: Option<StringTable<'s>>,
    global_symbols: SymbolTable<'s>,
    debug_info: DebugInformation<'s>,
    type_info: TypeInformation<'s>,
    id_info: IdInformation<'s>,
}

impl<'s> ContextPdbData<'s> {
    /// Create a [`ContextPdbData`] from a [`PDB`](pdb::PDB). This parses many of the PDB
    /// streams and stores them in the [`ContextPdbData`]. Most importantly, it builds
    /// a list of all the [`ModuleInfo`](pdb::ModuleInfo) objects in the PDB.
    pub fn try_from_pdb<S: Source<'s> + 's>(pdb: &mut PDB<'s, S>) -> Result<Self> {
        let global_symbols = pdb.global_symbols()?;
        let debug_info = pdb.debug_information()?;
        let type_info = pdb.type_information()?;
        let id_info = pdb.id_information()?;
        let address_map = pdb.address_map()?;
        let string_table = pdb.string_table().ok();

        // Load all modules. We store their parsed form in the ContextPdbData so that the
        // Context we create later can internally store objects which have a lifetime
        // dependency on the ModuleInfo, such as RawStrings, Inlinees and LinePrograms.
        let mut module_iter = debug_info.modules()?;
        let mut modules = Vec::new();
        while let Some(module) = module_iter.next()? {
            if let Some(module_info) = pdb.module_info(&module)? {
                modules.push(module_info);
            };
        }

        Ok(Self {
            modules,
            global_symbols,
            debug_info,
            type_info,
            id_info,
            address_map,
            string_table,
        })
    }

    /// Create a [`Context`]. This uses the default [`TypeFormatter`] settings.
    pub fn make_context(&self) -> Result<Context<'_, 's, '_>> {
        self.make_context_with_formatter_flags(Default::default())
    }

    /// Create a [`Context`], using the specified [`TypeFormatter`] flags.
    pub fn make_context_with_formatter_flags(
        &self,
        flags: TypeFormatterFlags,
    ) -> Result<Context<'_, 's, '_>> {
        let type_formatter =
            TypeFormatter::new(&self.debug_info, &self.type_info, &self.id_info, flags)?;

        Context::new_from_parts(
            &self.address_map,
            &self.global_symbols,
            self.string_table.as_ref(),
            &self.modules,
            MaybeOwned::Owned(type_formatter),
        )
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
pub struct Context<'a: 't, 's, 't> {
    address_map: &'a AddressMap<'s>,
    string_table: Option<&'a StringTable<'s>>,
    type_formatter: MaybeOwned<'a, TypeFormatter<'t>>,
    modules: &'a [ModuleInfo<'s>],
    functions: Vec<BasicFunctionInfo<'a>>,
    procedure_cache: RefCell<ProcedureCache>,
    module_cache: RefCell<BTreeMap<u16, Rc<ExtendedModuleInfo<'a>>>>,
    inline_name_cache: RefCell<BTreeMap<IdIndex, Option<Rc<String>>>>,
}

impl<'a, 's, 't> Context<'a, 's, 't> {
    /// Create a [`Context`] manually. Most consumers will want to use
    /// [`ContextPdbData::make_context`] instead.
    ///
    /// However, if you interact with a PDB directly and parse some of its contents
    /// for other uses, you may want to call this method in order to avoid overhead
    /// from repeatedly parsing the same streams.
    pub fn new_from_parts(
        address_map: &'a AddressMap<'s>,
        global_symbols: &'a SymbolTable<'s>,
        string_table: Option<&'a StringTable<'s>>,
        modules: &'a [ModuleInfo<'s>],
        type_formatter: MaybeOwned<'a, TypeFormatter<'t>>,
    ) -> Result<Self> {
        let mut functions = Vec::new();

        // Start with the public function symbols.
        let mut symbol_iter = global_symbols.iter();
        while let Some(symbol) = symbol_iter.next()? {
            if let Ok(SymbolData::Public(PublicSymbol {
                function: true,
                name,
                offset,
                ..
            })) = symbol.parse()
            {
                let start_rva = match offset.to_rva(address_map) {
                    Some(rva) => rva.0,
                    None => continue,
                };
                functions.push(BasicFunctionInfo {
                    start_rva,
                    end_rva: None,
                    name,
                    procedure_symbol_info: None,
                });
            }
        }

        // Then, add functions.
        for (module_index, module_info) in modules.iter().enumerate() {
            let mut symbols_iter = module_info.symbols()?;
            while let Some(symbol) = symbols_iter.next()? {
                if let Ok(SymbolData::Procedure(proc)) = symbol.parse() {
                    if proc.len == 0 {
                        continue;
                    }
                    let start_rva = match proc.offset.to_rva(address_map) {
                        Some(rva) => rva.0,
                        None => continue,
                    };

                    functions.push(BasicFunctionInfo {
                        start_rva,
                        end_rva: Some(start_rva + proc.len),
                        name: proc.name,
                        procedure_symbol_info: Some(ProcedureSymbolInfo {
                            module_index: module_index as u16,
                            symbol_index: symbol.index(),
                            end_symbol_index: proc.end,
                            offset: proc.offset,
                            type_index: proc.type_index,
                        }),
                    });
                }
            }
        }

        // Sort and de-duplicate, so that we can use binary search during lookup.
        // If we have multiple procs at the same probe (as a result of identical code folding),
        // we'd like to keep the last instance that we encountered in the original order.
        // dedup_by_key keeps the *first* element of consecutive duplicates, so we reverse first
        // and then use a stable sort before we de-duplicate.
        functions.reverse();
        functions.sort_by_key(|p| p.start_rva);
        functions.dedup_by_key(|p| p.start_rva);

        Ok(Self {
            address_map,
            string_table,
            type_formatter,
            modules,
            functions,
            procedure_cache: RefCell::new(Default::default()),
            module_cache: RefCell::new(BTreeMap::new()),
            inline_name_cache: RefCell::new(BTreeMap::new()),
        })
    }

    /// The number of functions found in the modules. If the PDB file lists
    /// multiple functions sharing the same rva range, the shared range is only
    /// counted as one function. In other words, this count is post-deduplication.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Iterate over all functions in the modules.
    pub fn functions(&self) -> FunctionIter<'_, 'a, 's, 't> {
        FunctionIter {
            context: self,
            cur_index: 0,
        }
    }

    /// Find the function whose code contains the provided address.
    /// The return value only contains the function name and the rva range, but
    /// no file or line information.
    pub fn find_function(&self, probe: u32) -> Result<Option<Function>> {
        let func = match self.lookup_function(probe) {
            Some(func) => func,
            None => return Ok(None),
        };
        let name = self.get_function_name(func).map(|n| (*n).clone());
        Ok(Some(Function {
            start_rva: func.start_rva,
            end_rva: func.end_rva,
            name,
        }))
    }

    /// Find information about the source code which generated the instruction at the
    /// provided address. This information includes the function name, file name and
    /// line number, of the containing procedure and of any functions that were inlined
    /// into the procedure by the compiler, at that address.
    ///
    /// A lot of information is cached so that repeated calls are fast.
    pub fn find_frames(&self, probe: u32) -> Result<Option<FunctionFrames>> {
        let func = match self.lookup_function(probe) {
            Some(func) => func,
            None => return Ok(None),
        };

        let start_rva = func.start_rva;

        let function = self.get_function_name(func).map(|n| (*n).clone());

        let proc = match &func.procedure_symbol_info {
            Some(proc) => proc,
            None => {
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
        };

        let module_info = &self.modules[proc.module_index as usize];
        let module = self.get_extended_module_info(proc.module_index)?;
        let line_program = &module.line_program;
        let inlinees = &module.inlinees;

        let lines = &self.get_procedure_lines(start_rva, proc, line_program)?[..];
        let search = match lines.binary_search_by_key(&probe, |li| li.start_rva) {
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

        let inline_ranges =
            self.get_procedure_inline_ranges(start_rva, module_info, proc, inlinees)?;
        let mut inline_ranges = &inline_ranges[..];

        loop {
            let current_depth = (frames.len() - 1) as u16;

            // Look up (probe, current_depth) in inline_ranges.
            // `inlined_addresses` is sorted in "breadth-first traversal order", i.e.
            // by `call_depth` first, and then by `start_rva`. See the comment at
            // the sort call for more information about why.
            let search = inline_ranges.binary_search_by(|range| {
                if range.call_depth > current_depth {
                    Ordering::Greater
                } else if range.call_depth < current_depth {
                    Ordering::Less
                } else if range.start_rva > probe {
                    Ordering::Greater
                } else if range.end_rva <= probe {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            });
            let (inline_range, remainder) = match search {
                Ok(index) => (&inline_ranges[index], &inline_ranges[index + 1..]),
                Err(_) => break,
            };
            let function = self
                .get_inline_name(inline_range.inlinee)
                .map(|name| name.deref().clone());
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
            start_rva: func.start_rva,
            end_rva: func.end_rva,
            frames,
        }))
    }

    fn lookup_function(&self, probe: u32) -> Option<&BasicFunctionInfo<'a>> {
        let last_function_starting_lte_address =
            match self.functions.binary_search_by_key(&probe, |p| p.start_rva) {
                Err(0) => return None,
                Ok(i) => i,
                Err(i) => i - 1,
            };
        assert!(self.functions[last_function_starting_lte_address].start_rva <= probe);
        if let Some(end_rva) = self.functions[last_function_starting_lte_address].end_rva {
            if probe >= end_rva {
                return None;
            }
        }
        Some(&self.functions[last_function_starting_lte_address])
    }

    fn get_extended_module_info(&self, module_index: u16) -> Result<Rc<ExtendedModuleInfo<'a>>> {
        let mut cache = self.module_cache.borrow_mut();
        match cache.entry(module_index) {
            Entry::Occupied(e) => Ok(e.get().clone()),
            Entry::Vacant(e) => {
                let m = self.compute_extended_module_info(module_index)?;
                Ok(e.insert(Rc::new(m)).clone())
            }
        }
    }

    fn compute_extended_module_info(&self, module_index: u16) -> Result<ExtendedModuleInfo<'a>> {
        let module_info = &self.modules[module_index as usize];
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

    fn get_function_name(&self, func: &BasicFunctionInfo<'a>) -> Option<Rc<String>> {
        match &func.procedure_symbol_info {
            Some(proc) => self.get_procedure_name(func.start_rva, &func.name, proc),
            None => Some(Rc::new(func.name.to_string().to_string())),
        }
    }

    fn get_procedure_name(
        &self,
        start_rva: u32,
        name: &RawString<'a>,
        proc: &ProcedureSymbolInfo,
    ) -> Option<Rc<String>> {
        let mut cache = self.procedure_cache.borrow_mut();
        let entry = cache.get_entry_mut(start_rva);
        match &entry.name {
            Some(name) => name.deref().clone(),
            None => {
                let name = self.compute_procedure_name(name, proc).map(Rc::new);
                entry.name = Some(name.clone());
                name
            }
        }
    }

    fn compute_procedure_name(
        &self,
        name: &RawString<'a>,
        proc: &ProcedureSymbolInfo,
    ) -> Option<String> {
        self.type_formatter
            .format_function(&name.to_string(), proc.type_index)
            .ok()
    }

    fn get_procedure_lines(
        &self,
        start_rva: u32,
        proc: &ProcedureSymbolInfo,
        line_program: &LineProgram,
    ) -> Result<Rc<Vec<CachedLineInfo>>> {
        let mut cache = self.procedure_cache.borrow_mut();
        let entry = cache.get_entry_mut(start_rva);
        match &entry.lines {
            Some(lines) => Ok(lines.clone()),
            None => {
                let lines = Rc::new(self.compute_procedure_lines(proc, line_program)?);
                entry.lines = Some(lines.clone());
                Ok(lines)
            }
        }
    }

    fn compute_procedure_lines(
        &self,
        proc: &ProcedureSymbolInfo,
        line_program: &LineProgram,
    ) -> Result<Vec<CachedLineInfo>> {
        let lines_for_proc = line_program.lines_at_offset(proc.offset);
        let mut iterator = lines_for_proc.map(|line_info| {
            let rva = line_info.offset.to_rva(self.address_map).unwrap().0;
            Ok((rva, line_info))
        });
        let mut lines = Vec::new();
        let mut next_item = iterator.next()?;
        while let Some((start_rva, line_info)) = next_item {
            next_item = iterator.next()?;
            lines.push(CachedLineInfo {
                start_rva,
                file_index: line_info.file_index,
                line_start: line_info.line_start,
            });
        }
        Ok(lines)
    }

    fn get_procedure_inline_ranges(
        &self,
        start_rva: u32,
        module_info: &ModuleInfo,
        proc: &ProcedureSymbolInfo,
        inlinees: &BTreeMap<IdIndex, Inlinee>,
    ) -> Result<Rc<Vec<InlineRange>>> {
        let mut cache = self.procedure_cache.borrow_mut();
        let entry = cache.get_entry_mut(start_rva);
        match &entry.inline_ranges {
            Some(inline_ranges) => Ok(inline_ranges.clone()),
            None => {
                let inline_ranges =
                    Rc::new(self.compute_procedure_inline_ranges(module_info, proc, inlinees)?);
                entry.inline_ranges = Some(inline_ranges.clone());
                Ok(inline_ranges)
            }
        }
    }

    fn compute_procedure_inline_ranges(
        &self,
        module_info: &ModuleInfo,
        proc: &ProcedureSymbolInfo,
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
                    self.process_inlinee_symbols(
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

        lines.sort_by(|r1, r2| {
            if r1.call_depth < r2.call_depth {
                Ordering::Less
            } else if r1.call_depth > r2.call_depth {
                Ordering::Greater
            } else if r1.start_rva < r2.start_rva {
                Ordering::Less
            } else if r1.start_rva > r2.start_rva {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        });

        Ok(lines)
    }

    fn process_inlinee_symbols(
        &self,
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
                let start_rva = line_info.offset.to_rva(self.address_map).unwrap().0;
                let end_rva = start_rva + length;
                lines.push(InlineRange {
                    start_rva,
                    end_rva,
                    call_depth,
                    inlinee: site.inlinee,
                    file_index: Some(line_info.file_index),
                    line_start: Some(line_info.line_start),
                });
                ranges |= RangeSet::from(start_rva..end_rva);
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
                    callee_ranges |= self.process_inlinee_symbols(
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
                let (start_rva, end_rva) = match range {
                    (Bound::Included(s), Bound::Excluded(e)) => (*s, *e),
                    other => {
                        panic!("Unexpected range bounds {:?}", other);
                    }
                };
                lines.push(InlineRange {
                    start_rva,
                    end_rva,
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

    fn get_inline_name(&self, id_index: IdIndex) -> Option<Rc<String>> {
        let mut cache = self.inline_name_cache.borrow_mut();
        cache
            .entry(id_index)
            .or_insert_with(|| match self.type_formatter.format_id(id_index) {
                Ok(name) => Some(Rc::new(name)),
                Err(_) => None,
            })
            .deref()
            .clone()
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
pub struct FunctionIter<'c, 'a, 's, 't> {
    context: &'c Context<'a, 's, 't>,
    cur_index: usize,
}

impl<'c, 'a, 's, 't> Iterator for FunctionIter<'c, 'a, 's, 't> {
    type Item = Function;

    fn next(&mut self) -> Option<Function> {
        if self.cur_index >= self.context.functions.len() {
            return None;
        }
        let func = &self.context.functions[self.cur_index];
        self.cur_index += 1;

        let name = self.context.get_function_name(func).map(|n| (*n).clone());
        Some(Function {
            start_rva: func.start_rva,
            end_rva: func.end_rva,
            name,
        })
    }
}

#[derive(Default)]
struct ProcedureCache(BTreeMap<u32, ExtendedProcedureInfo>);

impl ProcedureCache {
    fn get_entry_mut(&mut self, start_rva: u32) -> &mut ExtendedProcedureInfo {
        self.0
            .entry(start_rva)
            .or_insert_with(|| ExtendedProcedureInfo {
                name: None,
                lines: None,
                inline_ranges: None,
            })
    }
}

/// Basic data about a function, based on either a public function symbol or a
/// procedure symbol.
#[derive(Clone)]
struct BasicFunctionInfo<'a> {
    /// The address at which this function starts, i.e. the rva of the symbol.
    start_rva: u32,
    /// The address at which this function ends, if known. If this function is based on a
    /// procedure symbol, then the end address is known; if it's based on a public function
    /// symbol, then the end address is not known. During symbol lookup, we assume that
    /// functions with no end address cover the range up to the next function.
    end_rva: Option<u32>,
    /// The symbol name. For public symbols, this is the mangled ("decorated") function
    /// signature. For procedure symbols, this is just the function name, potentially including
    /// class scope and namespace.
    name: RawString<'a>,
    /// If this function is based on a procedure symbol, this contains the information about
    /// that symbol.
    procedure_symbol_info: Option<ProcedureSymbolInfo>,
}

#[derive(Clone)]
struct ProcedureSymbolInfo {
    module_index: u16,
    symbol_index: SymbolIndex,
    end_symbol_index: SymbolIndex,
    offset: PdbInternalSectionOffset,
    type_index: TypeIndex,
}

struct ExtendedProcedureInfo {
    name: Option<Option<Rc<String>>>,
    lines: Option<Rc<Vec<CachedLineInfo>>>,
    inline_ranges: Option<Rc<Vec<InlineRange>>>,
}

struct ExtendedModuleInfo<'a> {
    inlinees: BTreeMap<IdIndex, Inlinee<'a>>,
    line_program: LineProgram<'a>,
}

#[derive(Clone)]
struct CachedLineInfo {
    pub start_rva: u32,
    pub file_index: FileIndex,
    pub line_start: u32,
}

#[derive(Clone, Debug)]
struct InlineRange {
    pub start_rva: u32,
    pub end_rva: u32,
    pub call_depth: u16,
    pub inlinee: IdIndex,
    pub file_index: Option<FileIndex>,
    pub line_start: Option<u32>,
}
