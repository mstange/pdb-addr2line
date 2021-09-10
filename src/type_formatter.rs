use crate::error::Error;
use bitflags::bitflags;
use pdb::{
    ArgumentList, ArrayType, ClassKind, ClassType, CrossModuleExports, CrossModuleImports,
    CrossModuleRef, DebugInformation, FallibleIterator, FunctionAttributes, IdData, IdIndex,
    IdInformation, Item, ItemFinder, ItemIndex, ItemIter, MachineType, MemberFunctionType,
    ModifierType, Module, ModuleInfo, PointerMode, PointerType, PrimitiveKind, PrimitiveType,
    ProcedureType, RawString, StringTable, TypeData, TypeIndex, TypeInformation, UnionType,
    Variant,
};
use range_collections::RangeSet;
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::Write;
use std::mem;
use std::ops::Bound;
use std::rc::Rc;

type Result<V> = std::result::Result<V, Error>;

bitflags! {
    /// Flags for [`TypeFormatter`].
    pub struct TypeFormatterFlags: u32 {
        /// Do not print the return type for the root function.
        const NO_FUNCTION_RETURN = 0b1;

        /// Do not print static before the signature of a static method.
        const NO_MEMBER_FUNCTION_STATIC = 0b10;

        /// Add a space after each comma in an argument list.
        const SPACE_AFTER_COMMA = 0b100;

        /// Add a space before the * or & sigil of a pointer or reference.
        const SPACE_BEFORE_POINTER = 0b1000;

        /// Only print "MyClassName" instead of "class MyClassName", "struct MyClassName", or "interface MyClassName".
        const NAME_ONLY = 0b10000;
    }
}

impl Default for TypeFormatterFlags {
    fn default() -> Self {
        Self::NO_FUNCTION_RETURN
            | Self::NO_MEMBER_FUNCTION_STATIC
            | Self::SPACE_AFTER_COMMA
            | Self::NAME_ONLY
    }
}

/// This trait is only needed for consumers who want to call Context::new_from_parts
/// or TypeFormatter::new_from_parts manually, instead of using ContextPdbData. If you
/// use ContextPdbData you do not need to worry about this trait.
/// This trait allows Context and TypeFormatter to request parsing of module info
/// on-demand. It also does some lifetime acrobatics so that Context can cache objects
/// which have a lifetime dependency on the module info.
pub trait ModuleProvider<'s> {
    /// Get the module info for this module from the PDB.
    fn get_module_info(
        &self,
        module_index: u16,
        module: &Module,
    ) -> std::result::Result<Option<&ModuleInfo<'s>>, pdb::Error>;
}

/// Allows printing function signatures, for example for use in stack traces.
///
/// Procedure symbols in PDBs usually have a name string which only includes the function name,
/// and no function arguments. Instead, the arguments need to be obtained from the symbol's type
/// information. [`TypeFormatter`] handles that.
///
/// The same is true for "inlinee" functions - these are referenced by their [`pdb::IdIndex`], and their
/// [`IdData`]'s name string again only contains the raw function name but no arguments and also
/// no namespace or class name. [`TypeFormatter`] handles those, too, in [`TypeFormatter::format_id`].
// Lifetimes:
// 'a: Lifetime of the thing that owns the various streams, e.g. ContextPdbData.
// 's: The PDB Source lifetime.
pub struct TypeFormatter<'a, 's> {
    module_provider: &'a dyn ModuleProvider<'s>,
    pub(crate) modules: Rc<Vec<Module<'a>>>,
    string_table: Option<&'a StringTable<'s>>,
    cache: RefCell<TypeFormatterCache<'a>>,
    ptr_size: u32,
    flags: TypeFormatterFlags,
}

struct TypeFormatterCache<'a> {
    type_map: TypeMap<'a>,
    type_size_cache: TypeSizeCache<'a>,
    id_map: IdMap<'a>,
    /// lower case module_name() -> module_index
    module_name_map: Option<HashMap<String, u16>>,
    module_imports: HashMap<u16, Result<CrossModuleImports<'a>>>,
    module_exports: HashMap<u16, Result<CrossModuleExports>>,
}

// 'a: Lifetime of the thing that owns the various streams.
// 's: The PDB Source lifetime.
// 'c: Lifetime of the exclusive reference to the TypeFormatterCache, outlived by
//     the reference to the TypeFormatter.
struct TypeFormatterForModule<'c, 'a, 's> {
    module_index: u16,
    module_provider: &'a dyn ModuleProvider<'s>,
    modules: &'c [Module<'a>],
    string_table: Option<&'a StringTable<'s>>,
    cache: &'c mut TypeFormatterCache<'a>,
    ptr_size: u32,
    flags: TypeFormatterFlags,
}

impl<'a, 's> TypeFormatter<'a, 's> {
    /// Create a [`TypeFormatter`] manually. Most consumers will want to use
    /// [`ContextPdbData::make_type_formatter`] instead.
    ///
    /// However, if you interact with a PDB directly and parse some of its contents
    /// for other uses, you may want to call this method in order to avoid overhead
    /// from repeatedly parsing the same streams.
    pub fn new_from_parts(
        module_provider: &'a dyn ModuleProvider<'s>,
        modules: Rc<Vec<Module<'a>>>,
        debug_info: &DebugInformation<'s>,
        type_info: &'a TypeInformation<'s>,
        id_info: &'a IdInformation<'s>,
        string_table: Option<&'a StringTable<'s>>,
        flags: TypeFormatterFlags,
    ) -> std::result::Result<Self, pdb::Error> {
        let type_map = TypeMap {
            iter: type_info.iter(),
            finder: type_info.finder(),
        };
        let type_size_cache = TypeSizeCache {
            forward_ref_sizes: HashMap::new(),
            cached_ranges: RangeSet::empty(),
        };

        let id_map = IdMap {
            iter: id_info.iter(),
            finder: id_info.finder(),
        };

        let ptr_size = match debug_info.machine_type()? {
            MachineType::Amd64 | MachineType::Arm64 | MachineType::Ia64 | MachineType::RiscV64 => 8,
            MachineType::RiscV128 => 16,
            _ => 4,
        };

        Ok(Self {
            module_provider,
            modules,
            string_table,
            cache: RefCell::new(TypeFormatterCache {
                type_map,
                type_size_cache,
                id_map,
                module_name_map: None,
                module_imports: HashMap::new(),
                module_exports: HashMap::new(),
            }),
            ptr_size,
            flags,
        })
    }

    fn for_module<F, R>(&self, module_index: u16, f: F) -> R
    where
        F: FnOnce(&mut TypeFormatterForModule<'_, 'a, 's>) -> R,
    {
        let mut cache = self.cache.borrow_mut();
        let mut for_module = TypeFormatterForModule {
            module_index,
            module_provider: self.module_provider,
            modules: &self.modules,
            string_table: self.string_table,
            cache: &mut *cache,
            ptr_size: self.ptr_size,
            flags: self.flags,
        };
        f(&mut for_module)
    }

    /// Get the size, in bytes, of the type at `index`.
    pub fn get_type_size(&self, module_index: u16, index: TypeIndex) -> u32 {
        self.for_module(module_index, |tf| tf.get_type_size(index))
    }

    /// Return a string with the function or method signature, including return type (if
    /// requested), namespace and/or class qualifiers, and arguments.
    /// If the TypeIndex is 0, then only the raw name is emitted. In that case, the
    /// name may need to go through additional demangling / "undecorating", but this
    /// is the responsibility of the caller.
    /// This method is used for [`ProcedureSymbol`s](pdb::ProcedureSymbol).
    /// The module_index is the index of the module in which this procedure was found. It
    /// is necessary in order to properly resolve cross-module references.
    pub fn format_function(
        &self,
        name: &str,
        module_index: u16,
        function_type_index: TypeIndex,
    ) -> Result<String> {
        let mut s = String::new();
        self.emit_function(&mut s, name, module_index, function_type_index)?;
        Ok(s)
    }

    /// Write out the function or method signature, including return type (if requested),
    /// namespace and/or class qualifiers, and arguments.
    /// If the TypeIndex is 0, then only the raw name is emitted. In that case, the
    /// name may need to go through additional demangling / "undecorating", but this
    /// is the responsibility of the caller.
    /// This method is used for [`ProcedureSymbol`s](pdb::ProcedureSymbol).
    /// The module_index is the index of the module in which this procedure was found. It
    /// is necessary in order to properly resolve cross-module references.
    pub fn emit_function(
        &self,
        w: &mut impl Write,
        name: &str,
        module_index: u16,
        function_type_index: TypeIndex,
    ) -> Result<()> {
        self.for_module(module_index, |tf| {
            tf.emit_function(w, name, function_type_index)
        })
    }

    /// Return a string with the function or method signature, including return type (if
    /// requested), namespace and/or class qualifiers, and arguments.
    /// This method is used for inlined functions.
    /// The module_index is the index of the module in which this IdIndex was found. It
    /// is necessary in order to properly resolve cross-module references.
    pub fn format_id(&self, module_index: u16, id_index: IdIndex) -> Result<String> {
        let mut s = String::new();
        self.emit_id(&mut s, module_index, id_index)?;
        Ok(s)
    }

    /// Write out the function or method signature, including return type (if requested),
    /// namespace and/or class qualifiers, and arguments.
    /// This method is used for inlined functions.
    /// The module_index is the index of the module in which this IdIndex was found. It
    /// is necessary in order to properly resolve cross-module references.
    pub fn emit_id(&self, w: &mut impl Write, module_index: u16, id_index: IdIndex) -> Result<()> {
        self.for_module(module_index, |tf| tf.emit_id(w, id_index))
    }
}

impl<'c, 'a, 's> TypeFormatterForModule<'c, 'a, 's> {
    /// Get the size, in bytes, of the type at `index`.
    pub fn get_type_size(&mut self, index: TypeIndex) -> u32 {
        if let Ok(type_data) = self.parse_type_index(index) {
            self.get_data_size(index, &type_data)
        } else {
            0
        }
    }
    /// Write out the function or method signature, including return type (if requested),
    /// namespace and/or class qualifiers, and arguments.
    /// If the TypeIndex is 0, then only the raw name is emitted. In that case, the
    /// name may need to go through additional demangling / "undecorating", but this
    /// is the responsibility of the caller.
    /// This method is used for [`ProcedureSymbol`s](pdb::ProcedureSymbol).
    pub fn emit_function(
        &mut self,
        w: &mut impl Write,
        name: &str,
        function_type_index: TypeIndex,
    ) -> Result<()> {
        if function_type_index == TypeIndex(0) {
            return self.emit_name_str(w, name);
        }

        match self.parse_type_index(function_type_index)? {
            TypeData::MemberFunction(t) => {
                if t.this_pointer_type.is_none() {
                    self.maybe_emit_static(w)?;
                }
                self.maybe_emit_return_type(w, Some(t.return_type), t.attributes)?;
                self.emit_name_str(w, name)?;
                self.emit_method_args(w, t, true)?;
            }
            TypeData::Procedure(t) => {
                self.maybe_emit_return_type(w, t.return_type, t.attributes)?;
                self.emit_name_str(w, name)?;
                write!(w, "(")?;
                self.emit_type_index(w, t.argument_list)?;
                write!(w, ")")?;
            }
            _ => {
                write!(w, "{}", name)?;
            }
        }
        Ok(())
    }

    /// Write out the function or method signature, including return type (if requested),
    /// namespace and/or class qualifiers, and arguments.
    /// This method is used for inlined functions.
    pub fn emit_id(&mut self, w: &mut impl Write, id_index: IdIndex) -> Result<()> {
        let id_data = match self.parsee_id_index(id_index) {
            Ok(id_data) => id_data,
            Err(Error::PdbError(pdb::Error::UnimplementedTypeKind(t))) => {
                write!(w, "<unimplemented type kind 0x{:x}>", t)?;
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        match id_data {
            IdData::MemberFunction(m) => {
                let t = match self.parse_type_index(m.function_type)? {
                    TypeData::MemberFunction(t) => t,
                    _ => return Err(Error::MemberFunctionIdIsNotMemberFunctionType),
                };

                if t.this_pointer_type.is_none() {
                    self.maybe_emit_static(w)?;
                }
                self.maybe_emit_return_type(w, Some(t.return_type), t.attributes)?;
                self.emit_type_index(w, m.parent)?;
                write!(w, "::")?;
                self.emit_name_str(w, &m.name.to_string())?;
                self.emit_method_args(w, t, true)?;
            }
            IdData::Function(f) => {
                let t = match self.parse_type_index(f.function_type)? {
                    TypeData::Procedure(t) => t,
                    _ => return Err(Error::FunctionIdIsNotProcedureType),
                };

                self.maybe_emit_return_type(w, t.return_type, t.attributes)?;
                if let Some(scope) = f.scope {
                    self.emit_id(w, scope)?;
                    write!(w, "::")?;
                }
                self.emit_name_str(w, &f.name.to_string())?;
                write!(w, "(")?;
                self.emit_type_index(w, t.argument_list)?;
                write!(w, ")")?;
            }
            IdData::String(s) => {
                let name = s.name.to_string();

                if Self::is_anonymous_namespace(&name) {
                    write!(w, "`anonymous namespace'")?;
                } else {
                    write!(w, "{}", name)?;
                }
            }
            IdData::StringList(s) => {
                write!(w, "\"")?;
                for (i, type_index) in s.substrings.iter().enumerate() {
                    if i > 0 {
                        write!(w, "\" \"")?;
                    }
                    self.emit_type_index(w, *type_index)?;
                }
                write!(w, "\"")?;
            }
            other => write!(w, "<unhandled id scope {:?}>::", other)?,
        }
        Ok(())
    }

    /// Checks whether the given name declares an anonymous namespace.
    ///
    /// ID records specify the mangled format for anonymous namespaces: `?A0x<id>`, where `id` is a hex
    /// identifier of the namespace. Demanglers usually resolve this as "anonymous namespace".
    fn is_anonymous_namespace(name: &str) -> bool {
        name.strip_prefix("?A0x")
            .map_or(false, |rest| u32::from_str_radix(rest, 16).is_ok())
    }

    fn resolve_index<I>(&mut self, index: I) -> Result<I>
    where
        I: ItemIndex,
    {
        if !index.is_cross_module() {
            return Ok(index);
        }

        // We have a cross-module reference.
        // First, we prepare some information which we will need below.

        let string_table = self
            .string_table
            .ok_or(Error::CantResolveCrossModuleRefWithoutStringTable)?;

        let TypeFormatterCache {
            module_name_map,
            module_imports,
            module_exports,
            ..
        } = self.cache;
        let modules = self.modules;
        let module_provider = self.module_provider;
        let self_module_index = self.module_index;

        let get_module = |module_index: u16| -> Result<&'a ModuleInfo<'s>> {
            let module = modules
                .get(module_index as usize)
                .ok_or(Error::OutOfRangeModuleIndex(module_index))?;
            let module_info = module_provider
                .get_module_info(module_index, module)?
                .ok_or(Error::ModuleInfoNotFound(module_index))?;
            Ok(module_info)
        };

        let module_name_map = module_name_map.get_or_insert_with(|| {
            modules
                .iter()
                .enumerate()
                .map(|(module_index, module)| {
                    let name = module.module_name().to_ascii_lowercase();
                    (name, module_index as u16)
                })
                .collect()
        });

        // Now we follow the steps outlined in the comment for is_cross_module.

        //  1. Look up the index in [`CrossModuleImports`](crate::CrossModuleImports) of the current
        //     module.
        let imports = module_imports
            .entry(self_module_index)
            .or_insert_with(|| Ok(get_module(self_module_index)?.imports()?))
            .as_mut()
            .map_err(|err| mem::replace(err, Error::ModuleImportsUnsuccessful))?;

        let CrossModuleRef(module_ref, local_index) = imports.resolve_import(index)?;

        //  2. Use [`StringTable`](crate::StringTable) to resolve the name of the referenced module.
        let ref_module_name = module_ref
            .0
            .to_string_lossy(string_table)?
            .to_ascii_lowercase();

        //  3. Find the [`Module`](crate::Module) with the same module name and load its
        //     [`ModuleInfo`](crate::ModuleInfo).
        let ref_module_index = *module_name_map
            .get(&ref_module_name)
            .ok_or(Error::ModuleNameNotFound(ref_module_name))?;

        let module_exports = module_exports
            .entry(ref_module_index)
            .or_insert_with(|| Ok(get_module(ref_module_index)?.exports()?))
            .as_mut()
            .map_err(|err| mem::replace(err, Error::ModuleExportsUnsuccessful))?;

        //  4. Resolve the [`Local`](crate::Local) index into a global one using
        //     [`CrossModuleExports`](crate::CrossModuleExports).
        let index = module_exports
            .resolve_import(local_index)?
            .ok_or_else(|| Error::LocalIndexNotInExports(local_index.0.into()))?;

        Ok(index)
    }

    fn parse_type_index(&mut self, index: TypeIndex) -> Result<TypeData<'a>> {
        let index = self.resolve_index(index)?;
        let item = self.cache.type_map.try_get(index)?;
        Ok(item.parse()?)
    }

    fn parsee_id_index(&mut self, index: IdIndex) -> Result<IdData<'a>> {
        let index = self.resolve_index(index)?;
        let item = self.cache.id_map.try_get(index)?;
        Ok(item.parse()?)
    }

    fn get_class_size(&mut self, index: TypeIndex, class_type: &ClassType<'a>) -> u32 {
        if class_type.properties.forward_reference() {
            let name = class_type.unique_name.unwrap_or(class_type.name);
            let size = self.cache.type_size_cache.get_size_for_forward_reference(
                index,
                name,
                &mut self.cache.type_map,
            );

            // Sometimes the name will not be in self.forward_ref_sizes - this can occur for
            // the empty struct, which can be a forward reference to itself!
            size.unwrap_or(class_type.size as u32)
        } else {
            class_type.size.into()
        }
    }

    fn get_union_size(&mut self, index: TypeIndex, union_type: &UnionType<'a>) -> u32 {
        if union_type.properties.forward_reference() {
            let name = union_type.unique_name.unwrap_or(union_type.name);
            let size = self.cache.type_size_cache.get_size_for_forward_reference(
                index,
                name,
                &mut self.cache.type_map,
            );

            size.unwrap_or(union_type.size)
        } else {
            union_type.size
        }
    }

    fn get_data_size(&mut self, type_index: TypeIndex, type_data: &TypeData<'a>) -> u32 {
        match type_data {
            TypeData::Primitive(t) => {
                if t.indirection.is_some() {
                    return self.ptr_size;
                }
                match t.kind {
                    PrimitiveKind::NoType | PrimitiveKind::Void => 0,
                    PrimitiveKind::Char
                    | PrimitiveKind::UChar
                    | PrimitiveKind::RChar
                    | PrimitiveKind::I8
                    | PrimitiveKind::U8
                    | PrimitiveKind::Bool8 => 1,
                    PrimitiveKind::WChar
                    | PrimitiveKind::RChar16
                    | PrimitiveKind::Short
                    | PrimitiveKind::UShort
                    | PrimitiveKind::I16
                    | PrimitiveKind::U16
                    | PrimitiveKind::F16
                    | PrimitiveKind::Bool16 => 2,
                    PrimitiveKind::RChar32
                    | PrimitiveKind::Long
                    | PrimitiveKind::ULong
                    | PrimitiveKind::I32
                    | PrimitiveKind::U32
                    | PrimitiveKind::F32
                    | PrimitiveKind::F32PP
                    | PrimitiveKind::Bool32
                    | PrimitiveKind::HRESULT => 4,
                    PrimitiveKind::I64
                    | PrimitiveKind::U64
                    | PrimitiveKind::Quad
                    | PrimitiveKind::UQuad
                    | PrimitiveKind::F64
                    | PrimitiveKind::Complex32
                    | PrimitiveKind::Bool64 => 8,
                    PrimitiveKind::I128
                    | PrimitiveKind::U128
                    | PrimitiveKind::Octa
                    | PrimitiveKind::UOcta
                    | PrimitiveKind::F128
                    | PrimitiveKind::Complex64 => 16,
                    PrimitiveKind::F48 => 6,
                    PrimitiveKind::F80 => 10,
                    PrimitiveKind::Complex80 => 20,
                    PrimitiveKind::Complex128 => 32,
                    _ => panic!("Unknown PrimitiveKind {:?} in get_data_size", t.kind),
                }
            }
            TypeData::Class(t) => self.get_class_size(type_index, t),
            TypeData::MemberFunction(_) => self.ptr_size,
            TypeData::Procedure(_) => self.ptr_size,
            TypeData::Pointer(t) => t.attributes.size().into(),
            TypeData::Array(t) => *t.dimensions.last().unwrap(),
            TypeData::Union(t) => self.get_union_size(type_index, t),
            TypeData::Enumeration(t) => self.get_type_size(t.underlying_type),
            TypeData::Enumerate(t) => match t.value {
                Variant::I8(_) | Variant::U8(_) => 1,
                Variant::I16(_) | Variant::U16(_) => 2,
                Variant::I32(_) | Variant::U32(_) => 4,
                Variant::I64(_) | Variant::U64(_) => 8,
            },
            TypeData::Modifier(t) => self.get_type_size(t.underlying_type),
            _ => 0,
        }
    }

    fn has_flags(&self, flags: TypeFormatterFlags) -> bool {
        self.flags.intersects(flags)
    }

    fn maybe_emit_static(&self, w: &mut impl Write) -> Result<()> {
        if self.has_flags(TypeFormatterFlags::NO_MEMBER_FUNCTION_STATIC) {
            return Ok(());
        }

        w.write_str("static ")?;
        Ok(())
    }

    fn maybe_emit_return_type(
        &mut self,
        w: &mut impl Write,
        type_index: Option<TypeIndex>,
        attrs: FunctionAttributes,
    ) -> Result<()> {
        if self.has_flags(TypeFormatterFlags::NO_FUNCTION_RETURN) {
            return Ok(());
        }

        self.emit_return_type(w, type_index, attrs)?;
        Ok(())
    }

    fn emit_name_str(&mut self, w: &mut impl Write, name: &str) -> Result<()> {
        if name.is_empty() {
            write!(w, "<name omitted>")?;
        } else {
            write!(w, "{}", name)?;
        }
        Ok(())
    }

    fn emit_return_type(
        &mut self,
        w: &mut impl Write,
        type_index: Option<TypeIndex>,
        attrs: FunctionAttributes,
    ) -> Result<()> {
        if !attrs.is_constructor() {
            if let Some(index) = type_index {
                self.emit_type_index(w, index)?;
                write!(w, " ")?;
            }
        }
        Ok(())
    }

    /// Check if ptr points to the specified class, and if so, whether it points to const or non-const class.
    /// If it points to a different class than the one supplied in the `class` argument, don'a check constness.
    fn is_ptr_to_class(&mut self, ptr: TypeIndex, class: TypeIndex) -> Result<PtrToClassKind> {
        if let TypeData::Pointer(ptr_type) = self.parse_type_index(ptr)? {
            let underlying_type = ptr_type.underlying_type;
            if underlying_type == class {
                return Ok(PtrToClassKind::PtrToGivenClass { constant: false });
            }
            let underlying_type_data = self.parse_type_index(underlying_type)?;
            if let TypeData::Modifier(modifier) = underlying_type_data {
                if modifier.underlying_type == class {
                    return Ok(PtrToClassKind::PtrToGivenClass {
                        constant: modifier.constant,
                    });
                }
            }
        };
        Ok(PtrToClassKind::OtherType)
    }

    /// Return value: (this is pointer to const class, optional extra first argument)
    fn get_class_constness_and_extra_arguments(
        &mut self,
        this: TypeIndex,
        class: TypeIndex,
    ) -> Result<(bool, Option<TypeIndex>)> {
        match self.is_ptr_to_class(this, class)? {
            PtrToClassKind::PtrToGivenClass { constant } => {
                // The this type looks normal. Don'a return an extra argument.
                Ok((constant, None))
            }
            PtrToClassKind::OtherType => {
                // The type of the "this" pointer did not match the class type.
                // This is arguably bad type information.
                // It looks like this bad type information is emitted for all Rust "associated
                // functions" whose first argument is a reference. Associated functions don'a
                // take a self argument, so it would make sense to treat them as static.
                // But instead, these functions are marked as non-static, and the first argument's
                // type, rather than being part of the arguments list, is stored in the "this" type.
                // For example, for ProfileScope::new(name: &'static CStr), the arguments list is
                // empty and the this type is CStr*.
                // To work around this, return the this type as an extra first argument.
                Ok((false, Some(this)))
            }
        }
    }

    fn emit_method_args(
        &mut self,
        w: &mut impl Write,
        method_type: MemberFunctionType,
        allow_emit_const: bool,
    ) -> Result<()> {
        let args_list = match self.parse_type_index(method_type.argument_list)? {
            TypeData::ArgumentList(t) => t,
            _ => {
                return Err(Error::ArgumentTypeNotArgumentList);
            }
        };

        let (is_const_method, extra_first_arg) = match method_type.this_pointer_type {
            None => {
                // No this pointer - this is a static method.
                // Static methods cannot be const, and they have the correct arguments.
                (false, None)
            }
            Some(this_type) => {
                // For non-static methods, check whether the method is const, and work around a
                // problem with bad type information for Rust associated functions.
                self.get_class_constness_and_extra_arguments(this_type, method_type.class_type)?
            }
        };

        write!(w, "(")?;
        if let Some(first_arg) = extra_first_arg {
            self.emit_type_index(w, first_arg)?;
            self.emit_arg_list(w, args_list, true)?;
        } else {
            self.emit_arg_list(w, args_list, false)?;
        }
        write!(w, ")")?;

        if is_const_method && allow_emit_const {
            write!(w, " const")?;
        }

        Ok(())
    }

    // Should we emit a space as the first byte from emit_attributes? It depends.
    // "*" in a table cell means "value has no impact on the outcome".
    //
    //  caller allows space | attributes start with | SPACE_BEFORE_POINTER mode | previous byte was   | put space at the beginning?
    // ---------------------+-----------------------+---------------------------+---------------------+----------------------------
    //  no                  | *                     | *                         | *                   | no
    //  yes                 | const                 | *                         | *                   | yes
    //  yes                 | pointer sigil         | off                       | *                   | no
    //  yes                 | pointer sigil         | on                        | pointer sigil       | no
    //  yes                 | pointer sigil         | on                        | not a pointer sigil | yes
    fn emit_attributes(
        &mut self,
        w: &mut impl Write,
        attrs: Vec<PtrAttributes>,
        allow_space_at_beginning: bool,
        mut previous_byte_was_pointer_sigil: bool,
    ) -> Result<()> {
        let mut is_at_beginning = true;
        for attr in attrs.iter().rev() {
            if attr.is_pointee_const {
                if !is_at_beginning || allow_space_at_beginning {
                    write!(w, " ")?;
                }
                write!(w, "const")?;
                is_at_beginning = false;
                previous_byte_was_pointer_sigil = false;
            }

            if self.has_flags(TypeFormatterFlags::SPACE_BEFORE_POINTER)
                && !previous_byte_was_pointer_sigil
                && (!is_at_beginning || allow_space_at_beginning)
            {
                write!(w, " ")?;
            }
            is_at_beginning = false;
            match attr.mode {
                PointerMode::Pointer => write!(w, "*")?,
                PointerMode::LValueReference => write!(w, "&")?,
                PointerMode::Member => write!(w, "::*")?,
                PointerMode::MemberFunction => write!(w, "::*")?,
                PointerMode::RValueReference => write!(w, "&&")?,
            }
            previous_byte_was_pointer_sigil = true;
            if attr.is_pointer_const {
                write!(w, " const")?;
                previous_byte_was_pointer_sigil = false;
            }
        }
        Ok(())
    }

    fn emit_member_ptr(
        &mut self,
        w: &mut impl Write,
        fun: MemberFunctionType,
        attributes: Vec<PtrAttributes>,
    ) -> Result<()> {
        self.emit_return_type(w, Some(fun.return_type), fun.attributes)?;
        write!(w, "(")?;
        self.emit_type_index(w, fun.class_type)?;
        self.emit_attributes(w, attributes, false, false)?;
        write!(w, ")")?;
        self.emit_method_args(w, fun, false)?;
        Ok(())
    }

    fn emit_proc_ptr(
        &mut self,
        w: &mut impl Write,
        fun: ProcedureType,
        attributes: Vec<PtrAttributes>,
    ) -> Result<()> {
        self.emit_return_type(w, fun.return_type, fun.attributes)?;

        write!(w, "(")?;
        self.emit_attributes(w, attributes, false, false)?;
        write!(w, ")")?;
        write!(w, "(")?;
        self.emit_type_index(w, fun.argument_list)?;
        write!(w, ")")?;
        Ok(())
    }

    fn emit_other_ptr(
        &mut self,
        w: &mut impl Write,
        type_data: TypeData,
        attributes: Vec<PtrAttributes>,
    ) -> Result<()> {
        let mut buf = String::new();
        self.emit_type(&mut buf, type_data)?;
        let previous_byte_was_pointer_sigil = buf
            .as_bytes()
            .last()
            .map(|&b| b == b'*' || b == b'&')
            .unwrap_or(false);
        w.write_str(&buf)?;
        self.emit_attributes(w, attributes, true, previous_byte_was_pointer_sigil)?;

        Ok(())
    }

    fn emit_ptr_helper(
        &mut self,
        w: &mut impl Write,
        attributes: Vec<PtrAttributes>,
        type_data: TypeData,
    ) -> Result<()> {
        match type_data {
            TypeData::MemberFunction(t) => self.emit_member_ptr(w, t, attributes)?,
            TypeData::Procedure(t) => self.emit_proc_ptr(w, t, attributes)?,
            _ => self.emit_other_ptr(w, type_data, attributes)?,
        };
        Ok(())
    }

    fn emit_ptr(&mut self, w: &mut impl Write, ptr: PointerType, is_const: bool) -> Result<()> {
        let mut attributes = vec![PtrAttributes {
            is_pointer_const: ptr.attributes.is_const() || is_const,
            is_pointee_const: false,
            mode: ptr.attributes.pointer_mode(),
        }];
        let mut ptr = ptr;
        loop {
            let type_data = self.parse_type_index(ptr.underlying_type)?;
            match type_data {
                TypeData::Pointer(t) => {
                    attributes.push(PtrAttributes {
                        is_pointer_const: t.attributes.is_const(),
                        is_pointee_const: false,
                        mode: t.attributes.pointer_mode(),
                    });
                    ptr = t;
                }
                TypeData::Modifier(t) => {
                    // the vec cannot be empty since we push something in just before the loop
                    attributes.last_mut().unwrap().is_pointee_const = t.constant;
                    let underlying_type_data = self.parse_type_index(t.underlying_type)?;
                    if let TypeData::Pointer(t) = underlying_type_data {
                        attributes.push(PtrAttributes {
                            is_pointer_const: t.attributes.is_const(),
                            is_pointee_const: false,
                            mode: t.attributes.pointer_mode(),
                        });
                        ptr = t;
                    } else {
                        self.emit_ptr_helper(w, attributes, underlying_type_data)?;
                        return Ok(());
                    }
                }
                _ => {
                    self.emit_ptr_helper(w, attributes, type_data)?;
                    return Ok(());
                }
            }
        }
    }

    /// The returned Vec has the array dimensions in bytes, with the "lower" dimensions
    /// aggregated into the "higher" dimensions.
    fn get_array_info(&mut self, array: ArrayType) -> Result<(Vec<u32>, TypeIndex, TypeData<'a>)> {
        // For an array int[12][34] it'll be represented as "int[34] *".
        // For any reason the 12 is lost...
        // The internal representation is: Pointer{ base: Array{ base: int, dim: 34 * sizeof(int)} }
        let mut base = array;
        let mut dims = Vec::new();
        dims.push(base.dimensions[0]);

        // See the documentation for ArrayType::dimensions:
        //
        // > Contains array dimensions as specified in the PDB. This is not what you expect:
        // >
        // > * Dimensions are specified in terms of byte sizes, not element counts.
        // > * Multidimensional arrays aggregate the lower dimensions into the sizes of the higher
        // >   dimensions.
        // >
        // > Thus a `float[4][4]` has `dimensions: [16, 64]`. Determining array dimensions in terms
        // > of element counts requires determining the size of the `element_type` and iteratively
        // > dividing.
        //
        // XXXmstange the docs above imply that dimensions can have more than just one entry.
        // But this code only processes dimensions[0]. Is that a bug?
        loop {
            let type_index = base.element_type;
            let type_data = self.parse_type_index(type_index)?;
            match type_data {
                TypeData::Array(a) => {
                    dims.push(a.dimensions[0]);
                    base = a;
                }
                _ => {
                    return Ok((dims, type_index, type_data));
                }
            }
        }
    }

    fn emit_array(&mut self, w: &mut impl Write, array: ArrayType) -> Result<()> {
        let (dimensions_as_bytes, base_index, base) = self.get_array_info(array)?;
        let base_size = self.get_data_size(base_index, &base);
        self.emit_type(w, base)?;

        let mut iter = dimensions_as_bytes.into_iter().peekable();
        while let Some(current_level_byte_size) = iter.next() {
            let next_level_byte_size = *iter.peek().unwrap_or(&base_size);
            if next_level_byte_size != 0 {
                let element_count = current_level_byte_size / next_level_byte_size;
                write!(w, "[{}]", element_count)?;
            } else {
                // The base size can be zero: struct A{}; void foo(A x[10])
                // No way to get the array dimension in such a case
                write!(w, "[]")?;
            };
        }

        Ok(())
    }

    fn emit_modifier(&mut self, w: &mut impl Write, modifier: ModifierType) -> Result<()> {
        let type_data = self.parse_type_index(modifier.underlying_type)?;
        match type_data {
            TypeData::Pointer(ptr) => self.emit_ptr(w, ptr, modifier.constant)?,
            TypeData::Primitive(prim) => self.emit_primitive(w, prim, modifier.constant)?,
            _ => {
                if modifier.constant {
                    write!(w, "const ")?
                }
                self.emit_type(w, type_data)?;
            }
        }
        Ok(())
    }

    fn emit_class(&mut self, w: &mut impl Write, class: ClassType) -> Result<()> {
        if self.has_flags(TypeFormatterFlags::NAME_ONLY) {
            write!(w, "{}", class.name)?;
        } else {
            let name = match class.kind {
                ClassKind::Class => "class",
                ClassKind::Interface => "interface",
                ClassKind::Struct => "struct",
            };
            write!(w, "{} {}", name, class.name)?
        }
        Ok(())
    }

    fn emit_arg_list(
        &mut self,
        w: &mut impl Write,
        list: ArgumentList,
        comma_before_first: bool,
    ) -> Result<()> {
        if let Some((first, args)) = list.arguments.split_first() {
            if comma_before_first {
                write!(w, ",")?;
                if self.has_flags(TypeFormatterFlags::SPACE_AFTER_COMMA) {
                    write!(w, " ")?;
                }
            }
            self.emit_type_index(w, *first)?;
            for index in args.iter() {
                write!(w, ",")?;
                if self.has_flags(TypeFormatterFlags::SPACE_AFTER_COMMA) {
                    write!(w, " ")?;
                }
                self.emit_type_index(w, *index)?;
            }
        }
        Ok(())
    }

    fn emit_primitive(
        &mut self,
        w: &mut impl Write,
        prim: PrimitiveType,
        is_const: bool,
    ) -> Result<()> {
        // TODO: check that these names are what we want to see
        let name = match prim.kind {
            PrimitiveKind::NoType => "<NoType>",
            PrimitiveKind::Void => "void",
            PrimitiveKind::Char => "signed char",
            PrimitiveKind::UChar => "unsigned char",
            PrimitiveKind::RChar => "char",
            PrimitiveKind::WChar => "wchar_t",
            PrimitiveKind::RChar16 => "char16_t",
            PrimitiveKind::RChar32 => "char32_t",
            PrimitiveKind::I8 => "int8_t",
            PrimitiveKind::U8 => "uint8_t",
            PrimitiveKind::Short => "short",
            PrimitiveKind::UShort => "unsigned short",
            PrimitiveKind::I16 => "int16_t",
            PrimitiveKind::U16 => "uint16_t",
            PrimitiveKind::Long => "long",
            PrimitiveKind::ULong => "unsigned long",
            PrimitiveKind::I32 => "int",
            PrimitiveKind::U32 => "unsigned int",
            PrimitiveKind::Quad => "long long",
            PrimitiveKind::UQuad => "unsigned long long",
            PrimitiveKind::I64 => "int64_t",
            PrimitiveKind::U64 => "uint64_t",
            PrimitiveKind::I128 | PrimitiveKind::Octa => "int128_t",
            PrimitiveKind::U128 | PrimitiveKind::UOcta => "uint128_t",
            PrimitiveKind::F16 => "float16_t",
            PrimitiveKind::F32 => "float",
            PrimitiveKind::F32PP => "float",
            PrimitiveKind::F48 => "float48_t",
            PrimitiveKind::F64 => "double",
            PrimitiveKind::F80 => "long double",
            PrimitiveKind::F128 => "long double",
            PrimitiveKind::Complex32 => "complex<float>",
            PrimitiveKind::Complex64 => "complex<double>",
            PrimitiveKind::Complex80 => "complex<long double>",
            PrimitiveKind::Complex128 => "complex<long double>",
            PrimitiveKind::Bool8 => "bool",
            PrimitiveKind::Bool16 => "bool16_t",
            PrimitiveKind::Bool32 => "bool32_t",
            PrimitiveKind::Bool64 => "bool64_t",
            PrimitiveKind::HRESULT => "HRESULT",
            _ => panic!("Unknown PrimitiveKind {:?} in emit_primitive", prim.kind),
        };

        if prim.indirection.is_some() {
            if self.has_flags(TypeFormatterFlags::SPACE_BEFORE_POINTER) {
                if is_const {
                    write!(w, "{} const *", name)?
                } else {
                    write!(w, "{} *", name)?
                }
            } else if is_const {
                write!(w, "{} const*", name)?
            } else {
                write!(w, "{}*", name)?
            }
        } else if is_const {
            write!(w, "const {}", name)?
        } else {
            write!(w, "{}", name)?
        }
        Ok(())
    }

    fn emit_named(&mut self, w: &mut impl Write, base: &str, name: RawString) -> Result<()> {
        if self.has_flags(TypeFormatterFlags::NAME_ONLY) {
            write!(w, "{}", name)?
        } else {
            write!(w, "{} {}", base, name)?
        }

        Ok(())
    }

    fn emit_type_index(&mut self, w: &mut impl Write, index: TypeIndex) -> Result<()> {
        let type_data = match self.parse_type_index(index) {
            Ok(type_data) => type_data,
            Err(Error::PdbError(pdb::Error::UnimplementedTypeKind(t))) => {
                write!(w, "<unimplemented type kind 0x{:x}>", t)?;
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        self.emit_type(w, type_data)
    }

    fn emit_type(&mut self, w: &mut impl Write, type_data: TypeData) -> Result<()> {
        match type_data {
            TypeData::Primitive(t) => self.emit_primitive(w, t, false)?,
            TypeData::Class(t) => self.emit_class(w, t)?,
            TypeData::MemberFunction(t) => {
                self.maybe_emit_return_type(w, Some(t.return_type), t.attributes)?;
                write!(w, "()")?;
                self.emit_method_args(w, t, false)?;
            }
            TypeData::Procedure(t) => {
                self.maybe_emit_return_type(w, t.return_type, t.attributes)?;
                write!(w, "()(")?;
                self.emit_type_index(w, t.argument_list)?;
                write!(w, "")?;
            }
            TypeData::ArgumentList(t) => self.emit_arg_list(w, t, false)?,
            TypeData::Pointer(t) => self.emit_ptr(w, t, false)?,
            TypeData::Array(t) => self.emit_array(w, t)?,
            TypeData::Union(t) => self.emit_named(w, "union", t.name)?,
            TypeData::Enumeration(t) => self.emit_named(w, "enum", t.name)?,
            TypeData::Enumerate(t) => self.emit_named(w, "enum class", t.name)?,
            TypeData::Modifier(t) => self.emit_modifier(w, t)?,
            _ => write!(w, "unhandled type /* {:?} */", type_data)?,
        }

        Ok(())
    }
}

#[derive(Eq, PartialEq)]
enum PtrToClassKind {
    PtrToGivenClass {
        /// If true, the pointer is a "pointer to const ClassType".
        constant: bool,
    },
    OtherType,
}

#[derive(Debug)]
struct PtrAttributes {
    is_pointer_const: bool,
    is_pointee_const: bool,
    mode: PointerMode,
}

struct ItemMap<'a, I: ItemIndex> {
    iter: ItemIter<'a, I>,
    finder: ItemFinder<'a, I>,
}

impl<'a, I> ItemMap<'a, I>
where
    I: ItemIndex,
{
    pub fn try_get(&mut self, index: I) -> std::result::Result<Item<'a, I>, pdb::Error> {
        if index <= self.finder.max_index() {
            return self.finder.find(index);
        }

        while let Some(item) = self.iter.next()? {
            self.finder.update(&self.iter);
            match item.index().partial_cmp(&index) {
                Some(Ordering::Equal) => return Ok(item),
                Some(Ordering::Greater) => break,
                _ => continue,
            }
        }

        Err(pdb::Error::TypeNotFound(index.into()))
    }
}

type IdMap<'a> = ItemMap<'a, IdIndex>;
type TypeMap<'a> = ItemMap<'a, TypeIndex>;

struct TypeSizeCache<'a> {
    /// A hashmap that maps a type's (unique) name to its type size.
    ///
    /// When computing type sizes, special care must be taken for types which are
    /// marked as "forward references": For these types, the size must be taken from
    /// the occurrence of the type with the same (unique) name which is not marked as
    /// a forward reference.
    ///
    /// In order to be able to look up these sizes, we create a map which
    /// contains all sizes for non-forward_reference types. This map is populated on
    /// demand as the type iter is advanced.
    ///
    /// Type sizes are needed when computing array lengths based on byte lengths, when
    /// printing array types. They are also needed for the public get_type_size method.
    forward_ref_sizes: HashMap<RawString<'a>, u32>,

    cached_ranges: RangeSet<u32>,
}

impl<'a> TypeSizeCache<'a> {
    pub fn get_size_for_forward_reference(
        &mut self,
        index: TypeIndex,
        name: RawString<'a>,
        type_map: &mut TypeMap<'a>,
    ) -> Option<u32> {
        if let Some(size) = self.forward_ref_sizes.get(&name) {
            return Some(*size);
        }

        let start_index = index.0;
        let candidate_range = RangeSet::from((start_index + 1)..);
        let uncached_ranges = &candidate_range - &self.cached_ranges;
        for uncached_range in uncached_ranges.iter() {
            let (range_start, range_end) = match uncached_range {
                (Bound::Included(range_start), Bound::Excluded(range_end)) => {
                    (*range_start, Some(*range_end))
                }
                (Bound::Included(range_start), Bound::Unbounded) => (*range_start, None),
                _ => panic!("Unexpected range {:?}", uncached_range),
            };
            for index in range_start.. {
                if let Some(range_end) = range_end {
                    if index >= range_end {
                        break;
                    }
                }
                if let Ok(item) = type_map.try_get(TypeIndex(index)) {
                    let s = self.update_forward_ref_size_map(&item);
                    if let Some((found_name, found_size)) = s {
                        if found_name == name {
                            self.cached_ranges |= RangeSet::from(start_index..(index + 1));
                            return Some(found_size);
                        }
                    }
                } else {
                    break;
                }
            }
        }
        self.cached_ranges |= RangeSet::from(start_index..);

        None
    }

    pub fn update_forward_ref_size_map(
        &mut self,
        item: &Item<'a, TypeIndex>,
    ) -> Option<(RawString<'a>, u32)> {
        if let Ok(type_data) = item.parse() {
            match type_data {
                TypeData::Class(t) => {
                    if !t.properties.forward_reference() {
                        let name = t.unique_name.unwrap_or(t.name);
                        self.forward_ref_sizes.insert(name, t.size.into());
                        return Some((name, t.size.into()));
                    }
                }
                TypeData::Union(t) => {
                    if !t.properties.forward_reference() {
                        let name = t.unique_name.unwrap_or(t.name);
                        self.forward_ref_sizes.insert(name, t.size);
                        return Some((name, t.size));
                    }
                }
                _ => {}
            }
        }
        None
    }
}
