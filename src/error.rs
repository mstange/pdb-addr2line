#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Formatting error: {0}")]
    FormatError(#[source] std::fmt::Error),

    #[error("PDB error: {0}")]
    PdbError(#[source] pdb::Error),

    #[error("Unexpected type for argument list")]
    ArgumentTypeNotArgumentList,

    #[error("Id of type Function doesn't have type of Procedure")]
    FunctionIdIsNotProcedureType,

    #[error("Id of type MemberFunction doesn't have type of MemberFunction")]
    MemberFunctionIdIsNotMemberFunctionType,

    #[error("There are consecutive section contributions for module {0} and section {1} which are not ordered by offset")]
    UnorderedSectionContributions(usize, u16),

    #[error("Overlapping section contributions in section {0} from modules {1} and {2}")]
    OverlappingSectionContributions(u16, usize, usize),

    #[error("Getting the procedure lines was unsuccessful")]
    ProcedureLinesUnsuccessful,

    #[error("Getting the procedure inline ranges was unsuccessful")]
    ProcedureInlineRangesUnsuccessful,

    #[error("Getting the extended module info was unsuccessful")]
    ExtendedModuleInfoUnsuccessful,

    #[error("Could not resolve cross-module reference due to missing string table")]
    CantResolveCrossModuleRefWithoutStringTable,

    #[error("Getting the module imports was unsuccessful")]
    ModuleImportsUnsuccessful,

    #[error("Could not find the module with name {0}")]
    ModuleNameNotFound(String),

    #[error("Getting the module exports was unsuccessful")]
    ModuleExportsUnsuccessful,

    #[error("The local index {0} was not found in the module exports")]
    LocalIndexNotInExports(u32),

    #[error("The module index {0} was out-of-range.")]
    OutOfRangeModuleIndex(usize),

    #[error("Could not get the ModuleInfo for module index {0}")]
    ModuleInfoNotFound(usize),
}

impl From<pdb::Error> for Error {
    fn from(err: pdb::Error) -> Self {
        Self::PdbError(err)
    }
}

impl From<std::fmt::Error> for Error {
    fn from(err: std::fmt::Error) -> Self {
        Self::FormatError(err)
    }
}
