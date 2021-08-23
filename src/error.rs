#[derive(thiserror::Error, Debug)]
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
    UnorderedSectionContributions(u16, u16),

    #[error("Overlapping section contributions in section {0} from modules {1} and {2}")]
    OverlappingSectionContributions(u16, u16, u16),
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
