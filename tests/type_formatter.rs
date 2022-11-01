use std::{
    error::Error,
    path::{Path, PathBuf},
};

use pdb::IdIndex;
use pdb_addr2line::{pdb, ContextPdbData, TypeFormatterFlags};

/// Returns the full path to the specified fixture.
fn fixture<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    full_path.push("tests");
    full_path.push("fixtures");

    let path = path.as_ref();
    full_path.push(&path);

    assert!(
        full_path.exists(),
        "Fixture does not exist: {}",
        path.display()
    );

    full_path
}

#[test]
fn test() -> Result<(), Box<dyn Error>> {
    let file = std::fs::File::open(fixture("crash.pdb"))?;
    let data = ContextPdbData::try_from_pdb(pdb::PDB::open(file)?)?;
    let formatter = data.make_type_formatter()?;
    let formatter_without_args = data.make_type_formatter_with_flags(
        TypeFormatterFlags::default() | TypeFormatterFlags::NO_ARGUMENTS,
    )?;

    assert_eq!(
        formatter.format_id(0, IdIndex(0x12fe))?,
        "`anonymous namespace'::start()"
    );
    assert_eq!(
        formatter.format_id(0, IdIndex(0x12ff))?,
        "`anonymous namespace'::crash()"
    );
    assert_eq!(
        formatter.format_id(4, IdIndex(0x80000013))?,
        "std::allocator<wchar_t>::deallocate(wchar_t* const, const unsigned int)"
    );
    assert_eq!(
        formatter.format_id(4, IdIndex(0x80000007))?,
        "std::_Adjust_manually_vector_aligned(void*&, unsigned int&)"
    );

    assert_eq!(
        formatter_without_args.format_id(4, IdIndex(0x80000013))?,
        "std::allocator<wchar_t>::deallocate"
    );
    assert_eq!(
        formatter_without_args.format_id(4, IdIndex(0x80000007))?,
        "std::_Adjust_manually_vector_aligned"
    );

    Ok(())
}
