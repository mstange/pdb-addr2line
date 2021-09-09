use std::{error::Error, path::{Path, PathBuf}};

use pdb::IdIndex;
use pdb_addr2line::{pdb, TypeFormatter};

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
    let mut pdb = pdb::PDB::open(file)?;
    let debug_info = pdb.debug_information()?;
    let type_info = pdb.type_information()?;
    let id_info = pdb.id_information()?;
    let formatter = TypeFormatter::new(&debug_info, &type_info, &id_info, Default::default())?;

    assert_eq!(formatter.format_id(IdIndex(0x1310))?, "`anonymous namespace'::start()");
    assert_eq!(formatter.format_id(IdIndex(0x1311))?, "`anonymous namespace'::crash()");

    Ok(())
}