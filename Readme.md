[![crates.io page](http://meritbadge.herokuapp.com/pdb-addr2line)](https://crates.io/crates/pdb-addr2line)
[![docs.rs page](https://docs.rs/pdb-addr2line/badge.svg)](https://docs.rs/pdb-addr2line/)

# pdb-addr2line

Resolve addresses to function names, and to file name and line number
information, with the help of a PDB file. Inline stacks are supported.

The API of this crate is intended to be similar to the API of the
[`addr2line` crate](https://docs.rs/addr2line/); the two `Context` APIs
have comparable functionality. This crate is for PDB files whereas `addr2line`
is for DWARF data (which is used in ELF and mach-o binaries, for example).

This crate also has a `TypeFormatter` API which can be used to get function signature
strings independently from a `Context`.

To create a `Context`, use `ContextPdbData`.

## Example

```rust
use pdb_addr2line::pdb;

fn look_up_addresses<'s, S: pdb::Source<'s> + 's>(stream: S, addresses: &[u32]) -> pdb::Result<()> {
    let mut pdb = pdb::PDB::open(stream)?;
    let context_data = pdb_addr2line::ContextPdbData::try_from_pdb(&mut pdb)?;
    let context = context_data.make_context()?;

    for address in addresses {
        if let Some(procedure_frames) = context.find_frames(*address)? {
            eprintln!("0x{:x} - {} frames:", address, procedure_frames.frames.len());
            for frame in procedure_frames.frames {
                let line_str = frame.line.map(|l| format!("{}", l));
                eprintln!(
                    "     {} at {}:{}",
                    frame.function.as_deref().unwrap_or("<unknown>"),
                    frame.file.as_deref().unwrap_or("??"),
                    line_str.as_deref().unwrap_or("??"),
                )
            }
        } else {
            eprintln!("{:x} - no frames found", address);
        }
    }
    Ok(())
}
```

# Command-line usage

This repository also contains a CLI executable mirrored after addr2line.
You can install it using `cargo install`:

```
cargo install --examples pdb-addr2line
```

Here are some example uses:

```
$ curl -o dcomp.pdb -L "https://msdl.microsoft.com/download/symbols/dcomp.pdb/648B8DD0780A4E22FA7FA89B84633C231/dcomp.pdb"
$ pdb-addr2line --exe dcomp.pdb -f 0x59aa0 0x52340 0x467e8
Windows::UI::Composition::Compositor::Api::CreateScalarKeyFrameAnimation
??:?
std::map<unsigned int,Windows::UI::Composition::AnimationLoggingManager::ReferencedObject,std::less<unsigned int>,std::allocator<std::pair<unsigned int const ,Windows::UI::Composition::AnimationLoggingManager::ReferencedObject> > >::_Try_emplace<unsigned int const &>
??:?
DirectComposition::CVirtualSurfacePrimitive::CVirtualSurfacePrimitive
??:?
```

```
$ curl -o mozglue.pdb -L "https://github.com/mstange/profiler-get-symbols/raw/master/fixtures/win64-ci/mozglue.pdb"
$ pdb-addr2line --exe mozglue.pdb -fi 0x3b9fb
mozilla::JSONWriter::StartCollection(char const*, char const*, mozilla::JSONWriter::CollectionStyle)
/builds/worker/workspace/obj-build/dist/include/mozilla/JSONWriter.h:318
mozilla::JSONWriter::StartArrayProperty(char const*, mozilla::JSONWriter::CollectionStyle)
/builds/worker/workspace/obj-build/dist/include/mozilla/JSONWriter.h:417
mozilla::JSONWriter::StartArrayElement(mozilla::JSONWriter::CollectionStyle)
/builds/worker/workspace/obj-build/dist/include/mozilla/JSONWriter.h:422
mozilla::baseprofiler::AutoArraySchemaWriter::AutoArraySchemaWriter(mozilla::baseprofiler::SpliceableJSONWriter&, mozilla::baseprofiler::UniqueJSONStrings&)
/builds/worker/checkouts/gecko/mozglue/baseprofiler/core/ProfileBufferEntry.cpp:141
mozilla::baseprofiler::WriteSample(mozilla::baseprofiler::SpliceableJSONWriter&, mozilla::baseprofiler::UniqueJSONStrings&, mozilla::baseprofiler::ProfileSample const&)
/builds/worker/checkouts/gecko/mozglue/baseprofiler/core/ProfileBufferEntry.cpp:361
mozilla::baseprofiler::ProfileBuffer::StreamSamplesToJSON::<unnamed-tag>::operator()(mozilla::ProfileChunkedBuffer::Reader*) const
/builds/worker/checkouts/gecko/mozglue/baseprofiler/core/ProfileBufferEntry.cpp:809
```
