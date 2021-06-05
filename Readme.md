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

The implementation makes use of the excellent [`pdb` crate](https://crates.io/crates/pdb).

## Example

```rust
use pdb_addr2line::pdb; // (this is a re-export of the pdb crate)

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

This repository also contains a CLI executable modelled after addr2line.
You can install it using `cargo install`:

```
cargo install --examples pdb-addr2line
```

Here are some example uses:

```
$ curl -o dcomp.pdb -L "https://msdl.microsoft.com/download/symbols/dcomp.pdb/648B8DD0780A4E22FA7FA89B84633C231/dcomp.pdb"
$ pdb-addr2line --exe dcomp.pdb -fC 0x59aa0 0x52340 0x13498
Windows::UI::Composition::Compositor::Api::CreateScalarKeyFrameAnimation
??:?
std::map<unsigned int,Windows::UI::Composition::AnimationLoggingManager::ReferencedObject,std::less<unsigned int>,std::allocator<std::pair<unsigned int const ,Windows::UI::Composition::AnimationLoggingManager::ReferencedObject> > >::_Try_emplace<unsigned int const &>
??:?
DirectComposition::CDxDevice::RemoveGuardRect(ID3D11Texture2D*)
??:?
```

```
$ curl -o mozglue.pdb -L "https://github.com/mstange/profiler-get-symbols/raw/master/fixtures/win64-ci/mozglue.pdb"
$ pdb-addr2line -e mozglue.pdb -psfi 0x3b9fb
mozilla::JSONWriter::StartCollection(char const*, char const*, mozilla::JSONWriter::CollectionStyle) at JSONWriter.h:318
 (inlined by) mozilla::JSONWriter::StartArrayProperty(char const*, mozilla::JSONWriter::CollectionStyle) at JSONWriter.h:417
 (inlined by) mozilla::JSONWriter::StartArrayElement(mozilla::JSONWriter::CollectionStyle) at JSONWriter.h:422
 (inlined by) mozilla::baseprofiler::AutoArraySchemaWriter::AutoArraySchemaWriter(mozilla::baseprofiler::SpliceableJSONWriter&, mozilla::baseprofiler::UniqueJSONStrings&) at ProfileBufferEntry.cpp:141
 (inlined by) mozilla::baseprofiler::WriteSample(mozilla::baseprofiler::SpliceableJSONWriter&, mozilla::baseprofiler::UniqueJSONStrings&, mozilla::baseprofiler::ProfileSample const&) at ProfileBufferEntry.cpp:361
 (inlined by) mozilla::baseprofiler::ProfileBuffer::StreamSamplesToJSON::<unnamed-tag>::operator()(mozilla::ProfileChunkedBuffer::Reader*) const at ProfileBufferEntry.cpp:809
```

# Performance

`pdb-addr2line` optimizes for speed over memory by caching parsed information.
The debug information about inlines, files and line numbers is parsed lazily where possible.

## License

Licensed under either of

  * Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
  * MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
