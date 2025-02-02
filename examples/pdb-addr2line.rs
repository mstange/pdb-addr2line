use std::borrow::Cow;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, Lines, StdinLock, Write};
use std::path::{Path, PathBuf};

use clap::parser::ValuesRef;
use clap::{value_parser, Arg, ArgAction, Command};
use msvc_demangler::DemangleFlags;
use pdb_addr2line::pdb;

fn parse_uint_from_hex_string(string: &str) -> u32 {
    if string.len() > 2 && string.starts_with("0x") {
        u32::from_str_radix(&string[2..], 16).expect("Failed to parse address")
    } else {
        u32::from_str_radix(string, 16).expect("Failed to parse address")
    }
}

enum Addrs<'a> {
    Args(ValuesRef<'a, String>),
    Stdin(Lines<StdinLock<'a>>),
}

impl Iterator for Addrs<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let text = match *self {
            Addrs::Args(ref mut vals) => vals.next().map(Cow::from),
            Addrs::Stdin(ref mut lines) => lines.next().map(Result::unwrap).map(Cow::from),
        };
        text.as_ref()
            .map(Cow::as_ref)
            .map(parse_uint_from_hex_string)
    }
}

fn print_loc(file: &Option<Cow<str>>, line: Option<u32>, basenames: bool, llvm: bool) {
    if let Some(file) = file {
        let file: &str = file;
        let path = if basenames {
            Path::new(Path::new(file).file_name().unwrap())
        } else {
            Path::new(file)
        };
        print!("{}:", path.display());
        if llvm {
            print!("{}:0", line.unwrap_or(0));
        } else if let Some(line) = line {
            print!("{}", line);
        } else {
            print!("?");
        }
        println!();
    } else if llvm {
        println!("??:0:0");
    } else {
        println!("??:?");
    }
}

fn print_function(name: &str, demangle: bool) {
    if demangle && name.starts_with('?') {
        let flags = DemangleFlags::NO_ACCESS_SPECIFIERS
            | DemangleFlags::NO_FUNCTION_RETURNS
            | DemangleFlags::NO_MEMBER_TYPE
            | DemangleFlags::NO_MS_KEYWORDS
            | DemangleFlags::NO_THISTYPE
            | DemangleFlags::NO_CLASS_TYPE
            | DemangleFlags::SPACE_AFTER_COMMA
            | DemangleFlags::HUG_TYPE;
        print!(
            "{}",
            msvc_demangler::demangle(name, flags)
                .as_deref()
                .unwrap_or(name)
        );
    } else {
        print!("{}", name);
    }
}

fn main() {
    let matches = Command::new("pdb-addr2line")
        .version("0.1")
        .about("A fast addr2line port for PDBs")
        .args(&[
            Arg::new("exe")
                .short('e')
                .long("exe")
                .value_name("filename")
                .value_parser(value_parser!(PathBuf))
                .help(
                    "Specify the name of the executable for which addresses should be translated.",
                )
                .required(true),
            Arg::new("sup")
                .long("sup")
                .value_name("filename")
                .help("Path to supplementary object file."),
            Arg::new("functions")
                .action(ArgAction::SetTrue)
                .short('f')
                .long("functions")
                .help("Display function names as well as file and line number information."),
            Arg::new("pretty")
                .action(ArgAction::SetTrue)
                .short('p')
                .long("pretty-print")
                .help(
                    "Make the output more human friendly: each location are printed on \
                     one line.",
                ),
            Arg::new("inlines")
                .action(ArgAction::SetTrue)
                .short('i')
                .long("inlines")
                .help(
                    "If the address belongs to a function that was inlined, the source \
             information for all enclosing scopes back to the first non-inlined \
             function will also be printed.",
                ),
            Arg::new("addresses")
                .action(ArgAction::SetTrue)
                .short('a')
                .long("addresses")
                .help(
                    "Display the address before the function name, file and line \
                     number information.",
                ),
            Arg::new("basenames")
                .action(ArgAction::SetTrue)
                .short('s')
                .long("basenames")
                .help("Display only the base of each file name."),
            Arg::new("demangle")
                .action(ArgAction::SetTrue)
                .short('C')
                .long("demangle")
                .help(
                    "Demangle function names. \
             Specifying a specific demangling style (like GNU addr2line) \
             is not supported. (TODO)",
                ),
            Arg::new("llvm")
                .action(ArgAction::SetTrue)
                .long("llvm")
                .help("Display output in the same format as llvm-symbolizer."),
            Arg::new("addrs")
                .action(ArgAction::Append)
                .help("Addresses to use instead of reading from stdin."),
        ])
        .get_matches();

    let do_functions = matches.get_flag("functions");
    let do_inlines = matches.get_flag("inlines");
    let pretty = matches.get_flag("pretty");
    let print_addrs = matches.get_flag("addresses");
    let basenames = matches.get_flag("basenames");
    let demangle = matches.get_flag("demangle");
    let llvm = matches.get_flag("llvm");
    let path = matches.get_one::<PathBuf>("exe").unwrap();

    let file = File::open(path).unwrap();
    let map = unsafe { memmap2::MmapOptions::new().map(&file).unwrap() };
    let source = Source(map);

    let pdb = pdb::PDB::open(source).unwrap();
    let context_data = pdb_addr2line::ContextPdbData::try_from_pdb(pdb).unwrap();
    let ctx = context_data.make_context().unwrap();

    let stdin = std::io::stdin();
    let addrs = matches
        .get_many("addrs")
        .map(Addrs::Args)
        .unwrap_or_else(|| Addrs::Stdin(stdin.lock().lines()));

    for probe in addrs {
        if print_addrs {
            if llvm {
                print!("0x{:x}", probe);
            } else {
                print!("0x{:016x}", probe);
            }
            if pretty {
                print!(": ");
            } else {
                println!();
            }
        }

        if do_functions || do_inlines {
            let mut printed_anything = false;
            if let Some(frames) = ctx.find_frames(probe).unwrap() {
                for (i, frame) in frames.frames.iter().enumerate() {
                    if pretty && i != 0 {
                        print!(" (inlined by) ");
                    }

                    if do_functions {
                        if let Some(func) = &frame.function {
                            print_function(func, demangle);
                        } else {
                            print!("??");
                        }

                        if pretty {
                            print!(" at ");
                        } else {
                            println!();
                        }
                    }

                    print_loc(&frame.file, frame.line, basenames, llvm);

                    printed_anything = true;

                    if !do_inlines {
                        break;
                    }
                }
            }

            if !printed_anything {
                if do_functions {
                    print!("??");

                    if pretty {
                        print!(" at ");
                    } else {
                        println!();
                    }
                }

                if llvm {
                    println!("??:0:0");
                } else {
                    println!("??:?");
                }
            }
        } else {
            let frames = ctx.find_frames(probe).unwrap().unwrap();
            let frame = &frames.frames[0];
            print_loc(&frame.file, frame.line, basenames, llvm);
        }

        if llvm {
            println!();
        }
        std::io::stdout().flush().unwrap();
    }
}

#[derive(Debug)]
struct Source(memmap2::Mmap);

#[derive(Clone)]
struct ReadView {
    bytes: Vec<u8>,
}

impl fmt::Debug for ReadView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReadView({} bytes)", self.bytes.len())
    }
}

impl pdb::SourceView<'_> for ReadView {
    fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl<'s> pdb::Source<'s> for Source {
    fn view(
        &mut self,
        slices: &[pdb::SourceSlice],
    ) -> Result<Box<dyn pdb::SourceView<'s> + Send + Sync>, std::io::Error> {
        let len = slices.iter().fold(0, |acc, s| acc + s.size);

        let mut bytes = Vec::with_capacity(len);

        for slice in slices {
            bytes.extend_from_slice(&self.0[slice.offset as usize..][..slice.size]);
        }

        Ok(Box::new(ReadView { bytes }))
    }
}
