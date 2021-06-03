use std::borrow::Cow;
use std::fs::File;
use std::io::Cursor;
use std::io::{BufRead, Lines, StdinLock, Write};
use std::path::Path;

use clap::{App, Arg, Values};
use pdb_addr2line::pdb;

fn parse_uint_from_hex_string(string: &str) -> u32 {
    if string.len() > 2 && string.starts_with("0x") {
        u32::from_str_radix(&string[2..], 16).expect("Failed to parse address")
    } else {
        u32::from_str_radix(string, 16).expect("Failed to parse address")
    }
}

enum Addrs<'a> {
    Args(Values<'a>),
    Stdin(Lines<StdinLock<'a>>),
}

impl<'a> Iterator for Addrs<'a> {
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
        let file: &str = &file;
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

fn print_function(name: &str, _demangle: bool) {
    // TODO: Implement demangling
    print!("{}", name);
}

fn main() {
    let matches = App::new("hardliner")
        .version("0.1")
        .about("A fast addr2line clone")
        .arg(
            Arg::with_name("exe")
                .short("e")
                .long("exe")
                .value_name("filename")
                .help(
                    "Specify the name of the executable for which addresses should be translated.",
                )
                .required(true),
        )
        .arg(
            Arg::with_name("sup")
                .long("sup")
                .value_name("filename")
                .help("Path to supplementary object file."),
        )
        .arg(
            Arg::with_name("functions")
                .short("f")
                .long("functions")
                .help("Display function names as well as file and line number information."),
        )
        .arg(
            Arg::with_name("pretty")
                .short("p")
                .long("pretty-print")
                .help(
                    "Make the output more human friendly: each location are printed on \
                     one line.",
                ),
        )
        .arg(Arg::with_name("inlines").short("i").long("inlines").help(
            "If the address belongs to a function that was inlined, the source \
             information for all enclosing scopes back to the first non-inlined \
             function will also be printed.",
        ))
        .arg(
            Arg::with_name("addresses")
                .short("a")
                .long("addresses")
                .help(
                    "Display the address before the function name, file and line \
                     number information.",
                ),
        )
        .arg(
            Arg::with_name("basenames")
                .short("s")
                .long("basenames")
                .help("Display only the base of each file name."),
        )
        .arg(Arg::with_name("demangle").short("C").long("demangle").help(
            "Demangle function names. \
             Specifying a specific demangling style (like GNU addr2line) \
             is not supported. (TODO)",
        ))
        .arg(
            Arg::with_name("llvm")
                .long("llvm")
                .help("Display output in the same format as llvm-symbolizer."),
        )
        .arg(
            Arg::with_name("addrs")
                .takes_value(true)
                .multiple(true)
                .help("Addresses to use instead of reading from stdin."),
        )
        .get_matches();

    let do_functions = matches.is_present("functions");
    let do_inlines = matches.is_present("inlines");
    let pretty = matches.is_present("pretty");
    let print_addrs = matches.is_present("addresses");
    let basenames = matches.is_present("basenames");
    let demangle = matches.is_present("demangle");
    let llvm = matches.is_present("llvm");
    let path = matches.value_of("exe").unwrap();

    let file = File::open(path).unwrap();
    let map = unsafe { memmap2::MmapOptions::new().map(&file).unwrap() };
    let cursor = Cursor::new(map);
    let mut pdb = pdb::PDB::open(cursor).unwrap();

    let dbi = pdb.debug_information().unwrap();
    let tpi = pdb.type_information().unwrap();
    let ipi = pdb.id_information().unwrap();
    let flags = pdb_addr2line::TypeFormatterFlags::default()
        | pdb_addr2line::TypeFormatterFlags::NO_MEMBER_FUNCTION_STATIC;
    let type_formatter = pdb_addr2line::TypeFormatter::new(&dbi, &tpi, &ipi, flags).unwrap();
    let context_data = pdb_addr2line::ContextConstructionData::try_from_pdb(&mut pdb).unwrap();
    let ctx = pdb_addr2line::Context::new(&context_data, &type_formatter).unwrap();

    let stdin = std::io::stdin();
    let addrs = matches
        .values_of("addrs")
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
            let frames = ctx.find_frames(probe).unwrap().unwrap();
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
