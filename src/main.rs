//! SEID command-line utility.

use std::env;
use std::process::exit;

use seid::{BlockType, Inst, Parity, Rand, Seid, Time, Tpl};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: seid <command> [arguments]\n");
        eprintln!("Commands:");
        eprintln!("  inspect <id>          Inspect and display structural AST");
        eprintln!("  mint <template_text>  Mint a sample identifier");
        exit(1);
    }

    match args[1].as_str() {
        "inspect" => {
            if args.len() < 3 {
                eprintln!("Error: Missing ID argument");
                exit(1);
            }
            let raw = &args[2];
            match Seid::parse(raw) {
                Ok(id) => {
                    println!("Identifier: {}", id);
                    println!("Blocks ({}):", id.block_count());
                    for (i, block) in id.blocks().iter().enumerate() {
                        let kind = block.kind();
                        println!("  [{}] {:<10} : \"{}\"", i, kind, block.as_str());
                    }

                    if id.contains_type(BlockType::Parity) {
                        let parity_ok = id.check_parity().unwrap_or(false);
                        println!("Parity verified: {}", parity_ok);
                    }
                }
                Err(e) => {
                    eprintln!("Parse error: {}", e);
                    exit(1);
                }
            }
        }
        "mint" => {
            let tpl_name = if args.len() >= 3 { &args[2] } else { "usr" };

            let mut builder = Seid::builder();
            builder = builder
                .block(Tpl::new(tpl_name).expect("Valid template"))
                .expect("Add block");
            builder = builder
                .block(Inst::new("eu1").expect("Valid instance"))
                .expect("Add block");

            #[cfg(feature = "sys-clock")]
            {
                builder = builder
                    .block(Time::now().expect("Valid time"))
                    .expect("Add block");
            }
            #[cfg(not(feature = "sys-clock"))]
            {
                builder = builder
                    .block(Time::new(100).expect("Valid time"))
                    .expect("Add block");
            }

            builder = builder.block(Rand::fast()).expect("Add block");

            // Parity block computes checksum over preceding blocks
            builder = builder
                .block_with(|blocks| Ok(Parity::compute(blocks)))
                .expect("Add parity");

            let id = builder.build().expect("Build SEID");
            println!("{}", id);
        }
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            exit(1);
        }
    }
}
