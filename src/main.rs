//! SEID command-line utility.

use std::env;
use std::process::exit;

use seid::block::time::TimePrecision;
use seid::{Auth, Blob, BlockType, Cipher, Inst, Parity, Rand, RawBlock, Seid, Time, Tpl};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        exit(1);
    }

    match args[1].as_str() {
        "-h" | "--help" | "help" => {
            print_usage();
        }
        "gen" => {
            if args.len() < 3 {
                eprintln!("Error: Missing template argument for 'gen'");
                eprintln!("Usage: seid gen <template...>");
                eprintln!("Example: seid gen TIME RAND STXT:usr TEXT:eu1");
                exit(1);
            }
            handle_gen(&args[2..]);
        }
        "inspect" | "parse" => {
            if args.len() < 3 {
                eprintln!("Error: Missing ID argument");
                eprintln!("Usage: seid inspect <id>");
                exit(1);
            }
            handle_inspect(&args[2]);
        }
        "mint" => {
            handle_mint(&args[2..]);
        }
        raw_id => {
            handle_inspect(raw_id);
        }
    }
}

fn print_usage() {
    println!("SEID — Structured Extensible Identifier CLI\n");
    println!("USAGE:");
    println!("  seid <id>                  Inspect and analyze an identifier");
    println!("  seid parse <id>            Inspect identifier (explicit alias)");
    println!("  seid gen <template...>     Generate identifier from template");
    println!("  seid mint [template_text]  Mint a sample default identifier\n");
    println!("PRECISION & LIMIT SCALING TIME TEMPLATE:");
    println!("  TIME             Scales both precision and year limit with each instance:");
    println!("                   - 1st TIME: Date + Time-of-Day in seconds (~1s, up to Yr 3,796)");
    println!("                   - 2nd TIME: Subsecond Milliseconds (~1ms, up to Yr 3.79M)");
    println!("                   - 3rd TIME: Subsecond Microseconds (~1µs, up to Yr 3.79B)");
    println!("                   - 4th TIME: Subsecond Nanoseconds (~1ns, up to Yr 3.79 Trillion)");
    println!("  TIME:<u64>       Explicit raw integer value for this time block");
    println!("  RAND             Random entropy block (~47.6 bits)");
    println!("  RAND:<number>    Explicit random integer (u64)");
    println!("  STXT:<text>      Static template text block (Type 0, e.g. 'usr')");
    println!("  TEXT:<text>      Instance / text block (Type 1, e.g. 'eu1')");
    println!("  TPL:<text>       Static template text block (alias for STXT)");
    println!("  INST:<text>      Static instance text block (alias for TEXT)");
    println!("  PARITY           Auto-computing XXH3 error detection block");
    println!("  BLOB:<hex>       Binary payload block (up to 5 bytes hex)\n");
    println!("EXAMPLES:");
    println!("  seid gen TIME RAND STXT:usr TEXT:eu1");
    println!("  seid gen TIME TIME RAND STXT:order PARITY");
    println!("  seid gen TIME TIME TIME RAND STXT:event");
}

fn handle_gen(template_args: &[String]) {
    let tokens: Vec<&str> = template_args
        .iter()
        .flat_map(|arg| arg.split_whitespace())
        .collect();

    if tokens.is_empty() {
        eprintln!("Error: Template is empty");
        exit(1);
    }

    let mut builder = Seid::builder();
    let mut time_instance_count = 0;

    for token in tokens {
        let upper = token.to_ascii_uppercase();

        if upper == "TIME" {
            let block = Time::now_instance(time_instance_count).unwrap_or_else(|e| {
                eprintln!("Error creating TIME block: {}", e);
                exit(1);
            });
            time_instance_count += 1;
            builder = builder.block(block).unwrap_or_else(|e| {
                eprintln!("Builder error: {}", e);
                exit(1);
            });
        } else if let Some(val_str) = upper.strip_prefix("TIME:") {
            let val = val_str.parse::<u64>().unwrap_or_else(|_| {
                eprintln!("Error in '{}': invalid integer for TIME", token);
                exit(1);
            });
            let block = Time::new(val).unwrap_or_else(|e| {
                eprintln!("Error creating TIME block: {}", e);
                exit(1);
            });
            time_instance_count += 1;
            builder = builder.block(block).unwrap_or_else(|e| {
                eprintln!("Builder error: {}", e);
                exit(1);
            });
        } else if upper == "RAND" {
            builder = builder.block(Rand::fast()).unwrap_or_else(|e| {
                eprintln!("Builder error: {}", e);
                exit(1);
            });
        } else if let Some(val_str) = upper.strip_prefix("RAND:") {
            let val = val_str.parse::<u64>().unwrap_or_else(|_| {
                eprintln!("Error in '{}': invalid integer for RAND", token);
                exit(1);
            });
            let block = Rand::new(val).unwrap_or_else(|e| {
                eprintln!("Error creating RAND block: {}", e);
                exit(1);
            });
            builder = builder.block(block).unwrap_or_else(|e| {
                eprintln!("Builder error: {}", e);
                exit(1);
            });
        } else if upper == "PARITY" {
            builder = builder.block(Parity::auto()).unwrap_or_else(|e| {
                eprintln!("Builder error: {}", e);
                exit(1);
            });
        } else if let Some((prefix, val)) = token.split_once(':') {
            match prefix.to_ascii_uppercase().as_str() {
                "STXT" | "TPL" => {
                    let block = Tpl::new(val).unwrap_or_else(|e| {
                        eprintln!("Error creating block '{}': {}", token, e);
                        exit(1);
                    });
                    builder = builder.block(block).unwrap_or_else(|e| {
                        eprintln!("Builder error: {}", e);
                        exit(1);
                    });
                }
                "TEXT" | "INST" => {
                    let block = Inst::new(val).unwrap_or_else(|e| {
                        eprintln!("Error creating block '{}': {}", token, e);
                        exit(1);
                    });
                    builder = builder.block(block).unwrap_or_else(|e| {
                        eprintln!("Builder error: {}", e);
                        exit(1);
                    });
                }
                "BLOB" => {
                    let raw_bytes = hex_decode(val).unwrap_or_else(|e| {
                        eprintln!("Error in block '{}': {}", token, e);
                        exit(1);
                    });
                    let block = Blob::from_slice(&raw_bytes).unwrap_or_else(|e| {
                        eprintln!("Error creating BLOB block: {}", e);
                        exit(1);
                    });
                    builder = builder.block(block).unwrap_or_else(|e| {
                        eprintln!("Builder error: {}", e);
                        exit(1);
                    });
                }
                other => {
                    eprintln!("Error: Unknown block prefix '{}' in '{}'", other, token);
                    print_supported_tokens();
                    exit(1);
                }
            }
        } else {
            eprintln!("Error: Unrecognized template token '{}'", token);
            print_supported_tokens();
            exit(1);
        }
    }

    match builder.build() {
        Ok(id) => println!("{}", id),
        Err(e) => {
            eprintln!("Failed to build SEID: {}", e);
            exit(1);
        }
    }
}

fn print_supported_tokens() {
    eprintln!("\nSupported template tokens:");
    eprintln!("  TIME (Scales precision & range: Date+TOD -> +Millis -> +Micros -> +Nanos)");
    eprintln!("  TIME:<u64>");
    eprintln!("  RAND, RAND:<u64>");
    eprintln!("  STXT:<text> (Static template text, Type 0)");
    eprintln!("  TEXT:<text> (Static instance text, Type 7)");
    eprintln!("  TPL:<text>, INST:<text>");
    eprintln!("  PARITY");
    eprintln!("  BLOB:<hex>");
}

fn hex_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 {
        return Err("hex string must have an even length");
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte =
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hexadecimal character")?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn handle_mint(args: &[String]) {
    let tpl_name = if !args.is_empty() { &args[0] } else { "usr" };

    let id = Seid::builder()
        .block(Tpl::new(tpl_name).expect("Valid template"))
        .expect("Add block")
        .block(Inst::new("eu1").expect("Valid instance"))
        .expect("Add block")
        .time_now()
        .expect("Add date+time block")
        .time_now()
        .expect("Add ms block")
        .block(Rand::fast())
        .expect("Add block")
        .block(Parity::auto())
        .expect("Add parity")
        .build()
        .expect("Build SEID");

    println!("{}", id);
}

fn handle_inspect(raw: &str) {
    match Seid::parse(raw) {
        Ok(id) => print_detailed_id(&id, raw),
        Err(e) => {
            eprintln!("Parse error: {}", e);
            exit(1);
        }
    }
}

fn print_detailed_id(id: &Seid, raw_input: &str) {
    let manifest = id.manifest();
    let blocks = id.blocks();

    println!("SEID Identifier Analysis");
    println!("────────────────────────────────────────────────────────────");
    println!("Input:           {}", raw_input);
    println!("Canonical:       {}", id.to_encoded());
    println!("URL-Safe:        {}", id.to_url_encoded());
    println!(
        "Length:          {} chars (canonical), {} chars (url-safe)",
        id.encoded_len(),
        id.to_url_encoded().len()
    );
    println!(
        "Block Count:     {} functional block(s) + 1 manifest block",
        id.block_count()
    );

    println!("\nManifest Metadata");
    println!("────────────────────────────────────────────────────────────");
    let mut manifest_token = [0u8; 8];
    let m_len = manifest.encode_into(&mut manifest_token).unwrap_or(0);
    let m_str = std::str::from_utf8(&manifest_token[..m_len]).unwrap_or("??");
    let m_val = manifest.to_u64();
    println!("Token:           {}", m_str);
    println!("Bitfield (u64):  {} ({:#018x})", m_val, m_val);
    print!("Schema:          [");
    for (i, kind) in manifest.block_types().iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("{}", kind);
    }
    println!("]");

    if let Some(dt) = id.datetime() {
        println!("\nTimestamp Analysis (Chained Precision & Limit Scaling)");
        println!("────────────────────────────────────────────────────────────");
        println!(
            "Calendar Date:   {:04}-{:02}-{:02} (Day {} of year {})",
            dt.year, dt.month, dt.day, dt.day_of_year, dt.year
        );
        match dt.precision {
            TimePrecision::Seconds => {
                println!(
                    "Precision:       Second level (1 Time block, Date + TOD, up to Year 3,796)"
                );
                println!(
                    "Formatted:       {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                    dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second
                );
            }
            TimePrecision::Milliseconds => {
                println!("Precision:       Millisecond level (2 Time blocks, up to Year 3.79M)");
                println!(
                    "Formatted:       {:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} UTC",
                    dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.subsecond_parts[0]
                );
            }
            TimePrecision::Microseconds => {
                println!("Precision:       Microsecond level (3 Time blocks, up to Year 3.79B)");
                println!(
                    "Formatted:       {:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}_{:03} UTC",
                    dt.year,
                    dt.month,
                    dt.day,
                    dt.hour,
                    dt.minute,
                    dt.second,
                    dt.subsecond_parts[0],
                    dt.subsecond_parts[1]
                );
            }
            TimePrecision::Nanoseconds => {
                println!(
                    "Precision:       Nanosecond level (4 Time blocks, up to Year 3.79 Trillion)"
                );
                println!(
                    "Formatted:       {:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}_{:03}_{:03} UTC",
                    dt.year,
                    dt.month,
                    dt.day,
                    dt.hour,
                    dt.minute,
                    dt.second,
                    dt.subsecond_parts[0],
                    dt.subsecond_parts[1],
                    dt.subsecond_parts[2]
                );
            }
            TimePrecision::Picoseconds => {
                println!(
                    "Precision:       Picosecond level (5 Time blocks, up to Year 3.79 Quadrillion)"
                );
            }
            TimePrecision::Femtoseconds => {
                println!(
                    "Precision:       Femtosecond level (6 Time blocks, up to Year 3.79 Quintillion)"
                );
            }
            TimePrecision::Attoseconds => {
                println!("Precision:       Attosecond level (7+ Time blocks, Cosmic scale)");
            }
        }
    }

    if id.contains_type(BlockType::Parity) {
        println!("\nIntegrity & Error Detection");
        println!("────────────────────────────────────────────────────────────");
        match id.check_parity() {
            Ok(true) => {
                println!("Parity Status:   VALID (checksum matched)");
            }
            Ok(false) => {
                println!("Parity Status:   CORRUPTED / MISMATCH (data modified)");
            }
            Err(e) => {
                println!("Parity Status:   CHECK FAILED ({})", e);
            }
        }

        let mut sym_idx = 0;
        for (i, b) in blocks.iter().enumerate() {
            if b.kind() == BlockType::Parity {
                if let Ok(p) = b.decode::<Parity>() {
                    let expected =
                        seid::block::parity::compute_xxh3_checksum_with_seed(blocks, sym_idx);
                    let ok = p.value == expected;
                    println!(
                        "  Symbol #{}:      block [{}], stored: {} ({:#x}), computed: {} ({:#x}) [{}]",
                        sym_idx,
                        i,
                        p.value,
                        p.value,
                        expected,
                        expected,
                        if ok { "OK" } else { "MISMATCH" }
                    );
                    sym_idx += 1;
                }
            }
        }
    }

    let auth_blocks: Vec<(usize, &RawBlock)> = blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| b.kind() == BlockType::Auth)
        .collect();

    if !auth_blocks.is_empty() {
        println!("\nCryptographic Authentication");
        println!("────────────────────────────────────────────────────────────");
        for (idx, b) in auth_blocks {
            if let Ok(auth) = b.decode::<Auth>() {
                println!(
                    "  Block [{}]:      len: {} bytes, signed: {}, tag: 0x{}",
                    idx,
                    auth.len,
                    !auth.is_placeholder(),
                    hex_encode(auth.as_bytes())
                );
            }
        }
    }

    let cipher_blocks: Vec<(usize, &RawBlock)> = blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| b.kind() == BlockType::Cipher)
        .collect();

    if !cipher_blocks.is_empty() {
        println!("\nEncrypted Payloads (Cipher)");
        println!("────────────────────────────────────────────────────────────");
        for (idx, b) in cipher_blocks {
            if let Ok(cipher) = b.decode::<Cipher>() {
                println!(
                    "  Block [{}]:      len: {} bytes, ciphertext: 0x{}",
                    idx,
                    cipher.len,
                    hex_encode(cipher.as_bytes())
                );
            }
        }
    }

    println!("\nBlocks Breakdown");
    println!("────────────────────────────────────────────────────────────");
    println!("  Idx  Type       Token       Width  Decoded Content");

    let mut time_instance = 0;
    for (i, block) in blocks.iter().enumerate() {
        let details = format_block_details(block, &mut time_instance);
        let kind_str = block.kind().to_string();
        println!(
            "  [{}]  {:<10} {:<11} {:<6} {}",
            i,
            kind_str,
            block.as_str(),
            format!("{} ch", block.encoded_len()),
            details
        );
    }

    println!(
        "  [M]  {:<10} {:<11} {:<6} declared: {}, types: [{}]",
        "Manifest",
        m_str,
        format!("{} ch", m_len),
        manifest.block_count(),
        manifest
            .block_types()
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn format_block_details(block: &RawBlock, time_instance: &mut usize) -> String {
    match block.kind() {
        BlockType::TplText => {
            if let Ok(tpl) = block.decode::<Tpl>() {
                format!("template: \"{}\"", tpl.as_str())
            } else {
                format!("\"{}\"", block.as_str())
            }
        }
        BlockType::InstText => {
            if let Ok(inst) = block.decode::<Inst>() {
                format!("instance: \"{}\"", inst.as_str())
            } else {
                format!("\"{}\"", block.as_str())
            }
        }
        BlockType::Time => {
            if let Ok(time) = block.decode::<Time>() {
                let inst = *time_instance;
                *time_instance += 1;
                match inst {
                    0 => {
                        let sec_of_year = time.value() % seid::block::time::SECS_PER_CANONICAL_YEAR;
                        let day_idx = sec_of_year / seid::block::time::SECS_PER_DAY;
                        let sec_of_day = (sec_of_year % seid::block::time::SECS_PER_DAY) as u32;
                        let doy = ((day_idx % seid::block::time::DAYS_PER_YEAR_MAX) + 1) as u16;
                        let y_offset = time.value() / seid::block::time::SECS_PER_CANONICAL_YEAR;
                        let full_y = seid::block::time::YEAR_BASE + y_offset;
                        let (_, m, d) = seid::block::time::doy_to_ymd(full_y, doy);
                        let h = sec_of_day / 3600;
                        let min = (sec_of_day % 3600) / 60;
                        let s = sec_of_day % 60;
                        format!(
                            "Date+TOD: {:04}-{:02}-{:02} {:02}:{:02}:{:02} (raw: {})",
                            full_y,
                            m,
                            d,
                            h,
                            min,
                            s,
                            time.value()
                        )
                    }
                    1 => {
                        let ms = (time.value() % 1000) as u16;
                        let y_overflow = time.value() / 1000;
                        if y_overflow > 0 {
                            format!("Subsec: {} ms (+{} yr-tier)", ms, y_overflow)
                        } else {
                            format!("Subsec: {} ms", ms)
                        }
                    }
                    2 => {
                        let us = (time.value() % 1000) as u16;
                        let y_overflow = time.value() / 1000;
                        if y_overflow > 0 {
                            format!("Subsec: {} µs (+{} yr-tier)", us, y_overflow)
                        } else {
                            format!("Subsec: {} µs", us)
                        }
                    }
                    3 => {
                        let ns = (time.value() % 1000) as u16;
                        let y_overflow = time.value() / 1000;
                        if y_overflow > 0 {
                            format!("Subsec: {} ns (+{} yr-tier)", ns, y_overflow)
                        } else {
                            format!("Subsec: {} ns", ns)
                        }
                    }
                    _ => format!("Time block #{} (raw: {})", inst, time.value()),
                }
            } else {
                "invalid time block".to_string()
            }
        }
        BlockType::Rand => {
            if let Ok(rand) = block.decode::<Rand>() {
                format!("val: {} ({:#x})", format_num(rand.0), rand.0)
            } else {
                "invalid rand block".to_string()
            }
        }
        BlockType::Parity => {
            if let Ok(parity) = block.decode::<Parity>() {
                format!(
                    "checksum: {} ({:#x})",
                    format_num(parity.value),
                    parity.value
                )
            } else {
                "invalid parity block".to_string()
            }
        }
        BlockType::Auth => {
            if let Ok(auth) = block.decode::<Auth>() {
                format!(
                    "tag: 0x{} (signed: {})",
                    hex_encode(auth.as_bytes()),
                    !auth.is_placeholder()
                )
            } else {
                "invalid auth block".to_string()
            }
        }
        BlockType::Blob => {
            if let Ok(blob) = block.decode::<Blob>() {
                let slice = blob.as_bytes();
                if let Ok(s) = std::str::from_utf8(slice) {
                    if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                        return format!("bytes: 0x{} (\"{}\")", hex_encode(slice), s);
                    }
                }
                format!("bytes: 0x{} ({} B)", hex_encode(slice), slice.len())
            } else {
                "invalid blob block".to_string()
            }
        }
        BlockType::Cipher => {
            if let Ok(cipher) = block.decode::<Cipher>() {
                format!(
                    "cipher: 0x{} ({} B)",
                    hex_encode(cipher.as_bytes()),
                    cipher.len
                )
            } else {
                "invalid cipher block".to_string()
            }
        }
        BlockType::Unknown(tag) => format!("unknown tag {}", tag),
        BlockType::Escape => "escape tag".to_string(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn format_num(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let len = s.len();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result
}
