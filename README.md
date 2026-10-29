
# SEID

[![Crates.io](https://img.shields.io/crates/v/seid.svg)](https://crates.io/crates/seid)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A universal, stack-allocated, self-describing identifier system designed for distributed architectures. 

SEID uses `::` as its section delimiter, enforces strict Base62 alphanumeric purity (`[0-9A-Za-z]`), and packs undisruptive structural metadata into a compact trailing manifest block.

```text
usr::eu1::01JC8F::9xK2mA::0d4F
───  ───  ──────  ──────  ────
 │    │     │       │       └── Trailing Manifest (Capabilities & Layout)
 │    │     │       └────────── Random Entropy Nonce
 │    │     └────────────────── Sortable Epoch Timestamp
 │    └──────────────────────── Instance Variable (e.g. Cluster / Region / Tenant)
 └───────────────────────────── Template Prefix (Entity Type)
```

---

## Key Priorities

1. **Readability & Recognizability**: Every section is 2 to 8 clean Base62 characters separated by `::`. No messy prefixes, hyphens, or punctuation.
2. **Undisruptive Metadata**: Structural metadata is embedded in a single, trailing Base62 manifest block that visually conforms to the rest of the identifier.
3. **Template-Free Self-Description**: Any parser can inspect the structural Abstract Syntax Tree (AST) without consulting an external schema or database.
4. **Stack-Only Guarantee (`no_std`)**: The parsed `Seid` object occupies **136 bytes on the stack**. No dynamic heap allocation is required to parse, validate, or read fields.
5. **Capability System (Forward-Compatible)**: Unknown future block types are parsed as `Block::Unknown`, allowing older services to read known fields and re-encode the original ID losslessly without data corruption.
6. **Explicit Execution**: Parsers and generators perform zero implicit or hidden operations. Cryptographic verification, parity checks, and decryption are strictly explicit.

---

## Block Types

Each functional block is constrained to 2–8 Base62 characters and maps to an explicit capability:

| Code | Type | Description |
| :---: | :--- | :--- |
| `0` | `TplText` | Static template text defining resource or entity domain (`usr`, `order`). |
| `1` | `Rand` | Monotonic or CSPRNG entropy for collision prevention (up to 48 bits/block). |
| `2` | `Time` | Chronologically sortable timestamp integer (Base62 sorts lexicographically). |
| `3` | `Parity` | XXH3 checksum symbol protecting all preceding blocks from typos. |
| `4` | `Auth` | BLAKE3 keyed origin proof / verification tag. |
| `5` | `Blob` | Arbitrary raw binary payload (up to 6 bytes/block). |
| `6` | `Cipher` | Encrypted binary payload derived via BLAKE3 keystream (co-keyed with Auth). |
| `7` | `InstText` | Contextual runtime variable (region, cluster, shard, tenant). |
| `8..15`| `Unknown` | Future capabilities preserved verbatim for forward-compatibility. |

---

## Installation

Add SEID to your `Cargo.toml`:

```toml
[dependencies]
seid = { version = "0.2.0", default-features = false, features = ["alloc"] }
```

### Feature Flags

| Feature | Default | Description |
| :--- | :---: | :--- |
| `std` | ✅ | Enables standard library error handling and CLI utilities. |
| `alloc` | ✅ | Enables heap serialization (`id.encode() -> String`). |
| `sys-clock`| ✅ | Enables `builder.time_now()` via `std::time::SystemTime`. |
| `sys-rand` | ✅ | Enables `rand_sys()` using OS cryptographic entropy via `getrandom`. |
| `serde` | ❌ | Zero-allocation `Serialize` and `Deserialize` implementations. |
| `subtle` | ❌ | Constant-time tag comparison for `Auth` verification. |

---

## Usage

### 1. Generating an Identifier

```rust
use seid::Seid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let id = Seid::builder()
        .template("usr")?            // Entity prefix
        .instance("eu1")?            // Instance / tenant variable
        .time_now()?                 // Sortable timestamp
        .rand_fast()?                // Nonce entropy
        .parity()?                   // XXH3 error-detection checksum
        .build()?;

    // Format directly to stdout (zero heap allocation via Display)
    println!("Generated SEID: {id}");

    // Or encode into a heap String (requires feature = "alloc")
    let raw_string: String = id.encode();
    println!("String: {raw_string}");

    Ok(())
}
```

### 2. Zero-Alloc Parsing & Manual Element Access

```rust
use seid::Seid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = "usr::eu1::01JC8F::9xK2mA::0b2K";
    let id = Seid::parse(raw)?;

    // Zero-cost index operator: id[index]
    let entity = id[0].as_str().unwrap();
    let tenant = id[1].as_str().unwrap();
    let timestamp = id[2].as_u64().unwrap();

    println!("Entity: {entity}, Tenant: {tenant}, Timestamp: {timestamp}");

    // Semantic queries (O(1), zero parsing)
    if let Some(ts) = id.timestamp() {
        println!("Combined timestamp: {ts}");
    }

    Ok(())
}
```

### 3. Compile-Time Pattern Matching with Variable Binding

The `match_seid!` macro expands directly into native Rust slice matching at compile time:

```rust
use seid::{match_seid, Seid};

fn route_identifier(id: &Seid) {
    match_seid!(id, {
        // Matches "usr", binds instance to `tenant`, binds timestamp to `ts`
        [Tpl(t), Inst(tenant), Time(ts), ..] if t == "usr" => {
            println!("User in tenant {tenant} created at {ts}");
        },

        // Matches any order ID with an instance variable
        [Tpl(t), Inst(shard), ..] if t == "ord" => {
            println!("Order on shard {shard}");
        },

        // Matches an ID containing an unknown future block tag
        [.., Unknown(tag, token)] => {
            println!("Forward-compatible block detected (tag={tag}): {token}");
        },

        // Fallback
        _ => {
            println!("Default handler for ID: {id}");
        },
    });
}
```

### 4. Explicit Verification & Decryption

No verification happens silently during parsing. Verification is invoked on demand:

```rust
// 1. Explicit Parity Check (XXH3)
match id.check_parity() {
    Ok(true) => println!("Checksum valid!"),
    Ok(false) => eprintln!("ID corrupted!"),
    Err(e) => eprintln!("Error: {e}"),
}

// 2. Explicit Signature Verification (BLAKE3)
let public_key = [0u8; 32];
if id.verify_signature(&public_key)? {
    println!("Author verified!");
}

// 3. Explicit Decryption (BLAKE3 Stream Cipher)
let secret_key = [0u8; 32];
let mut plaintext = [0u8; 32];
let bytes_written = id.decrypt(&secret_key, &mut plaintext)?;
```

---

## Token-Level Canonical Hashing

To ensure forward-compatibility, **Parity** and **Auth** blocks compute hashes over the canonical Base62 token bytes rather than internal Rust struct representations.

If a new client mints an ID with a future block type and an older client parses it:
* The older client stores the block as `Block::Unknown { tag, token }`.
* When the older client calls `check_parity()` or `verify_signature()`, it hashes the exact same Base62 token bytes.
* **Parity and authentication never break across versions.**

---

## CLI Utility

The `seid` crate includes a command-line tool:

```bash
# Mint a quick sample identifier
$ seid mint usr
usr::eu1::01JC8F::9xK2mA::07gR

# Inspect structural AST
$ seid inspect usr::eu1::01JC8F::9xK2mA::07gR
Identifier: usr::eu1::01JC8F::9xK2mA::07gR
Blocks (4):
  [0] TplText  : "usr"
  [1] InstText : "eu1"
  [2] Time     : 1729837421
  [3] Rand     : 0x002a4f918c21
  [4] Parity   : 0x0019b84a912e
Matched user ID under tenant: eu1
```

---

## License

This project is licensed under the terms of the GNU General Public License v3.0 or later ([GPL-3.0-or-later](LICENSE)).
