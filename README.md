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
3. **Template-Free Self-Description**: Any parser can inspect the structural layout without consulting an external schema or database.
4. **Stack-Only Guarantee (`no_std`)**: The parsed `Seid` object is fully stack-allocated. No dynamic heap allocation is required to parse, validate, or read fields.
5. **Forward-Compatible Tags**: Unknown future block types (tags `8..=14` and `Escape`) are preserved as opaque `RawBlock`s, so older services can re-encode the original ID losslessly.
6. **Explicit Execution**: Cryptographic verification, parity checks, and decryption are never implicit during parse — call them on demand.

---

## Block Types

Each functional block is constrained to 2–8 Base62 characters and maps to an explicit capability:

| Code | Type | Description |
| :---: | :--- | :--- |
| `0` | `TplText` | Static template text defining resource or entity domain (`usr`, `order`). |
| `1` | `InstText` | Contextual runtime variable (region, cluster, shard, tenant). |
| `2` | `Time` | Chronologically sortable timestamp integer (Base62 sorts lexicographically within a width tier). |
| `3` | `Rand` | Monotonic or CSPRNG entropy for collision prevention (up to ~48 bits/block). |
| `4` | `Parity` | XXH3 checksum symbol protecting functional blocks from typos. |
| `5` | `Auth` | BLAKE3 keyed origin proof / verification tag. |
| `6` | `Blob` | Arbitrary raw binary payload (up to 5 bytes/block). |
| `7` | `Cipher` | Encrypted binary payload derived via BLAKE3 keystream. |
| `8..=14` | `Unknown` | Opaque forward-compat tags reserved for future official built-ins. |
| `15` | `Escape` | Gate for future multi-nibble extended official types. |

There is intentionally **no custom/user-defined type API**. Application-specific payloads should use `Blob` (or `Cipher`), while unknown tags stay opaque for forward compatibility.

---

## Installation

Add SEID to your `Cargo.toml`:

```toml
[dependencies]
seid = "1.0"
```

### Feature Flags

| Feature | Default | Description |
| :--- | :---: | :--- |
| `std` | ✅ | Standard library error formatting and CLI binary. |
| `alloc` | ✅ | Heap serialization (`id.encode() -> String`). |
| `sys-clock`| ✅ | Enables `builder.time_now()` via `std::time::SystemTime`. |
| `sys-rand` | ✅ | Enables `rand_sys()` using OS entropy via `getrandom`. |
| `serde` | ❌ | Zero-allocation `Serialize` / `Deserialize` for `Seid`. |

---

## Usage

### 1. Generating an Identifier

```rust
use seid::Seid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let id = Seid::builder()
        .template("usr")?     // Entity prefix
        .instance("eu1")?     // Instance / tenant variable
        .time_now()?          // Sortable timestamp
        .rand_fast()?         // Nonce entropy
        .parity()?            // XXH3 error-detection checksum
        .build()?;

    // Format directly (zero heap allocation via Display)
    println!("Generated SEID: {id}");

    // Or encode into a heap String (requires feature = "alloc")
    let raw_string: String = id.encode();
    println!("String: {raw_string}");

    Ok(())
}
```

### 2. Zero-Alloc Parsing & Field Access

```rust
use seid::{Inst, Seid, Time, Tpl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = "usr::eu1::01JC8F::9xK2mA::0b2K";
    let id = Seid::parse(raw)?;

    let entity: Tpl = id.get_as(0)?;
    let tenant: Inst = id.get_as(1)?;
    let timestamp: Time = id.get_as(2)?;

    println!(
        "Entity: {}, Tenant: {}, Timestamp: {}",
        entity.as_str(),
        tenant.as_str(),
        timestamp.value()
    );

    if let Some(ts) = id.timestamp() {
        println!("Combined timestamp: {ts}");
    }

    Ok(())
}
```

### 3. Schema Matching & Extraction

```rust
use seid::{BlockType, Inst, Seid, Time, Tpl};

fn route_identifier(id: &Seid) -> Result<(), seid::ExtractError> {
    const USER_SCHEMA: &[BlockType] = &[
        BlockType::TplText,
        BlockType::InstText,
        BlockType::Time,
    ];

    if id.matches_schema(USER_SCHEMA) {
        let (tpl, tenant, ts): (Tpl, Inst, Time) = id.unpack()?;
        if tpl.as_str() == "usr" {
            println!("User in tenant {} at {}", tenant.as_str(), ts.value());
        }
    }

    Ok(())
}
```

### 4. Explicit Verification & Decryption

No verification happens during parsing. Invoke checks on demand:

```rust
# use seid::Seid;
# fn example(id: &Seid) -> Result<(), Box<dyn std::error::Error>> {
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
let _bytes_written = id.decrypt(&secret_key, &mut plaintext)?;
# Ok(())
# }
```

---

## Token-Level Canonical Hashing

**Parity** and **Auth** compute hashes over canonical Base62 token bytes (plus type tags), not Rust struct layouts.

If a newer client mints an ID with a future block type and an older client parses it:

* The older client keeps the block as `RawBlock { kind: Unknown(tag), token }`.
* `check_parity()` / `verify_signature()` hash the same Base62 bytes.
* Parity and authentication remain stable across versions.

---

## CLI Utility

The `seid` crate includes a command-line tool (requires `std`):

```bash
# Mint a quick sample identifier
$ seid mint usr

# Inspect structural layout
$ seid inspect usr::eu1::01JC8F::9xK2mA::07gR
```

---

## License

This project is licensed under the terms of the GNU General Public License v3.0 or later ([GPL-3.0-or-later](LICENSE)).
