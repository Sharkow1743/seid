//! SEID — Structured Extensible Identifier.
//!
//! A universal, stack-allocated, self-describing identifier format for distributed
//! systems. Tokens are Base62 (`[0-9A-Za-z]`), sections are delimited by `::`
//! (or `.` for URL-safe form), and a trailing manifest encodes each block's
//! 4-bit capability tag.
//!
//! # Quick start
//!
//! ```
//! # #[cfg(feature = "sys-clock")]
//! # {
//! use seid::Seid;
//!
//! let id = Seid::builder()
//!     .template("usr")
//!     .unwrap()
//!     .instance("eu1")
//!     .unwrap()
//!     .time_now()
//!     .unwrap()
//!     .rand_fast()
//!     .unwrap()
//!     .parity()
//!     .unwrap()
//!     .build()
//!     .unwrap();
//!
//! let parsed = Seid::parse(id.to_encoded().as_str()).unwrap();
//! assert_eq!(id, parsed);
//! # }
//! ```
//!
//! # `no_std`
//!
//! This crate is `#![no_std]` by default. Enable `alloc` for heap `String`
//! encoding and `std` for the richer default feature set (system clock / RNG).

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod base62;
pub mod block;
pub mod builder;
pub mod error;
pub mod manifest;
pub mod parser;
pub mod seid;

#[cfg(feature = "serde")]
pub mod serde;

pub use block::{
    Auth, Blob, Block, BlockType, Cipher, DateTime, FromBlock, InlineStr, Inst, MAX_BLOCKS, Parity,
    Rand, RawBlock, Time, TimePrecision, Tpl, Unpack,
};
pub use builder::{IdBuilder, SeidBuilder};
pub use error::{
    BlockError, BufferError, BuilderError, CryptoError, ExtractError, ManifestError, ParityError,
    ParseError,
};
pub use manifest::Manifest;
pub use seid::{
    CANONICAL_DELIMITER, DELIMITER, EncodedSeid, Id, MAX_ENCODED_LEN, Seid, URL_DELIMITER,
};
