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
    Auth, Blob, Block, BlockType, Cipher, FromBlock, InlineStr, Inst, MAX_BLOCKS, Parity, Rand,
    RawBlock, Time, Tpl, Unpack,
};
pub use builder::{IdBuilder, SeidBuilder};
pub use error::{
    BlockError, BufferError, BuilderError, CryptoError, ExtractError, ManifestError, ParityError,
    ParseError,
};
pub use manifest::Manifest;
pub use seid::{EncodedSeid, Id, MAX_ENCODED_LEN, Seid};
