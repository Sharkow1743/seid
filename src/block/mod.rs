//! Modular block trait, native structs, and raw block token representations.

use crate::error::BuilderError;

pub use crate::manifest::{
    BlockType, ESCAPE_TAG, MAX_BLOCK_BYTES, MAX_BLOCK_LEN, MAX_BLOCKS, MIN_BLOCK_LEN,
};

pub mod blob;
pub mod crypto;
pub mod extract;
pub mod parity;
pub mod rand;
pub mod raw;
pub mod text;
pub mod time;

pub use blob::Blob;
pub use crypto::{Auth, Cipher};
pub use extract::{FromBlock, Unpack};
pub use parity::Parity;
pub use rand::Rand;
pub use raw::{InlineStr, RawBlock};
pub use text::{Inst, Tpl};
pub use time::{DateTime, Time, TimePrecision};

/// Static function pointer signature for build-time finalization hooks.
pub type FinalizeFn =
    fn(state: &[u8; 32], blocks: &[RawBlock], my_idx: usize) -> Result<InlineStr, BuilderError>;

/// Zero-allocation, stack-only build hook container.
#[derive(Copy, Clone)]
pub struct Hook {
    pub func: FinalizeFn,
    pub state: [u8; 32],
}

/// Core trait implemented by all standard block structs.
pub trait Block: Sized {
    /// The unique capability tag of this block.
    const TYPE: BlockType;

    /// Encodes this block into canonical Base62 characters.
    fn encode(&self, dest: &mut [u8]) -> Result<usize, crate::error::BufferError>;

    /// Decodes this block from a Base62 string token.
    fn decode(raw: &str) -> Result<Self, crate::error::BlockError>;

    /// Optional build hook for self-sealing blocks (e.g. `Auth`, `Parity`).
    /// Invoked during `SeidBuilder::build()` across all assembled blocks.
    fn build_hook(&self) -> Option<Hook> {
        None
    }
}
