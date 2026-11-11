//! Parity and error detection calculations using XXH3 over canonical tokens and manifest.

use xxhash_rust::xxh3::Xxh3;

use crate::base62::{self, MAX_U64_BASE62_VAL};
use crate::block::{Block, BlockType, Hook, InlineStr, MAX_BLOCK_LEN, RawBlock};
use crate::error::{BlockError, BufferError, BuilderError};

fn parity_finalize_hook(
    _state: &[u8; 32],
    blocks: &[RawBlock],
    my_idx: usize,
) -> Result<InlineStr, BuilderError> {
    // Count which parity symbol this is (0 for the 1st parity block, 1 for the 2nd, etc.)
    let symbol_idx = blocks[..my_idx]
        .iter()
        .filter(|b| b.kind == BlockType::Parity)
        .count();

    let checksum = compute_xxh3_checksum_with_seed(blocks, symbol_idx);
    let mut buf = [0u8; MAX_BLOCK_LEN];
    let written = base62::encode_u64_into(checksum, &mut buf)?;
    let s = core::str::from_utf8(&buf[..written])
        .map_err(|_| BuilderError::Block(BlockError::InvalidBase62Char(0)))?;
    InlineStr::try_new(s).map_err(BuilderError::Block)
}

pub fn compute_xxh3_checksum(blocks: &[RawBlock]) -> u64 {
    compute_xxh3_checksum_with_seed(blocks, 0)
}

pub fn compute_xxh3_checksum_with_seed(blocks: &[RawBlock], symbol_idx: usize) -> u64 {
    let mut hasher = Xxh3::with_seed(symbol_idx as u64);
    hasher.update(b"seid::parity::v2");
    hasher.update(&(symbol_idx as u64).to_le_bytes());

    for (i, block) in blocks.iter().enumerate() {
        if block.kind != BlockType::Parity {
            hasher.update(&(i as u64).to_le_bytes());
            hasher.update(&[block.kind.as_u8()]);
            hasher.update(block.as_bytes());
            hasher.update(b"::");
        }
    }
    hasher.digest() % (MAX_U64_BASE62_VAL + 1)
}

/// Type 4: Parity / error detection block.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Parity {
    pub value: u64,
    pub is_auto: bool,
}

impl Parity {
    #[inline]
    pub fn new(checksum: u64) -> Self {
        Self {
            value: checksum,
            is_auto: false,
        }
    }

    /// Creates an auto-computing Parity block that calculates the checksum
    /// across all other blocks during `SeidBuilder::build()`. Can be placed anywhere.
    #[inline]
    pub const fn auto() -> Self {
        Self {
            value: 0,
            is_auto: true,
        }
    }

    #[inline]
    pub fn compute(blocks: &[RawBlock]) -> Self {
        Self::new(compute_xxh3_checksum(blocks))
    }

    #[inline]
    pub fn compute_symbol(blocks: &[RawBlock], symbol_idx: usize) -> Self {
        Self::new(compute_xxh3_checksum_with_seed(blocks, symbol_idx))
    }

    #[inline]
    pub fn verify(&self, blocks: &[RawBlock]) -> bool {
        self.verify_symbol(blocks, 0)
    }

    #[inline]
    pub fn verify_symbol(&self, blocks: &[RawBlock], symbol_idx: usize) -> bool {
        compute_xxh3_checksum_with_seed(blocks, symbol_idx) == self.value
    }

    #[inline]
    pub fn value(&self) -> u64 {
        self.value
    }
}

impl Block for Parity {
    const TYPE: BlockType = BlockType::Parity;

    #[inline]
    fn encode(&self, dest: &mut [u8]) -> Result<usize, BufferError> {
        base62::encode_u64_into(self.value, dest)
    }

    #[inline]
    fn decode(raw: &str) -> Result<Self, BlockError> {
        let val = base62::decode_u64(raw)?;
        Ok(Self::new(val))
    }

    #[inline]
    fn build_hook(&self) -> Option<Hook> {
        if self.is_auto {
            Some(Hook {
                func: parity_finalize_hook,
                state: [0u8; 32],
            })
        } else {
            None
        }
    }
}
