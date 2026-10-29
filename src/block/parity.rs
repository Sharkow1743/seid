//! Parity and error detection calculations using XXH3 over canonical tokens.

use xxhash_rust::xxh3::Xxh3;

use crate::base62::{self, MAX_U64_BASE62_VAL};
use crate::block::{Block, BlockType, RawBlock};
use crate::error::{BlockError, BufferError};

pub fn compute_xxh3_checksum(blocks: &[RawBlock]) -> u64 {
    let mut hasher = Xxh3::new();
    for block in blocks {
        hasher.update(block.as_bytes());
        hasher.update(b"::");
    }
    hasher.digest() % (MAX_U64_BASE62_VAL + 1)
}

/// Type 3: Parity / error detection block.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Parity(pub u64);

impl Parity {
    #[inline]
    pub fn new(checksum: u64) -> Self {
        Self(checksum)
    }

    #[inline]
    pub fn compute(preceding_blocks: &[RawBlock]) -> Self {
        Self(compute_xxh3_checksum(preceding_blocks))
    }

    #[inline]
    pub fn verify(&self, preceding_blocks: &[RawBlock]) -> bool {
        compute_xxh3_checksum(preceding_blocks) == self.0
    }

    #[inline]
    pub fn value(&self) -> u64 {
        self.0
    }
}

impl Block for Parity {
    const TYPE: BlockType = BlockType::Parity;

    #[inline]
    fn encode(&self, dest: &mut [u8]) -> Result<usize, BufferError> {
        base62::encode_u64_into(self.0, dest)
    }

    #[inline]
    fn decode(raw: &str) -> Result<Self, BlockError> {
        let val = base62::decode_u64(raw)?;
        Ok(Self(val))
    }
}
