//! Raw binary payload block operations.

use crate::base62;
use crate::block::{Block, BlockType, MAX_BLOCK_BYTES};
use crate::error::{BlockError, BufferError};

/// Type 6: Raw arbitrary binary payload block (up to 5 bytes within numerical bounds).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Blob {
    pub bytes: [u8; MAX_BLOCK_BYTES],
    pub len: u8,
}

impl Blob {
    pub fn from_slice(slice: &[u8]) -> Result<Self, BlockError> {
        if slice.is_empty() || slice.len() > MAX_BLOCK_BYTES {
            return Err(BlockError::PayloadTooLarge(slice.len()));
        }

        let mut val: u64 = 0;
        for &b in slice {
            val = (val << 8) | (b as u64);
        }
        if val > base62::MAX_U64_BASE62_VAL {
            return Err(BlockError::PayloadTooLarge(slice.len()));
        }

        let mut bytes = [0u8; MAX_BLOCK_BYTES];
        bytes[..slice.len()].copy_from_slice(slice);
        Ok(Self {
            bytes,
            len: slice.len() as u8,
        })
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl Block for Blob {
    const TYPE: BlockType = BlockType::Blob;

    #[inline]
    fn encode(&self, dest: &mut [u8]) -> Result<usize, BufferError> {
        base62::encode_bytes_into(self.as_bytes(), dest)
    }

    #[inline]
    fn decode(raw: &str) -> Result<Self, BlockError> {
        let mut bytes = [0u8; MAX_BLOCK_BYTES];
        let len = base62::decode_bytes_into(raw, &mut bytes)?;
        Ok(Self {
            bytes,
            len: len as u8,
        })
    }
}
