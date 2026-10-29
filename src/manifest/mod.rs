//! Trailing manifest metadata encoding and decoding.

pub mod types;
pub use types::*;

use core::fmt;
use core::str;

use crate::base62;
use crate::error::{BufferError, ManifestError};

/// Decoded representation of the trailing manifest metadata.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Manifest {
    pub(crate) block_count: u8,
    pub(crate) types: [BlockType; MAX_BLOCKS],
}

impl Manifest {
    #[inline]
    pub const fn new(block_count: u8, types: [BlockType; MAX_BLOCKS]) -> Self {
        debug_assert!(block_count >= 1 && block_count <= MAX_BLOCKS as u8);
        Self { block_count, types }
    }

    #[inline]
    pub const fn block_count(&self) -> u8 {
        self.block_count
    }

    #[inline]
    pub fn block_type(&self, index: usize) -> Option<BlockType> {
        if index < self.block_count as usize {
            Some(self.types[index])
        } else {
            None
        }
    }

    #[inline]
    pub fn block_types(&self) -> &[BlockType] {
        &self.types[..self.block_count as usize]
    }

    #[inline]
    pub fn contains(&self, target: BlockType) -> bool {
        let count = self.block_count as usize;
        let mut i = 0;
        while i < count {
            if self.types[i] == target {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Packs the block count and 4-bit capability tags into a `u64`.
    pub fn to_u64(&self) -> u64 {
        let count = self.block_count as usize;
        let mut val = (self.block_count as u64) & 0x0F;

        let mut i = 0;
        while i < count {
            let shift = 4 + (i * 4);
            val |= ((self.types[i].as_u8() as u64) & 0x0F) << shift;
            i += 1;
        }

        val
    }

    /// Unpacks a manifest from a native `u64` bitfield.
    pub fn from_u64(val: u64) -> Result<Self, ManifestError> {
        let block_count = (val & 0x0F) as u8;
        if block_count == 0 || block_count > MAX_BLOCKS as u8 {
            return Err(ManifestError::InvalidBlockCount {
                declared: block_count,
                max: MAX_BLOCKS as u8,
            });
        }

        let mut types = [BlockType::TplText; MAX_BLOCKS];
        let count = block_count as usize;
        let mut i = 0;

        while i < count {
            let shift = 4 + (i * 4);
            let raw_type = ((val >> shift) & 0x0F) as u8;
            types[i] = BlockType::from_u8(raw_type);
            i += 1;
        }

        let total_bits_used = 4 + (count * 4);
        if total_bits_used < 64 && (val >> total_bits_used) != 0 {
            return Err(ManifestError::TruncatedBitfield);
        }

        Ok(Self { block_count, types })
    }

    pub fn decode(raw: &str) -> Result<Self, ManifestError> {
        let len = raw.len();
        if len < MIN_BLOCK_LEN || len > MAX_BLOCK_LEN {
            return Err(ManifestError::Base62(
                crate::error::Base62Error::InvalidChar(0),
            ));
        }

        let val = base62::decode_u64(raw).map_err(ManifestError::Base62)?;
        Self::from_u64(val)
    }

    pub fn encoded_len(&self) -> usize {
        let val = self.to_u64();
        let raw_len = base62::encoded_u64_len(val);
        if raw_len < MIN_BLOCK_LEN {
            MIN_BLOCK_LEN
        } else {
            raw_len
        }
    }

    pub fn encode_into(&self, dest: &mut [u8]) -> Result<usize, BufferError> {
        let needed = self.encoded_len();
        if dest.len() < needed {
            return Err(BufferError::TooSmall {
                required: needed,
                provided: dest.len(),
            });
        }

        let val = self.to_u64();
        let raw_len = base62::encoded_u64_len(val);

        if raw_len < MIN_BLOCK_LEN {
            let padding = MIN_BLOCK_LEN - raw_len;
            for i in 0..padding {
                dest[i] = b'0';
            }
            base62::encode_u64_into(val, &mut dest[padding..])?;
            Ok(MIN_BLOCK_LEN)
        } else {
            base62::encode_u64_into(val, dest)
        }
    }
}

impl fmt::Display for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; MAX_BLOCK_LEN];
        let written = self.encode_into(&mut buf).map_err(|_| fmt::Error)?;
        let s = unsafe { str::from_utf8_unchecked(&buf[..written]) };
        f.write_str(s)
    }
}
