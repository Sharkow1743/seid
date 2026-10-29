//! Chronological timestamp block operations.

use crate::base62::{self, MAX_U64_BASE62_VAL};
use crate::block::{Block, BlockType};
use crate::error::{BlockError, BufferError};

pub const DEFAULT_CUSTOM_EPOCH_MS: u64 = 1_704_067_200_000;

/// Type 2: Sortable timestamp integer block.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Time(pub u64);

impl Time {
    #[inline]
    pub fn new(timestamp: u64) -> Result<Self, BlockError> {
        if timestamp > MAX_U64_BASE62_VAL {
            return Err(BlockError::InvalidLength(timestamp as usize));
        }
        Ok(Self(timestamp))
    }

    #[inline]
    pub fn value(&self) -> u64 {
        self.0
    }

    #[cfg(feature = "sys-clock")]
    pub fn now() -> Result<Self, BlockError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BlockError::InvalidLength(0))?
            .as_millis() as u64;

        let delta = now_ms.saturating_sub(DEFAULT_CUSTOM_EPOCH_MS);
        Self::new(delta)
    }
}

impl Block for Time {
    const TYPE: BlockType = BlockType::Time;

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
