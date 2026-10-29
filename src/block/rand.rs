//! Random entropy block operations.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::base62::{self, MAX_U64_BASE62_VAL};
use crate::block::{Block, BlockType};
use crate::error::{BlockError, BufferError};

static SEED_COUNTER: AtomicU64 = AtomicU64::new(0x517c_c1b7_2722_0a95);

/// Type 1: Random entropy block (up to 48 bits per block).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Rand(pub u64);

impl Rand {
    #[inline]
    pub fn new(val: u64) -> Result<Self, BlockError> {
        if val > MAX_U64_BASE62_VAL {
            return Err(BlockError::InvalidLength(val as usize));
        }
        Ok(Self(val))
    }

    #[inline]
    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn fast() -> Self {
        let seed = SEED_COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: u64) -> Self {
        let mut rng = fastrand::Rng::with_seed(seed);
        let val = rng.u64(0..=MAX_U64_BASE62_VAL);
        Self(val)
    }

    #[cfg(feature = "sys-rand")]
    pub fn sys() -> Result<Self, getrandom::Error> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf)?;
        let val = u64::from_be_bytes(buf) % (MAX_U64_BASE62_VAL + 1);
        Ok(Self(val))
    }
}

impl Block for Rand {
    const TYPE: BlockType = BlockType::Rand;

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
