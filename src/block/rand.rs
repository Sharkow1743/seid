//! Random entropy block operations.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::base62::{self, MAX_U64_BASE62_VAL};
use crate::block::{Block, BlockType};
use crate::error::{Base62Error, BlockError, BufferError};

static SEED_COUNTER: AtomicU64 = AtomicU64::new(0);

#[inline]
fn init_entropy() -> u64 {
    let ptr_entropy = (&SEED_COUNTER as *const AtomicU64 as usize) as u64;
    let local = 0u64;
    let stack_entropy = (&local as *const u64 as usize) as u64;

    #[cfg(feature = "std")]
    let time_entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    #[cfg(not(feature = "std"))]
    let time_entropy = 0x517c_c1b7_2722_0a95;

    ptr_entropy
        ^ stack_entropy.rotate_left(21)
        ^ time_entropy.rotate_left(42)
        ^ 0x9e37_79b9_7f4a_7c15
}

/// Type 1: Random entropy block (up to 47.6 bits per block).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Rand(pub u64);

impl Rand {
    #[inline]
    pub fn new(val: u64) -> Result<Self, BlockError> {
        if val > MAX_U64_BASE62_VAL {
            return Err(BlockError::Base62(Base62Error::Overflow));
        }
        Ok(Self(val))
    }

    #[inline]
    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn fast() -> Self {
        let current = SEED_COUNTER.load(Ordering::Relaxed);
        if current == 0 {
            let _ = SEED_COUNTER.compare_exchange(
                0,
                init_entropy(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
        let step = SEED_COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
        Self::from_seed(step ^ 0xbf58_476d_1ce4_e5b9)
    }

    pub fn from_seed(seed: u64) -> Self {
        let mut rng = fastrand::Rng::with_seed(seed);
        let val = rng.u64(0..=MAX_U64_BASE62_VAL);
        Self(val)
    }

    #[cfg(feature = "sys-rand")]
    pub fn sys() -> Result<Self, getrandom::Error> {
        let mut buf = [0u8; 8];
        loop {
            getrandom::fill(&mut buf)?;
            let raw = u64::from_be_bytes(buf) & 0x0000_FFFF_FFFF_FFFF;
            if raw <= MAX_U64_BASE62_VAL {
                return Ok(Self(raw));
            }
        }
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
