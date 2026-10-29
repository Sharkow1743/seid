//! Text block structs for template and instance scoping.

use crate::block::{Block, BlockType, InlineStr};
use crate::error::{BlockError, BufferError};

/// Type 0: Static template text block (hierarchy, domain, entity type).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tpl(pub InlineStr);

impl Tpl {
    #[inline]
    pub fn new(s: &str) -> Result<Self, BlockError> {
        Ok(Self(InlineStr::try_new(s)?))
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Block for Tpl {
    const TYPE: BlockType = BlockType::TplText;

    #[inline]
    fn encode(&self, dest: &mut [u8]) -> Result<usize, BufferError> {
        let len = self.0.len();
        if dest.len() < len {
            return Err(BufferError::TooSmall {
                required: len,
                provided: dest.len(),
            });
        }
        dest[..len].copy_from_slice(self.0.as_bytes());
        Ok(len)
    }

    #[inline]
    fn decode(raw: &str) -> Result<Self, BlockError> {
        Self::new(raw)
    }
}

impl core::ops::Deref for Tpl {
    type Target = str;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

/// Type 7: Static instance text block (region, cluster, tenant, shard).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Inst(pub InlineStr);

impl Inst {
    #[inline]
    pub fn new(s: &str) -> Result<Self, BlockError> {
        Ok(Self(InlineStr::try_new(s)?))
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Block for Inst {
    const TYPE: BlockType = BlockType::InstText;

    #[inline]
    fn encode(&self, dest: &mut [u8]) -> Result<usize, BufferError> {
        let len = self.0.len();
        if dest.len() < len {
            return Err(BufferError::TooSmall {
                required: len,
                provided: dest.len(),
            });
        }
        dest[..len].copy_from_slice(self.0.as_bytes());
        Ok(len)
    }

    #[inline]
    fn decode(raw: &str) -> Result<Self, BlockError> {
        Self::new(raw)
    }
}

impl core::ops::Deref for Inst {
    type Target = str;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}
