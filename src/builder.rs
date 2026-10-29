//! Fully block-agnostic identifier builder.

use crate::block::{Block, InlineStr, MAX_BLOCK_LEN, MAX_BLOCKS, RawBlock};
use crate::error::BuilderError;
use crate::seid::Seid;

/// Block-agnostic builder taking any struct implementing [`Block`].
#[derive(Copy, Clone, Debug)]
pub struct SeidBuilder {
    blocks: [RawBlock; MAX_BLOCKS],
    count: usize,
}

pub type IdBuilder = SeidBuilder;

impl SeidBuilder {
    #[inline]
    pub const fn new() -> Self {
        Self {
            blocks: [RawBlock::new(crate::manifest::BlockType::TplText, unsafe {
                InlineStr::from_raw_parts([0; MAX_BLOCK_LEN], 0)
            }); MAX_BLOCKS],
            count: 0,
        }
    }

    #[inline]
    pub fn current_blocks(&self) -> &[RawBlock] {
        &self.blocks[..self.count]
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.count
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Appends any type implementing [`Block`].
    pub fn block<B: Block>(mut self, b: B) -> Result<Self, BuilderError> {
        if self.count >= MAX_BLOCKS {
            return Err(BuilderError::CapacityExceeded(MAX_BLOCKS));
        }

        let mut buf = [0u8; MAX_BLOCK_LEN];
        let written = b.encode(&mut buf)?;
        let s = core::str::from_utf8(&buf[..written])
            .map_err(|_| BuilderError::Block(crate::error::BlockError::InvalidBase62Char(0)))?;

        let token = InlineStr::try_new(s)?;
        self.blocks[self.count] = RawBlock::new(B::TYPE, token);
        self.count += 1;
        Ok(self)
    }

    /// Evaluates a block constructor closure with access to preceding blocks.
    pub fn block_with<B: Block, F>(self, f: F) -> Result<Self, BuilderError>
    where
        F: FnOnce(&[RawBlock]) -> Result<B, BuilderError>,
    {
        let block_instance = f(self.current_blocks())?;
        self.block(block_instance)
    }

    /// Seals the blocks into a verified `Seid`.
    pub fn build(self) -> Result<Seid, BuilderError> {
        if self.count == 0 {
            return Err(BuilderError::Empty);
        }
        Ok(Seid::from_raw_parts(self.count as u8, self.blocks))
    }
}

impl Default for SeidBuilder {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
