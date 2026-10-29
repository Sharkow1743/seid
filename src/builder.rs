//! Fully block-agnostic identifier builder with build-time hooks.

use crate::block::{Block, Hook, InlineStr, MAX_BLOCK_LEN, MAX_BLOCKS, RawBlock};
use crate::error::BuilderError;
use crate::manifest::BlockType;
use crate::seid::Seid;

/// Block-agnostic builder supporting self-sealing blocks via stack-allocated hooks.
#[derive(Copy, Clone)]
pub struct SeidBuilder {
    blocks: [RawBlock; MAX_BLOCKS],
    hooks: [Option<Hook>; MAX_BLOCKS],
    count: usize,
}

pub type IdBuilder = SeidBuilder;

impl SeidBuilder {
    #[inline]
    pub const fn new() -> Self {
        Self {
            blocks: [RawBlock::new(BlockType::TplText, unsafe {
                InlineStr::from_raw_parts([0; MAX_BLOCK_LEN], 0)
            }); MAX_BLOCKS],
            hooks: [None; MAX_BLOCKS],
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

    /// Appends any type implementing [`Block`]. Registers build hooks if provided.
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
        self.hooks[self.count] = b.build_hook();
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

    /// Finalizes all self-sealing blocks in dependency order:
    /// Pass 1 seals cryptographic signatures (`Auth`), and Pass 2 computes error detection (`Parity`).
    pub fn build(mut self) -> Result<Seid, BuilderError> {
        if self.count == 0 {
            return Err(BuilderError::Empty);
        }

        // Pass 1: Finalize application signatures and content blocks
        for i in 0..self.count {
            if self.blocks[i].kind != BlockType::Parity {
                if let Some(hook) = self.hooks[i] {
                    let updated_token = (hook.func)(&hook.state, &self.blocks[..self.count], i)?;
                    self.blocks[i].token = updated_token;
                }
            }
        }

        // Pass 2: Finalize error-detection symbols (Parity) over finalized tokens
        for i in 0..self.count {
            if self.blocks[i].kind == BlockType::Parity {
                if let Some(hook) = self.hooks[i] {
                    let updated_token = (hook.func)(&hook.state, &self.blocks[..self.count], i)?;
                    self.blocks[i].token = updated_token;
                }
            }
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
