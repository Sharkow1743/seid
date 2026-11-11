//! Fully block-agnostic identifier builder with build-time hooks.

use crate::block::crypto::auth_finalize_hook;
use crate::block::{
    Auth, Block, Hook, InlineStr, Inst, MAX_BLOCK_LEN, MAX_BLOCKS, Parity, Rand, RawBlock, Tpl,
};
use crate::error::{BlockError, BuilderError};
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
        let valid_placeholder = unsafe {
            InlineStr::from_raw_parts([b'0'; MAX_BLOCK_LEN], crate::manifest::MIN_BLOCK_LEN as u8)
        };
        Self {
            blocks: [RawBlock::new(BlockType::TplText, valid_placeholder); MAX_BLOCKS],
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
            .map_err(|_| BuilderError::Block(BlockError::InvalidBase62Char(0)))?;

        let token = InlineStr::try_new(s)?;
        self.blocks[self.count] = RawBlock::new(B::TYPE, token);
        self.hooks[self.count] = b.build_hook();
        self.count += 1;
        Ok(self)
    }

    /// Appends a template text block (`Tpl`).
    pub fn template(self, s: &str) -> Result<Self, BuilderError> {
        self.block(Tpl::new(s)?)
    }

    /// Appends an instance text block (`Inst`).
    pub fn instance(self, s: &str) -> Result<Self, BuilderError> {
        self.block(Inst::new(s)?)
    }

    /// Appends a fast PRNG entropy block.
    pub fn rand_fast(self) -> Result<Self, BuilderError> {
        self.block(Rand::fast())
    }

    /// Appends an OS CSPRNG entropy block.
    #[cfg(feature = "sys-rand")]
    pub fn rand_sys(self) -> Result<Self, BuilderError> {
        let r = Rand::sys().map_err(|_| {
            BuilderError::Block(BlockError::Base62(crate::error::Base62Error::Overflow))
        })?;
        self.block(r)
    }

    /// Appends an auto-computing parity checksum block.
    pub fn parity(self) -> Result<Self, BuilderError> {
        self.block(Parity::auto())
    }

    /// Appends an Auth placeholder that seals over the full identifier during `build()`.
    ///
    /// The key is kept only in the builder hook, never on the [`Auth`] block itself.
    pub fn auth(mut self, key: [u8; 32]) -> Result<Self, BuilderError> {
        if self.count >= MAX_BLOCKS {
            return Err(BuilderError::CapacityExceeded(MAX_BLOCKS));
        }

        let b = Auth::unsigned();
        let mut buf = [0u8; MAX_BLOCK_LEN];
        let written = b.encode(&mut buf)?;
        let s = core::str::from_utf8(&buf[..written])
            .map_err(|_| BuilderError::Block(BlockError::InvalidBase62Char(0)))?;
        let token = InlineStr::try_new(s)?;

        self.blocks[self.count] = RawBlock::new(Auth::TYPE, token);
        self.hooks[self.count] = Some(Hook {
            func: auth_finalize_hook,
            state: key,
        });
        self.count += 1;
        Ok(self)
    }

    /// Appends a new timestamp block automatically configured for the next precision tier
    /// based on how many `Time` blocks have already been appended to this builder.
    #[cfg(all(feature = "sys-clock", feature = "std"))]
    pub fn time_now(self) -> Result<Self, BuilderError> {
        let time_instance_count = self
            .current_blocks()
            .iter()
            .filter(|b| b.kind() == BlockType::Time)
            .count();
        let time_block = crate::block::Time::now_instance(time_instance_count)?;
        self.block(time_block)
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
