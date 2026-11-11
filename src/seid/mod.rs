//! Core identifier representation, stack string output, and multi-format encoding.

mod crypto_ops;
mod encode;
mod query;

use core::cmp::Ordering;
use core::fmt;
use core::ops::Index;
use core::str;

use crate::block::{Block, BlockType, MAX_BLOCKS, RawBlock};
use crate::error::{ExtractError, ParseError};
use crate::manifest::Manifest;

pub const DELIMITER: &str = "::";
pub const CANONICAL_DELIMITER: &str = "::";
pub const URL_DELIMITER: &str = ".";

pub const MAX_ENCODED_LEN: usize = 88;

/// Fixed-size stack-allocated canonical ASCII string representation of a `Seid`.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct EncodedSeid {
    buf: [u8; MAX_ENCODED_LEN],
    len: u8,
}

impl EncodedSeid {
    #[inline]
    pub fn as_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.buf[..self.len as usize]) }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::ops::Deref for EncodedSeid {
    type Target = str;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for EncodedSeid {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialOrd for EncodedSeid {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EncodedSeid {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl fmt::Display for EncodedSeid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for EncodedSeid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

/// Primary stack-allocated identifier object.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Seid {
    pub(crate) block_count: u8,
    pub(crate) blocks: [RawBlock; MAX_BLOCKS],
}

pub type Id = Seid;

impl Seid {
    #[inline]
    pub const fn from_raw_parts(block_count: u8, blocks: [RawBlock; MAX_BLOCKS]) -> Self {
        Self {
            block_count,
            blocks,
        }
    }

    #[inline]
    pub const fn block_count(&self) -> usize {
        self.block_count as usize
    }

    #[inline]
    pub fn blocks(&self) -> &[RawBlock] {
        &self.blocks[..self.block_count as usize]
    }

    #[inline]
    pub fn get_block(&self, index: usize) -> Option<&RawBlock> {
        if index < self.block_count as usize {
            Some(&self.blocks[index])
        } else {
            None
        }
    }

    #[inline]
    pub fn manifest(&self) -> Manifest {
        let mut types = [BlockType::TplText; MAX_BLOCKS];
        let count = self.block_count as usize;
        let mut i = 0;
        while i < count {
            types[i] = self.blocks[i].kind();
            i += 1;
        }
        Manifest::new(self.block_count, types)
    }

    #[inline]
    pub fn contains_type(&self, kind: BlockType) -> bool {
        self.manifest().contains(kind)
    }

    pub fn matches_schema(&self, schema: &[BlockType]) -> bool {
        let blocks = self.blocks();
        if blocks.len() != schema.len() {
            return false;
        }
        for (i, &expected) in schema.iter().enumerate() {
            if blocks[i].kind() != expected {
                return false;
            }
        }
        true
    }

    #[inline]
    pub fn get_as<B: Block>(&self, index: usize) -> Result<B, ExtractError> {
        let block = self
            .get_block(index)
            .ok_or(ExtractError::OutOfBounds(index))?;
        block
            .decode::<B>()
            .map_err(|e| ExtractError::Block { index, source: e })
    }

    pub fn first_of<B: Block>(&self) -> Result<Option<B>, ExtractError> {
        for (i, block) in self.blocks().iter().enumerate() {
            if block.kind() == B::TYPE {
                return block
                    .decode::<B>()
                    .map(Some)
                    .map_err(|e| ExtractError::Block {
                        index: i,
                        source: e,
                    });
            }
        }
        Ok(None)
    }

    #[inline]
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.blocks()
            .first()
            .is_some_and(|b| b.as_str() == prefix)
    }

    pub fn matches_prefix(&self, prefixes: &[&str]) -> bool {
        let blocks = self.blocks();
        if blocks.len() < prefixes.len() {
            return false;
        }
        for (i, &prefix) in prefixes.iter().enumerate() {
            if blocks[i].as_str() != prefix {
                return false;
            }
        }
        true
    }

    #[inline]
    pub fn template_path(&self) -> impl Iterator<Item = &str> {
        self.blocks().iter().filter_map(|b| {
            if b.kind() == BlockType::TplText {
                Some(b.as_str())
            } else {
                None
            }
        })
    }

    #[inline]
    pub fn unpack<'a, T: crate::block::Unpack<'a>>(&'a self) -> Result<T, ExtractError> {
        T::unpack(self.blocks())
    }

    #[inline]
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        crate::parser::parse(input)
    }

    #[inline]
    pub const fn builder() -> crate::builder::SeidBuilder {
        crate::builder::SeidBuilder::new()
    }
}

impl PartialOrd for Seid {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Seid {
    fn cmp(&self, other: &Self) -> Ordering {
        let count = self.block_count.min(other.block_count) as usize;
        for i in 0..count {
            match self.blocks[i].token.cmp(&other.blocks[i].token) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        self.block_count.cmp(&other.block_count)
    }
}

impl AsRef<[RawBlock]> for Seid {
    #[inline]
    fn as_ref(&self) -> &[RawBlock] {
        self.blocks()
    }
}

impl<'a> IntoIterator for &'a Seid {
    type Item = &'a RawBlock;
    type IntoIter = core::slice::Iter<'a, RawBlock>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.blocks().iter()
    }
}

impl Index<usize> for Seid {
    type Output = RawBlock;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        assert!(
            index < self.block_count as usize,
            "Seid block index out of bounds"
        );
        &self.blocks[index]
    }
}

impl fmt::Display for Seid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.block_count as usize;
        for i in 0..count {
            self.blocks[i].fmt(f)?;
            f.write_str(CANONICAL_DELIMITER)?;
        }
        self.manifest().fmt(f)
    }
}

impl str::FromStr for Seid {
    type Err = ParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for Seid {
    type Error = ParseError;

    #[inline]
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}
