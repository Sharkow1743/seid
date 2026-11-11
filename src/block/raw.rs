//! Stack-allocated token and raw block representations.

use core::borrow::Borrow;
use core::cmp::Ordering;
use core::fmt;
use core::str;

use crate::base62;
use crate::error::{BlockError, BufferError};
use crate::manifest::{BlockType, MAX_BLOCK_LEN, MIN_BLOCK_LEN};

use super::Block;

/// Stack-allocated fixed 8-byte ASCII string for text and token blocks.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct InlineStr {
    buf: [u8; MAX_BLOCK_LEN],
    len: u8,
}

impl InlineStr {
    pub const fn try_new(s: &str) -> Result<Self, BlockError> {
        let bytes = s.as_bytes();
        let len = bytes.len();

        if len < MIN_BLOCK_LEN || len > MAX_BLOCK_LEN {
            return Err(BlockError::InvalidLength(len));
        }

        let mut buf = [0u8; MAX_BLOCK_LEN];
        let mut i = 0;
        while i < len {
            let c = bytes[i];
            if !base62::is_base62(c) {
                return Err(BlockError::InvalidBase62Char(c));
            }
            buf[i] = c;
            i += 1;
        }

        Ok(Self {
            buf,
            len: len as u8,
        })
    }

    #[inline]
    pub const unsafe fn from_raw_parts(buf: [u8; MAX_BLOCK_LEN], len: u8) -> Self {
        Self { buf, len }
    }

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

impl PartialOrd for InlineStr {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InlineStr {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl AsRef<str> for InlineStr {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for InlineStr {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Borrow<str> for InlineStr {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl TryFrom<&str> for InlineStr {
    type Error = BlockError;
    #[inline]
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::try_new(s)
    }
}

impl PartialEq<str> for InlineStr {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for InlineStr {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<InlineStr> for str {
    #[inline]
    fn eq(&self, other: &InlineStr) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<InlineStr> for &str {
    #[inline]
    fn eq(&self, other: &InlineStr) -> bool {
        *self == other.as_str()
    }
}

impl core::ops::Deref for InlineStr {
    type Target = str;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Debug for InlineStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for InlineStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An ingested or parsed block token with its manifest [`BlockType`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RawBlock {
    pub(crate) kind: BlockType,
    pub(crate) token: InlineStr,
}

impl RawBlock {
    #[inline]
    pub const fn new(kind: BlockType, token: InlineStr) -> Self {
        Self { kind, token }
    }

    #[inline]
    pub const fn kind(&self) -> BlockType {
        self.kind
    }

    #[inline]
    pub const fn block_type(&self) -> BlockType {
        self.kind
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        self.token.as_str()
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.token.as_bytes()
    }

    #[inline]
    pub fn encoded_len(&self) -> usize {
        self.token.len()
    }

    #[inline]
    pub fn encode_into(&self, dest: &mut [u8]) -> Result<usize, BufferError> {
        let len = self.token.len();
        if dest.len() < len {
            return Err(BufferError::TooSmall {
                required: len,
                provided: dest.len(),
            });
        }
        dest[..len].copy_from_slice(self.token.as_bytes());
        Ok(len)
    }

    pub fn decode<B: Block>(&self) -> Result<B, BlockError> {
        if self.kind != B::TYPE {
            return Err(BlockError::TypeMismatch {
                expected: B::TYPE,
                actual: self.kind,
            });
        }
        B::decode(self.token.as_str())
    }
}

impl fmt::Display for RawBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token.as_str())
    }
}
