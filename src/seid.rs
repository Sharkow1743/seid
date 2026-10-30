//! Core identifier representation, stack string output, and multi-format encoding.

use core::cmp::Ordering;
use core::fmt;
use core::ops::Index;
use core::str;

use crate::block::{
    Auth, Block, BlockType, InlineStr, MAX_BLOCK_LEN, MAX_BLOCKS, Parity, RawBlock, Time,
};
use crate::error::{BufferError, CryptoError, ExtractError, ParityError, ParseError};
use crate::manifest::Manifest;

#[cfg(feature = "alloc")]
use alloc::string::String;

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
            .map_or(false, |b| b.as_str() == prefix)
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

    // =========================================================================
    // Checksum & Cryptography
    // =========================================================================

    pub fn check_parity(&self) -> Result<bool, ParityError> {
        let blocks = self.blocks();
        let mut found = false;
        let mut ok = true;
        let mut symbol_idx = 0;

        for block in blocks {
            if block.kind == BlockType::Parity {
                found = true;
                let p: Parity = block
                    .decode()
                    .map_err(|_| ParityError::UncorrectableError)?;
                if !p.verify_symbol(blocks, symbol_idx) {
                    ok = false;
                }
                symbol_idx += 1;
            }
        }

        if found {
            Ok(ok)
        } else {
            Err(ParityError::NoParityBlock)
        }
    }

    /// Verifies the first Auth block in the identifier.
    pub fn verify_signature(&self, key: &[u8; 32]) -> Result<bool, CryptoError> {
        let blocks = self.blocks();
        let auth_pos = blocks.iter().position(|b| b.kind() == BlockType::Auth);

        match auth_pos {
            Some(idx) => self.verify_signature_at(idx, key),
            None => Err(CryptoError::NoAuthBlock),
        }
    }

    /// Verifies envelope authentication for the Auth block at `auth_idx`.
    pub fn verify_signature_at(
        &self,
        auth_idx: usize,
        key: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        let blocks = self.blocks();
        if auth_idx >= blocks.len() || blocks[auth_idx].kind() != BlockType::Auth {
            return Err(CryptoError::NoAuthBlock);
        }

        let a: Auth = blocks[auth_idx].decode()?;
        if !a.is_signed {
            return Err(CryptoError::UnsignedAuthBlock(auth_idx));
        }

        crate::block::crypto::verify_blake3_envelope_auth(blocks, a.as_bytes(), key, auth_idx)
    }

    /// Signs an unsigned Auth block at `auth_idx` in place, returning a signed `Seid`.
    pub fn sign_at(&self, auth_idx: usize, key: &[u8; 32]) -> Result<Self, CryptoError> {
        let mut new_blocks = self.blocks;
        let count = self.block_count as usize;

        if auth_idx >= count || new_blocks[auth_idx].kind() != BlockType::Auth {
            return Err(CryptoError::NoAuthBlock);
        }

        let signed_auth = crate::block::crypto::create_blake3_envelope_auth(
            &new_blocks[..count],
            key,
            auth_idx,
            crate::block::crypto::DEFAULT_AUTH_TAG_LEN,
        )?;

        let mut buf = [0u8; MAX_BLOCK_LEN];
        let written = signed_auth.encode(&mut buf)?;
        let s = core::str::from_utf8(&buf[..written])
            .map_err(|_| CryptoError::Block(crate::error::BlockError::InvalidBase62Char(0)))?;
        let token = InlineStr::try_new(s)?;

        new_blocks[auth_idx] = RawBlock::new(BlockType::Auth, token);
        Ok(Self::from_raw_parts(self.block_count, new_blocks))
    }

    pub fn is_fully_signed(&self) -> bool {
        for block in self.blocks() {
            if block.kind == BlockType::Auth {
                if let Ok(a) = block.decode::<Auth>() {
                    if !a.is_signed {
                        return false;
                    }
                }
            }
        }
        true
    }

    pub fn decrypt(&self, key: &[u8; 32], out: &mut [u8]) -> Result<usize, CryptoError> {
        self.decrypt_with_nonce(key, &[], out)
    }

    pub fn decrypt_with_nonce(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        crate::block::crypto::decrypt_blocks_with_nonce(self.blocks(), key, nonce, out)
    }

    /// Returns the primary timestamp:
    /// - If 1 Time block: delta milliseconds since epoch.
    /// - If 2 Time blocks: coarse seconds * 1,000,000,000 + fine nanoseconds.
    pub fn timestamp(&self) -> Option<u64> {
        let mut time_iter = self.blocks().iter().filter_map(|b| {
            if b.kind() == BlockType::Time {
                b.decode::<Time>().ok().map(|t| t.0)
            } else {
                None
            }
        });

        let coarse = time_iter.next()?;
        match time_iter.next() {
            Some(fine) => Some(coarse.saturating_mul(1_000_000_000).saturating_add(fine)),
            None => Some(coarse),
        }
    }

    // =========================================================================
    // Serialization & Ingestion
    // =========================================================================

    #[inline]
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        crate::parser::parse(input)
    }

    #[inline]
    pub const fn builder() -> crate::builder::SeidBuilder {
        crate::builder::SeidBuilder::new()
    }

    pub fn encoded_len(&self) -> usize {
        self.encoded_len_with_delim(CANONICAL_DELIMITER)
    }

    pub fn encoded_len_with_delim(&self, delim: &str) -> usize {
        let count = self.block_count as usize;
        let mut len = 0;
        for block in &self.blocks[..count] {
            len += block.encoded_len();
        }
        len += count * delim.len();
        len += self.manifest().encoded_len();
        len
    }

    pub fn encode_to_slice<'a>(&self, dest: &'a mut [u8]) -> Result<&'a str, BufferError> {
        self.encode_to_slice_with_delim(dest, CANONICAL_DELIMITER)
    }

    pub fn encode_to_slice_with_delim<'a>(
        &self,
        dest: &'a mut [u8],
        delim: &str,
    ) -> Result<&'a str, BufferError> {
        let required = self.encoded_len_with_delim(delim);
        if dest.len() < required {
            return Err(BufferError::TooSmall {
                required,
                provided: dest.len(),
            });
        }

        let mut cursor = 0;
        let count = self.block_count as usize;
        let delim_bytes = delim.as_bytes();

        for block in &self.blocks[..count] {
            let written = block.encode_into(&mut dest[cursor..])?;
            cursor += written;
            dest[cursor..cursor + delim_bytes.len()].copy_from_slice(delim_bytes);
            cursor += delim_bytes.len();
        }

        let manifest = self.manifest();
        cursor += manifest.encode_into(&mut dest[cursor..])?;

        Ok(unsafe { str::from_utf8_unchecked(&dest[..cursor]) })
    }

    pub fn to_encoded(&self) -> EncodedSeid {
        let mut buf = [0u8; MAX_ENCODED_LEN];
        let len = self.encode_to_slice(&mut buf).unwrap().len();
        EncodedSeid {
            buf,
            len: len as u8,
        }
    }

    /// Formats the identifier as a URL-safe string using '.' as delimiter.
    pub fn to_url_encoded(&self) -> EncodedSeid {
        let mut buf = [0u8; MAX_ENCODED_LEN];
        let len = self
            .encode_to_slice_with_delim(&mut buf, URL_DELIMITER)
            .unwrap()
            .len();
        EncodedSeid {
            buf,
            len: len as u8,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn encode(&self) -> String {
        use core::fmt::Write;
        let mut s = String::with_capacity(self.encoded_len());
        let _ = write!(s, "{}", self);
        s
    }
}

impl PartialOrd for Seid {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Zero-allocation O(N) token-by-token comparison.
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
