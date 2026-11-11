//! Cryptographic signature authentication and stream cipher payload operations using BLAKE3.

use crate::base62;
use crate::block::{Block, BlockType, InlineStr, MAX_BLOCK_BYTES, MAX_BLOCK_LEN, RawBlock};
use crate::error::{BlockError, BufferError, BuilderError, CryptoError};

/// Default authenticating MAC tag length in bytes.
pub const DEFAULT_AUTH_TAG_LEN: usize = MAX_BLOCK_BYTES;

/// Constant-time slice comparison in pure no_std without external dependencies.
#[inline(never)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub(crate) fn auth_finalize_hook(
    state: &[u8; 32],
    blocks: &[RawBlock],
    my_idx: usize,
) -> Result<InlineStr, BuilderError> {
    let auth = create_blake3_envelope_auth(blocks, state, my_idx, DEFAULT_AUTH_TAG_LEN)?;
    let mut buf = [0u8; MAX_BLOCK_LEN];
    let written = auth.encode(&mut buf)?;
    let s = core::str::from_utf8(&buf[..written])
        .map_err(|_| BuilderError::Block(BlockError::InvalidBase62Char(0)))?;
    InlineStr::try_new(s).map_err(BuilderError::Block)
}

/// Computes BLAKE3 envelope authentication over functional payload blocks.
///
/// Excludes all Auth blocks (to allow multi-signing) and Parity blocks.
/// The signature covers the full identifier layout at `auth_index`.
pub fn create_blake3_envelope_auth(
    blocks: &[RawBlock],
    key: &[u8; 32],
    auth_index: usize,
    tag_len: usize,
) -> Result<Auth, CryptoError> {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"seid::envelope::auth::v2");
    hasher.update(&(auth_index as u64).to_le_bytes());

    for (i, block) in blocks.iter().enumerate() {
        if block.kind != BlockType::Auth && block.kind != BlockType::Parity {
            hasher.update(&(i as u64).to_le_bytes());
            hasher.update(&[block.kind.as_u8()]);
            hasher.update(block.as_bytes());
            hasher.update(b"::");
        }
    }

    let clamped = tag_len.min(MAX_BLOCK_BYTES);
    let mut output = [0u8; 32];
    let mut xof = hasher.finalize_xof();
    xof.fill(&mut output);

    let mut bytes = [0u8; MAX_BLOCK_BYTES];
    bytes[..clamped].copy_from_slice(&output[..clamped]);

    Ok(Auth {
        bytes,
        len: clamped as u8,
    })
}

pub fn verify_blake3_envelope_auth(
    blocks: &[RawBlock],
    tag: &[u8],
    key: &[u8; 32],
    auth_index: usize,
) -> Result<bool, CryptoError> {
    let expected = create_blake3_envelope_auth(blocks, key, auth_index, tag.len())?;
    Ok(constant_time_eq(tag, expected.as_bytes()))
}

/// Decrypts sequential cipher blocks with an optional nonce to prevent keystream reuse.
pub fn decrypt_blocks_with_nonce(
    blocks: &[RawBlock],
    key: &[u8; 32],
    nonce: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let mut cipher_len = 0;
    for block in blocks {
        if block.kind == BlockType::Cipher {
            let c: Cipher = block.decode()?;
            cipher_len += (c.len as usize).min(MAX_BLOCK_BYTES);
        }
    }

    if cipher_len == 0 {
        return Err(CryptoError::NoCipherBlock);
    }

    if out.len() < cipher_len {
        return Err(CryptoError::Buffer(BufferError::TooSmall {
            required: cipher_len,
            provided: out.len(),
        }));
    }

    let mut cursor = 0;
    let mut chunk_index: usize = 0;

    for block in blocks {
        if block.kind == BlockType::Cipher {
            let c: Cipher = block.decode()?;
            let chunk_len = (c.len as usize).min(MAX_BLOCK_BYTES);

            let mut hasher = blake3::Hasher::new_keyed(key);
            hasher.update(b"seid::cipher::keystream::v2");
            hasher.update(&(nonce.len() as u64).to_le_bytes());
            hasher.update(nonce);
            hasher.update(&(chunk_index as u64).to_le_bytes());

            let mut xof = hasher.finalize_xof();
            let mut keystream = [0u8; MAX_BLOCK_BYTES];
            xof.fill(&mut keystream[..chunk_len]);

            for i in 0..chunk_len {
                out[cursor + i] = c.bytes[i] ^ keystream[i];
            }
            cursor += chunk_len;
            chunk_index += 1;
        }
    }

    Ok(cursor)
}

pub fn decrypt_blocks(
    blocks: &[RawBlock],
    key: &[u8; 32],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    decrypt_blocks_with_nonce(blocks, key, &[], out)
}

/// Type 5: Cryptographic authenticator MAC tag block.
///
/// Does not store signing keys. Use [`SeidBuilder::auth`](crate::SeidBuilder::auth) to
/// seal during build, or [`Seid::sign_at`](crate::Seid::sign_at) afterward.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Auth {
    pub bytes: [u8; MAX_BLOCK_BYTES],
    pub len: u8,
}

impl Auth {
    /// Placeholder tag filled with zeros; intended for later sealing via builder or `sign_at`.
    #[inline]
    pub fn unsigned() -> Self {
        Self {
            bytes: [0u8; MAX_BLOCK_BYTES],
            len: DEFAULT_AUTH_TAG_LEN as u8,
        }
    }

    /// True when this tag is still the all-zero placeholder (not yet sealed).
    ///
    /// A real MAC is all-zero with probability ~2^(-40) at the default tag length.
    #[inline]
    pub fn is_placeholder(&self) -> bool {
        self.as_bytes().iter().all(|&b| b == 0)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl Block for Auth {
    const TYPE: BlockType = BlockType::Auth;

    #[inline]
    fn encode(&self, dest: &mut [u8]) -> Result<usize, BufferError> {
        base62::encode_bytes_into(self.as_bytes(), dest)
    }

    #[inline]
    fn decode(raw: &str) -> Result<Self, BlockError> {
        let mut bytes = [0u8; MAX_BLOCK_BYTES];
        let len = base62::decode_bytes_into(raw, &mut bytes)?;
        Ok(Self {
            bytes,
            len: len as u8,
        })
    }
}

/// Type 7: Encrypted binary payload block.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cipher {
    pub bytes: [u8; MAX_BLOCK_BYTES],
    pub len: u8,
}

impl Cipher {
    #[inline]
    pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Self, CryptoError> {
        Self::encrypt_chunk_with_nonce(plaintext, key, &[], 0)
    }

    #[inline]
    pub fn encrypt_with_nonce(
        plaintext: &[u8],
        key: &[u8; 32],
        nonce: &[u8],
    ) -> Result<Self, CryptoError> {
        Self::encrypt_chunk_with_nonce(plaintext, key, nonce, 0)
    }

    #[inline]
    pub fn encrypt_chunk(
        plaintext: &[u8],
        key: &[u8; 32],
        chunk_index: usize,
    ) -> Result<Self, CryptoError> {
        Self::encrypt_chunk_with_nonce(plaintext, key, &[], chunk_index)
    }

    pub fn encrypt_chunk_with_nonce(
        plaintext: &[u8],
        key: &[u8; 32],
        nonce: &[u8],
        chunk_index: usize,
    ) -> Result<Self, CryptoError> {
        if plaintext.is_empty() || plaintext.len() > MAX_BLOCK_BYTES {
            return Err(CryptoError::Block(BlockError::PayloadTooLarge(
                plaintext.len(),
            )));
        }

        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(b"seid::cipher::keystream::v2");
        hasher.update(&(nonce.len() as u64).to_le_bytes());
        hasher.update(nonce);
        hasher.update(&(chunk_index as u64).to_le_bytes());

        let mut xof = hasher.finalize_xof();
        let mut keystream = [0u8; MAX_BLOCK_BYTES];
        xof.fill(&mut keystream[..plaintext.len()]);

        let mut bytes = [0u8; MAX_BLOCK_BYTES];
        for i in 0..plaintext.len() {
            bytes[i] = plaintext[i] ^ keystream[i];
        }

        Ok(Self {
            bytes,
            len: plaintext.len() as u8,
        })
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl Block for Cipher {
    const TYPE: BlockType = BlockType::Cipher;

    #[inline]
    fn encode(&self, dest: &mut [u8]) -> Result<usize, BufferError> {
        base62::encode_bytes_into(self.as_bytes(), dest)
    }

    #[inline]
    fn decode(raw: &str) -> Result<Self, BlockError> {
        let mut bytes = [0u8; MAX_BLOCK_BYTES];
        let len = base62::decode_bytes_into(raw, &mut bytes)?;
        Ok(Self {
            bytes,
            len: len as u8,
        })
    }
}
