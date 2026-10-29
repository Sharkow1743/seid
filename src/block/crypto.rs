//! Cryptographic signature authentication and stream cipher payload operations using BLAKE3.

use crate::base62;
use crate::block::{Block, BlockType, MAX_BLOCK_BYTES, RawBlock};
use crate::error::{BlockError, BufferError, CryptoError};

pub fn verify_blake3_auth(
    blocks: &[RawBlock],
    tag: &[u8],
    key: &[u8; 32],
) -> Result<bool, CryptoError> {
    let mut hasher = blake3::Hasher::new_keyed(key);

    for block in blocks {
        if block.kind == BlockType::Auth {
            break;
        }
        hasher.update(block.as_bytes());
        hasher.update(b"::");
    }

    let mut output = [0u8; 32];
    let mut xof = hasher.finalize_xof();
    xof.fill(&mut output);

    let expected = &output[..tag.len()];

    #[cfg(feature = "subtle")]
    {
        use subtle::ConstantTimeEq;
        Ok(tag.ct_eq(expected).into())
    }

    #[cfg(not(feature = "subtle"))]
    {
        Ok(tag == expected)
    }
}

pub fn create_blake3_auth(
    blocks: &[RawBlock],
    key: &[u8; 32],
    tag_len: usize,
) -> Result<Auth, CryptoError> {
    let mut hasher = blake3::Hasher::new_keyed(key);

    for block in blocks {
        if block.kind == BlockType::Auth {
            break;
        }
        hasher.update(block.as_bytes());
        hasher.update(b"::");
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

pub fn decrypt_blocks(
    blocks: &[RawBlock],
    key: &[u8; 32],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let mut cipher_len = 0;
    for block in blocks {
        if block.kind == BlockType::Cipher {
            let c: Cipher = block.decode()?;
            cipher_len += c.len as usize;
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

    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"seid::cipher::keystream");

    let mut xof = hasher.finalize_xof();
    let mut cursor = 0;

    for block in blocks {
        if block.kind == BlockType::Cipher {
            let c: Cipher = block.decode()?;
            let chunk_len = c.len as usize;
            let mut keystream = [0u8; MAX_BLOCK_BYTES];
            xof.fill(&mut keystream[..chunk_len]);

            for i in 0..chunk_len {
                out[cursor + i] = c.bytes[i] ^ keystream[i];
            }
            cursor += chunk_len;
        }
    }

    Ok(cursor)
}

/// Type 4: Cryptographic Authenticator MAC tag block.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Auth {
    pub bytes: [u8; MAX_BLOCK_BYTES],
    pub len: u8,
}

impl Auth {
    #[inline]
    pub fn sign(preceding_blocks: &[RawBlock], key: &[u8; 32]) -> Self {
        create_blake3_auth(preceding_blocks, key, MAX_BLOCK_BYTES).unwrap()
    }

    #[inline]
    pub fn sign_with_len(
        preceding_blocks: &[RawBlock],
        key: &[u8; 32],
        tag_len: usize,
    ) -> Result<Self, CryptoError> {
        create_blake3_auth(preceding_blocks, key, tag_len)
    }

    #[inline]
    pub fn verify(&self, preceding_blocks: &[RawBlock], key: &[u8; 32]) -> bool {
        verify_blake3_auth(preceding_blocks, self.as_bytes(), key).unwrap_or(false)
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

/// Type 6: Encrypted binary payload block.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cipher {
    pub bytes: [u8; MAX_BLOCK_BYTES],
    pub len: u8,
}

impl Cipher {
    pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Self, CryptoError> {
        if plaintext.is_empty() || plaintext.len() > MAX_BLOCK_BYTES {
            return Err(CryptoError::Block(BlockError::PayloadTooLarge(
                plaintext.len(),
            )));
        }

        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(b"seid::cipher::keystream");
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
