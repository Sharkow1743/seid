//! Parity checks and cryptographic operations on [`Seid`](super::Seid).

use super::Seid;
use crate::block::{Auth, Block, BlockType, InlineStr, MAX_BLOCK_LEN, Parity, RawBlock};
use crate::error::{CryptoError, ParityError};

impl Seid {
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

    pub fn verify_signature(&self, key: &[u8; 32]) -> Result<bool, CryptoError> {
        let blocks = self.blocks();
        let auth_pos = blocks.iter().position(|b| b.kind() == BlockType::Auth);

        match auth_pos {
            Some(idx) => self.verify_signature_at(idx, key),
            None => Err(CryptoError::NoAuthBlock),
        }
    }

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
}
