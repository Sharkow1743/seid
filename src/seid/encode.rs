//! Encoding helpers for [`Seid`](super::Seid).

use core::str;

use super::{CANONICAL_DELIMITER, EncodedSeid, MAX_ENCODED_LEN, Seid, URL_DELIMITER};
use crate::error::BufferError;

#[cfg(feature = "alloc")]
use alloc::string::String;

impl Seid {
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
