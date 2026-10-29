//! Stack-only Base62 encoding and decoding routines.

pub mod charset;
pub use charset::is_base62;

use crate::block::MAX_BLOCK_LEN;
use crate::error::{Base62Error, BufferError};

/// Maximum numerical value representable in an 8-character Base62 block ($62^8 - 1$).
pub const MAX_U64_BASE62_VAL: u64 = 218_340_105_584_895;

// =============================================================================
// Integer Codec (u64)
// =============================================================================

/// Computes the number of Base62 characters needed to encode a `u64`.
pub const fn encoded_u64_len(mut val: u64) -> usize {
    if val == 0 {
        return 1;
    }
    let mut len = 0;
    while val > 0 {
        val /= 62;
        len += 1;
    }
    len
}

/// Encodes a `u64` into a destination byte slice in big-endian order.
///
/// Returns the number of bytes written.
pub fn encode_u64_into(mut val: u64, dest: &mut [u8]) -> Result<usize, BufferError> {
    if val > MAX_U64_BASE62_VAL {
        return Err(BufferError::TooSmall {
            required: MAX_BLOCK_LEN,
            provided: dest.len(),
        });
    }

    let needed = encoded_u64_len(val);
    if dest.len() < needed {
        return Err(BufferError::TooSmall {
            required: needed,
            provided: dest.len(),
        });
    }

    if val == 0 {
        dest[0] = b'0';
        return Ok(1);
    }

    // Write from the back (least significant digit first)
    let mut idx = needed;
    while val > 0 {
        idx -= 1;
        dest[idx] = charset::encode_char((val % 62) as u8);
        val /= 62;
    }

    Ok(needed)
}

/// Decodes a big-endian Base62 string slice into a `u64`.
pub fn decode_u64(raw: &str) -> Result<u64, Base62Error> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return Err(Base62Error::Empty);
    }

    let mut val: u64 = 0;
    for &c in bytes {
        let digit = charset::decode_char(c)? as u64;
        val = val
            .checked_mul(62)
            .and_then(|v| v.checked_add(digit))
            .ok_or(Base62Error::Overflow)?;
    }

    Ok(val)
}

// =============================================================================
// Raw Byte Codec (Arbitrary binary / Blob / Cipher / Auth)
// =============================================================================

/// Computes the number of Base62 characters needed to encode $N$ bytes of data.
pub const fn encoded_bytes_len(byte_len: usize) -> usize {
    match byte_len {
        0 => 0,
        1 => 2, // 256 <= 62^2 (3,844)
        2 => 3, // 65,536 <= 62^3 (238,328)
        3 => 5, // 16.7M <= 62^5
        4 => 6, // 4.29B <= 62^6
        5 => 7, // 1.09T <= 62^7
        6 => 8, // 281T <= 62^8
        _ => 8, // Clamped to block maximum
    }
}

/// Encodes an arbitrary byte slice (up to 6 bytes) into Base62.
pub fn encode_bytes_into(src: &[u8], dest: &mut [u8]) -> Result<usize, BufferError> {
    if src.is_empty() {
        return Ok(0);
    }

    let mut val: u64 = 0;
    for &b in src {
        val = (val << 8) | (b as u64);
    }

    encode_u64_into(val, dest)
}

/// Decodes a Base62 string back into raw bytes.
pub fn decode_bytes_into(raw: &str, dest: &mut [u8]) -> Result<usize, Base62Error> {
    let mut val = decode_u64(raw)?;
    let mut temp = [0u8; 8];
    let mut len = 0;

    while val > 0 {
        temp[len] = (val & 0xFF) as u8;
        val >>= 8;
        len += 1;
    }

    if dest.len() < len {
        return Err(Base62Error::Buffer(BufferError::TooSmall {
            required: len,
            provided: dest.len(),
        }));
    }

    // Reverse into big-endian byte order
    for i in 0..len {
        dest[i] = temp[len - 1 - i];
    }

    Ok(len)
}
