//! Stack-only Base62 encoding and decoding routines.

pub mod charset;
pub use charset::is_base62;

use crate::block::{MAX_BLOCK_BYTES, MAX_BLOCK_LEN, MIN_BLOCK_LEN};
use crate::error::{Base62Error, BufferError};

/// Maximum numerical value representable in an 8-character Base62 block ($62^8 - 1$).
pub const MAX_U64_BASE62_VAL: u64 = 218_340_105_584_895;

// =============================================================================
// Integer Codec (u64)
// =============================================================================

pub const fn encoded_u64_len(mut val: u64) -> usize {
    if val == 0 {
        return MIN_BLOCK_LEN;
    }
    let mut len = 0;
    while val > 0 {
        val /= 62;
        len += 1;
    }
    if len < MIN_BLOCK_LEN {
        MIN_BLOCK_LEN
    } else {
        len
    }
}

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

    for i in 0..needed {
        dest[i] = b'0';
    }

    if val == 0 {
        return Ok(needed);
    }

    let mut idx = needed;
    while val > 0 {
        idx -= 1;
        dest[idx] = charset::encode_char((val % 62) as u8);
        val /= 62;
    }

    Ok(needed)
}

pub fn encode_u64_fixed_into(
    mut val: u64,
    fixed_len: usize,
    dest: &mut [u8],
) -> Result<usize, BufferError> {
    if val > MAX_U64_BASE62_VAL || fixed_len > MAX_BLOCK_LEN || fixed_len < MIN_BLOCK_LEN {
        return Err(BufferError::TooSmall {
            required: fixed_len,
            provided: dest.len(),
        });
    }

    if dest.len() < fixed_len {
        return Err(BufferError::TooSmall {
            required: fixed_len,
            provided: dest.len(),
        });
    }

    for i in 0..fixed_len {
        dest[i] = b'0';
    }

    let mut idx = fixed_len;
    while val > 0 && idx > 0 {
        idx -= 1;
        dest[idx] = charset::encode_char((val % 62) as u8);
        val /= 62;
    }

    Ok(fixed_len)
}

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

    if val > MAX_U64_BASE62_VAL {
        return Err(Base62Error::Overflow);
    }

    Ok(val)
}

// =============================================================================
// Raw Byte Codec (Arbitrary binary / Blob / Cipher / Auth)
// =============================================================================

/// Canonical mapping from byte length (1..=5) to exact Base62 character width.
pub const fn encoded_bytes_len(byte_len: usize) -> usize {
    match byte_len {
        0 => 0,
        1 => 2, // 256 <= 62^2 (3,844)
        2 => 3, // 65,536 <= 62^3 (238,328)
        3 => 5, // 16.7M <= 62^5 (916M)
        4 => 6, // 4.29B <= 62^6 (56.8B)
        5 => 7, // 1.09T <= 62^7 (3.52T)
        _ => MAX_BLOCK_LEN,
    }
}

/// Canonical mapping from Base62 character length back to byte length.
pub const fn decoded_bytes_len(char_len: usize) -> usize {
    match char_len {
        0 => 0,
        1..=2 => 1,
        3..=4 => 2,
        5 => 3,
        6 => 4,
        _ => MAX_BLOCK_BYTES,
    }
}

/// Encodes an arbitrary byte slice (up to 5 bytes) into Base62 preserving length.
pub fn encode_bytes_into(src: &[u8], dest: &mut [u8]) -> Result<usize, BufferError> {
    if src.is_empty() {
        return Ok(0);
    }
    if src.len() > MAX_BLOCK_BYTES {
        return Err(BufferError::TooSmall {
            required: MAX_BLOCK_LEN,
            provided: dest.len(),
        });
    }

    let mut val: u64 = 0;
    for &b in src {
        val = (val << 8) | (b as u64);
    }

    let target_len = encoded_bytes_len(src.len());
    encode_u64_fixed_into(val, target_len, dest)
}

/// Decodes a Base62 string back into raw bytes, preserving exact length and leading zeros.
pub fn decode_bytes_into(raw: &str, dest: &mut [u8]) -> Result<usize, Base62Error> {
    if raw.is_empty() {
        return Ok(0);
    }
    let val = decode_u64(raw)?;
    let expected_len = decoded_bytes_len(raw.len());

    if dest.len() < expected_len {
        return Err(Base62Error::Buffer(BufferError::TooSmall {
            required: expected_len,
            provided: dest.len(),
        }));
    }

    for i in 0..expected_len {
        let shift = (expected_len - 1 - i) * 8;
        dest[i] = ((val >> shift) & 0xFF) as u8;
    }

    Ok(expected_len)
}
