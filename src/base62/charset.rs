//! Base62 character set definition and O(1) table lookups.
//!
//! # Lexical Order
//!
//! The character set is strictly ordered by ASCII value:
//! 1. `0..=9` -> Values `0..=9`   (ASCII 48..=57)
//! 2. `A..=Z` -> Values `10..=35` (ASCII 65..=90)
//! 3. `a..=z` -> Values `36..=61` (ASCII 97..=122)
//!
//! Because `48 < 65 < 97`, raw byte-level sorting (`memcmp`) matches
//! numerical Base62 magnitude.

use crate::error::Base62Error;

/// The canonical 62-character alphabet.
pub const CHARSET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Sentinel value indicating an invalid Base62 byte in the lookup table.
pub const INVALID_CHAR: u8 = 0xFF;

/// 256-byte reverse lookup table for O(1) decoding without branches.
#[rustfmt::skip]
pub const REVERSE_TABLE: [u8; 256] = {
    let mut table = [INVALID_CHAR; 256];
    let mut i = 0;
    while i < 62 {
        table[CHARSET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Fast $O(1)$ check to verify if a byte belongs to the Base62 alphabet.
#[inline(always)]
pub const fn is_base62(c: u8) -> bool {
    REVERSE_TABLE[c as usize] != INVALID_CHAR
}

/// Decodes a single ASCII byte into its numerical value (`0..=61`).
#[inline(always)]
pub const fn decode_char(c: u8) -> Result<u8, Base62Error> {
    let val = REVERSE_TABLE[c as usize];
    if val != INVALID_CHAR {
        Ok(val)
    } else {
        Err(Base62Error::InvalidChar(c))
    }
}

/// Encodes a numerical value (`0..=61`) into its ASCII byte representation.
///
/// # Panics
/// Panics in debug mode if `val >= 62`.
#[inline(always)]
pub const fn encode_char(val: u8) -> u8 {
    debug_assert!(val < 62, "Base62 value out of range");
    CHARSET[val as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lexicographical_order() {
        // Assert that the array is strictly sorted in ascending ASCII order
        for i in 0..61 {
            assert!(CHARSET[i] < CHARSET[i + 1]);
        }
    }

    #[test]
    fn test_reverse_table_completeness() {
        for i in 0..62 {
            let ch = CHARSET[i];
            assert_eq!(REVERSE_TABLE[ch as usize], i as u8);
            assert!(is_base62(ch));
        }

        // Test non-Base62 characters
        assert!(!is_base62(b'-'));
        assert!(!is_base62(b'_'));
        assert!(!is_base62(b':'));
        assert!(!is_base62(b'/'));
    }
}
