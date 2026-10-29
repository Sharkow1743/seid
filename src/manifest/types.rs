//! Manifest types, discriminators, and format limits.

use core::fmt;

/// The maximum number of functional blocks an identifier can contain (excluding Manifest).
pub const MAX_BLOCKS: usize = 8;

/// Minimum character length of any encoded Base62 block.
pub const MIN_BLOCK_LEN: usize = 2;

/// Maximum character length of any encoded Base62 block.
pub const MAX_BLOCK_LEN: usize = 8;

/// Maximum raw binary payload capacity per single block in bytes.
pub const MAX_BLOCK_BYTES: usize = 6;

/// Reserved escape tag representing extended type systems in future specifications.
pub const ESCAPE_TAG: u8 = 15;

/// 4-bit discriminator defining the semantic capability of a block in the manifest bitfield.
///
/// # Namespace Layout
/// - `0..=7`: Core standard block types defined by the SEID specification.
/// - `8..=14`: Dedicated custom block space reserved for external crates and applications.
/// - `15`: Reserved escape tag.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockType {
    /// Type 0: Static template text (hierarchy & domain).
    TplText,
    /// Type 1: Random entropy (uniqueness / nonce).
    Rand,
    /// Type 2: Chronologically sortable timestamp.
    Time,
    /// Type 3: Parity / checksum symbol for error detection.
    Parity,
    /// Type 4: Cryptographic origin proof / signature tag.
    Auth,
    /// Type 5: Raw arbitrary binary payload.
    Blob,
    /// Type 6: Encrypted binary payload (co-keyed with Auth).
    Cipher,
    /// Type 7: Static instance text (region, cluster, shard, tenant).
    InstText,
    /// Types 8..=14: Dedicated custom block space reserved for third-party / proprietary blocks.
    Custom(u8),
    /// Type 15: Escape tag for future multi-nibble extended types.
    Escape,
}

impl BlockType {
    /// Converts a raw 4-bit nibble into its corresponding [`BlockType`].
    #[inline]
    pub const fn from_u8(val: u8) -> Self {
        match val & 0x0F {
            0 => Self::TplText,
            1 => Self::Rand,
            2 => Self::Time,
            3 => Self::Parity,
            4 => Self::Auth,
            5 => Self::Blob,
            6 => Self::Cipher,
            7 => Self::InstText,
            tag @ 8..=14 => Self::Custom(tag),
            15 => Self::Escape,
            _ => unreachable!(),
        }
    }

    /// Returns the 4-bit representation as a primitive `u8`.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::TplText => 0,
            Self::Rand => 1,
            Self::Time => 2,
            Self::Parity => 3,
            Self::Auth => 4,
            Self::Blob => 5,
            Self::Cipher => 6,
            Self::InstText => 7,
            Self::Custom(tag) => {
                debug_assert!(tag >= 8 && tag <= 14, "Custom block tag must be in 8..=14");
                tag & 0x0F
            }
            Self::Escape => 15,
        }
    }

    /// Returns `true` if this block belongs to the standard specification (types `0..=7`).
    #[inline]
    pub const fn is_standard(self) -> bool {
        matches!(
            self,
            Self::TplText
                | Self::Rand
                | Self::Time
                | Self::Parity
                | Self::Auth
                | Self::Blob
                | Self::Cipher
                | Self::InstText
        )
    }

    /// Returns `true` if this block belongs to the third-party custom namespace (types `8..=14`).
    #[inline]
    pub const fn is_custom(self) -> bool {
        matches!(self, Self::Custom(_))
    }
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TplText => f.write_str("TplText"),
            Self::Rand => f.write_str("Rand"),
            Self::Time => f.write_str("Time"),
            Self::Parity => f.write_str("Parity"),
            Self::Auth => f.write_str("Auth"),
            Self::Blob => f.write_str("Blob"),
            Self::Cipher => f.write_str("Cipher"),
            Self::InstText => f.write_str("InstText"),
            Self::Custom(tag) => write!(f, "Custom({tag})"),
            Self::Escape => f.write_str("Escape"),
        }
    }
}
