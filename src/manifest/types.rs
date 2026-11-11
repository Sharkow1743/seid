//! Manifest types, discriminators, and format limits.

use core::fmt;

/// The maximum number of functional blocks an identifier can contain (excluding Manifest).
pub const MAX_BLOCKS: usize = 8;

/// Minimum character length of any encoded Base62 block.
pub const MIN_BLOCK_LEN: usize = 2;

/// Maximum character length of any encoded Base62 block.
pub const MAX_BLOCK_LEN: usize = 8;

/// Maximum raw binary payload capacity per single block in bytes.
/// Clamped strictly to 5 bytes ($2^{40} - 1 = 1,099,511,627,775 < 62^7$) to guarantee
/// 100% infallible encoding within Base62 block limits.
pub const MAX_BLOCK_BYTES: usize = 5;

/// Reserved escape tag representing extended type systems in future specifications.
pub const ESCAPE_TAG: u8 = 15;

/// 4-bit discriminator defining the semantic capability of a block in the manifest bitfield.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockType {
    /// Type 0: Static template text (hierarchy & domain).
    TplText,
    /// Type 1: Static instance text (region, cluster, shard, tenant).
    InstText,
    /// Type 2: Chronologically sortable timestamp.
    Time,
    /// Type 3: Random entropy (uniqueness / nonce).
    Rand,
    /// Type 4: Parity / checksum symbol for error detection.
    Parity,
    /// Type 5: Cryptographic origin proof / signature tag.
    Auth,
    /// Type 6: Raw arbitrary binary payload.
    Blob,
    /// Type 7: Encrypted binary payload (co-keyed with Auth).
    Cipher,
    /// Types 8..=14: Opaque unknown tags preserved for forward-compatibility.
    /// Reserved for future official built-ins; not a user-defined type API.
    Unknown(u8),
    /// Type 15: Escape tag for future multi-nibble extended types.
    Escape,
}

impl BlockType {
    #[inline]
    pub const fn from_u8(val: u8) -> Self {
        match val & 0x0F {
            0 => Self::TplText,
            1 => Self::InstText,
            2 => Self::Time,
            3 => Self::Rand,
            4 => Self::Parity,
            5 => Self::Auth,
            6 => Self::Blob,
            7 => Self::Cipher,
            tag @ 8..=14 => Self::Unknown(tag),
            15 => Self::Escape,
            _ => unreachable!(),
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::TplText => 0,
            Self::InstText => 1,
            Self::Time => 2,
            Self::Rand => 3,
            Self::Parity => 4,
            Self::Auth => 5,
            Self::Blob => 6,
            Self::Cipher => 7,
            Self::Unknown(tag) => {
                debug_assert!(tag >= 8 && tag <= 14, "Unknown block tag must be in 8..=14");
                tag & 0x0F
            }
            Self::Escape => 15,
        }
    }

    #[inline]
    pub const fn is_standard(self) -> bool {
        matches!(
            self,
            Self::TplText
                | Self::InstText
                | Self::Time
                | Self::Rand
                | Self::Parity
                | Self::Auth
                | Self::Blob
                | Self::Cipher
        )
    }

    #[inline]
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown(_))
    }
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TplText => f.write_str("TplText"),
            Self::InstText => f.write_str("InstText"),
            Self::Time => f.write_str("Time"),
            Self::Rand => f.write_str("Rand"),
            Self::Parity => f.write_str("Parity"),
            Self::Auth => f.write_str("Auth"),
            Self::Blob => f.write_str("Blob"),
            Self::Cipher => f.write_str("Cipher"),
            Self::Unknown(tag) => write!(f, "Unknown({tag})"),
            Self::Escape => f.write_str("Escape"),
        }
    }
}
