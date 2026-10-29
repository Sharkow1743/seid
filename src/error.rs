//! Error types for the `seid` crate.

use crate::manifest::types::BlockType;
use thiserror::Error;

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum BufferError {
    #[error("destination buffer too small: required {required} bytes, provided {provided}")]
    TooSmall { required: usize, provided: usize },
}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum Base62Error {
    #[error("invalid Base62 character: byte {0:#04x}")]
    InvalidChar(u8),
    #[error("decoded Base62 integer value overflows numerical bounds")]
    Overflow,
    #[error("cannot decode empty Base62 input")]
    Empty,
    #[error(transparent)]
    Buffer(#[from] BufferError),
}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum BlockError {
    #[error("invalid block character length: {0} (must be between 2 and 8 characters)")]
    InvalidLength(usize),
    #[error("invalid ASCII Base62 byte in block: {0:#04x}")]
    InvalidBase62Char(u8),
    #[error("block binary payload too large: {0} bytes (max is 6 bytes / 218T numerical limit)")]
    PayloadTooLarge(usize),
    #[error("block type mismatch: expected {expected}, actual {actual}")]
    TypeMismatch {
        expected: BlockType,
        actual: BlockType,
    },
    #[error(transparent)]
    Base62(#[from] Base62Error),
    #[error(transparent)]
    Buffer(#[from] BufferError),
}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum ManifestError {
    #[error("invalid block count in manifest: {declared} (maximum supported is {max})")]
    InvalidBlockCount { declared: u8, max: u8 },
    #[error("invalid manifest character length: {0}")]
    InvalidLength(usize),
    #[error("manifest bitstream contains extraneous unconsumed bits")]
    ExtraneousBits,
    #[error(transparent)]
    Base62(#[from] Base62Error),
    #[error(transparent)]
    Buffer(#[from] BufferError),
}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum ParseError {
    #[error("cannot parse empty identifier string")]
    EmptyInput,
    #[error("identifier is missing required trailing manifest block")]
    MissingManifest,
    #[error("too many blocks: found {count}, maximum allowable is {max}")]
    TooManyBlocks { count: usize, max: usize },
    #[error(
        "block count mismatch: manifest declares {manifest_declared} blocks, but found {actual}"
    )]
    BlockCountMismatch {
        manifest_declared: usize,
        actual: usize,
    },
    #[error("malformed lexical delimiter sequence")]
    MalformedDelimiter,
    #[error("failed to parse block at index {index}: {source}")]
    Block {
        index: usize,
        #[source]
        source: BlockError,
    },
    #[error("failed to parse trailing manifest: {0}")]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Base62(#[from] Base62Error),
}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum ParityError {
    #[error("identifier does not contain a parity block")]
    NoParityBlock,
    #[error("parity mismatch: expected checksum {expected:#018x}, calculated {calculated:#018x}")]
    ChecksumMismatch { expected: u64, calculated: u64 },
    #[error("uncorrectable error: corruption exceeds recovery budget")]
    UncorrectableError,
}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("identifier does not contain an auth block")]
    NoAuthBlock,
    #[error("identifier does not contain any cipher blocks")]
    NoCipherBlock,
    #[error("auth block at index {0} is unsigned")]
    UnsignedAuthBlock(usize),
    #[error("cryptographic authentication failed: signature mismatch or corrupted data")]
    InvalidSignature,
    #[error("invalid key length: expected {expected} bytes, provided {provided}")]
    InvalidKeyLength { expected: usize, provided: usize },
    #[error("failed to decrypt cipher payload: authentication tag mismatch")]
    DecryptionFailed,
    #[error(transparent)]
    Buffer(#[from] BufferError),
    #[error(transparent)]
    Block(#[from] BlockError),
}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum BuilderError {
    #[error("cannot add block: maximum capacity of {0} blocks reached")]
    CapacityExceeded(usize),
    #[error("cannot build identifier without at least one functional block")]
    Empty,
    #[error(transparent)]
    Block(#[from] BlockError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Buffer(#[from] BufferError),
}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExtractError {
    #[error("block count mismatch: expected {expected}, actual {actual}")]
    CountMismatch { expected: usize, actual: usize },
    #[error("block at index {index} failed extraction: {source}")]
    Block {
        index: usize,
        #[source]
        source: BlockError,
    },
    #[error("index {0} is out of bounds")]
    OutOfBounds(usize),
    #[error(transparent)]
    Parse(#[from] ParseError),
}
