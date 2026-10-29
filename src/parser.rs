//! Explicit zero-copy parser for `Seid`.

use crate::block::{InlineStr, MAX_BLOCK_LEN, MAX_BLOCKS, MIN_BLOCK_LEN, RawBlock};
use crate::error::{BlockError, ParseError};
use crate::manifest::Manifest;
use crate::seid::{DELIMITER, Seid};

pub fn parse(input: &str) -> Result<Seid, ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyInput);
    }

    let mut tokens: [&str; MAX_BLOCKS + 1] = [""; MAX_BLOCKS + 1];
    let mut token_count = 0;

    let mut start = 0;
    let bytes = input.as_bytes();
    let delim_bytes = DELIMITER.as_bytes();
    let len = bytes.len();

    let mut i = 0;
    while i < len {
        if i + delim_bytes.len() <= len && &bytes[i..i + delim_bytes.len()] == delim_bytes {
            let slice = &input[start..i];
            if slice.is_empty() {
                return Err(ParseError::MalformedDelimiter);
            }
            if token_count >= tokens.len() {
                return Err(ParseError::TooManyBlocks {
                    count: token_count + 1,
                    max: MAX_BLOCKS,
                });
            }
            tokens[token_count] = slice;
            token_count += 1;
            i += delim_bytes.len();
            start = i;
        } else {
            i += 1;
        }
    }

    let last_slice = &input[start..];
    if last_slice.is_empty() {
        return Err(ParseError::MalformedDelimiter);
    }
    if token_count >= tokens.len() {
        return Err(ParseError::TooManyBlocks {
            count: token_count + 1,
            max: MAX_BLOCKS,
        });
    }
    tokens[token_count] = last_slice;
    token_count += 1;

    if token_count < 2 {
        return Err(ParseError::MissingManifest);
    }

    let manifest_token = tokens[token_count - 1];
    let manifest = Manifest::decode(manifest_token)?;
    let declared_blocks = manifest.block_count() as usize;

    let functional_count = token_count - 1;
    if declared_blocks != functional_count {
        return Err(ParseError::BlockCountMismatch {
            manifest_declared: declared_blocks,
            actual: functional_count,
        });
    }

    let mut blocks = [RawBlock::new(crate::manifest::BlockType::TplText, unsafe {
        InlineStr::from_raw_parts([0; MAX_BLOCK_LEN], 0)
    }); MAX_BLOCKS];

    for idx in 0..functional_count {
        let token = tokens[idx];
        let t_len = token.len();
        if t_len < MIN_BLOCK_LEN || t_len > MAX_BLOCK_LEN {
            return Err(ParseError::Block {
                index: idx,
                source: BlockError::InvalidLength(t_len),
            });
        }

        let b_type = manifest
            .block_type(idx)
            .ok_or(ParseError::BlockCountMismatch {
                manifest_declared: declared_blocks,
                actual: functional_count,
            })?;

        let inline = InlineStr::try_new(token).map_err(|e| ParseError::Block {
            index: idx,
            source: e,
        })?;

        blocks[idx] = RawBlock::new(b_type, inline);
    }

    Ok(Seid::from_raw_parts(functional_count as u8, blocks))
}
