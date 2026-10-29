//! Typed block extraction into native primitives and block structs.

use crate::block::{Block, BlockType, InlineStr, RawBlock};
use crate::error::{BlockError, ExtractError};

/// Trait for types that can be extracted from a [`RawBlock`].
pub trait FromBlock<'a>: Sized {
    fn from_block(block: &'a RawBlock) -> Result<Self, ExtractError>;
}

impl<'a, B: Block> FromBlock<'a> for B {
    #[inline]
    fn from_block(block: &'a RawBlock) -> Result<Self, ExtractError> {
        block.decode::<B>().map_err(|e| ExtractError::Block {
            index: 0,
            source: e,
        })
    }
}

impl<'a> FromBlock<'a> for &'a str {
    #[inline]
    fn from_block(block: &'a RawBlock) -> Result<Self, ExtractError> {
        Ok(block.as_str())
    }
}

impl<'a> FromBlock<'a> for u64 {
    #[inline]
    fn from_block(block: &'a RawBlock) -> Result<Self, ExtractError> {
        crate::base62::decode_u64(block.as_str()).map_err(|e| ExtractError::Block {
            index: 0,
            source: BlockError::Base62(e),
        })
    }
}

impl<'a> FromBlock<'a> for u32 {
    #[inline]
    fn from_block(block: &'a RawBlock) -> Result<Self, ExtractError> {
        let val: u64 = FromBlock::from_block(block)?;
        u32::try_from(val).map_err(|_| ExtractError::Block {
            index: 0,
            source: BlockError::Base62(crate::error::Base62Error::Overflow),
        })
    }
}

impl<'a> FromBlock<'a> for InlineStr {
    #[inline]
    fn from_block(block: &'a RawBlock) -> Result<Self, ExtractError> {
        Ok(block.token)
    }
}

impl<'a> FromBlock<'a> for BlockType {
    #[inline]
    fn from_block(block: &'a RawBlock) -> Result<Self, ExtractError> {
        Ok(block.kind)
    }
}

impl<'a> FromBlock<'a> for &'a RawBlock {
    #[inline]
    fn from_block(block: &'a RawBlock) -> Result<Self, ExtractError> {
        Ok(block)
    }
}

impl<'a> FromBlock<'a> for RawBlock {
    #[inline]
    fn from_block(block: &'a RawBlock) -> Result<Self, ExtractError> {
        Ok(*block)
    }
}

/// Trait implemented by tuples of [`FromBlock`] to validate and unpack blocks.
pub trait Unpack<'a>: Sized {
    fn unpack(blocks: &'a [RawBlock]) -> Result<Self, ExtractError>;
}

macro_rules! impl_unpack_tuple {
    ($count:literal, $( $idx:tt : $T:ident ),*) => {
        impl<'a, $( $T: FromBlock<'a> ),*> Unpack<'a> for ($( $T, )*) {
            fn unpack(blocks: &'a [RawBlock]) -> Result<Self, ExtractError> {
                if blocks.len() != $count {
                    return Err(ExtractError::CountMismatch {
                        expected: $count,
                        actual: blocks.len(),
                    });
                }
                Ok(($(
                    $T::from_block(&blocks[$idx]).map_err(|e| match e {
                        ExtractError::Block { source, .. } => ExtractError::Block { index: $idx, source },
                        other => other,
                    })?,
                )*))
            }
        }
    };
}

impl_unpack_tuple!(1, 0:A);
impl_unpack_tuple!(2, 0:A, 1:B);
impl_unpack_tuple!(3, 0:A, 1:B, 2:C);
impl_unpack_tuple!(4, 0:A, 1:B, 2:C, 3:D);
impl_unpack_tuple!(5, 0:A, 1:B, 2:C, 3:D, 4:E);
impl_unpack_tuple!(6, 0:A, 1:B, 2:C, 3:D, 4:E, 5:F);
impl_unpack_tuple!(7, 0:A, 1:B, 2:C, 3:D, 4:E, 5:F, 6:G);
impl_unpack_tuple!(8, 0:A, 1:B, 2:C, 3:D, 4:E, 5:F, 6:G, 7:H);
