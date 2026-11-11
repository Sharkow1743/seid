use seid::block::{BlockType, Inst, Tpl};
use seid::error::{BlockError, ParseError};
use seid::{Manifest, Seid};

// =============================================================================
// 3. Lexical Parser & Delimiter Tests
// =============================================================================

#[test]
fn test_parser_canonical_and_url_delimiters() {
    let id = Seid::builder()
        .block(Tpl::new("doc").unwrap())
        .unwrap()
        .block(Inst::new("us1").unwrap())
        .unwrap()
        .build()
        .unwrap();

    let canonical = id.to_encoded();
    assert!(canonical.as_str().contains("::"));
    let from_canonical = Seid::parse(canonical.as_str()).unwrap();
    assert_eq!(id, from_canonical);

    let url = id.to_url_encoded();
    assert!(url.as_str().contains('.'));
    assert!(!url.as_str().contains("::"));
    let from_url = Seid::parse(url.as_str()).unwrap();
    assert_eq!(id, from_url);
}

#[test]
fn test_parser_mixed_delimiter_rejection() {
    let mixed1 = "usr.eu1::manifest";
    assert_eq!(Seid::parse(mixed1), Err(ParseError::MalformedDelimiter));

    let mixed2 = "usr::eu1.manifest";
    assert_eq!(Seid::parse(mixed2), Err(ParseError::MalformedDelimiter));
}

#[test]
fn test_parser_malformed_delimiters() {
    assert_eq!(Seid::parse(""), Err(ParseError::EmptyInput));
    assert_eq!(
        Seid::parse("::usr::mani"),
        Err(ParseError::MalformedDelimiter)
    );
    assert_eq!(
        Seid::parse("usr::mani::"),
        Err(ParseError::MalformedDelimiter)
    );
    assert_eq!(
        Seid::parse(".usr.mani"),
        Err(ParseError::MalformedDelimiter)
    );
    assert_eq!(
        Seid::parse("usr.mani."),
        Err(ParseError::MalformedDelimiter)
    );
    assert_eq!(
        Seid::parse("usr::::mani"),
        Err(ParseError::MalformedDelimiter)
    );
    assert_eq!(
        Seid::parse("usr..mani"),
        Err(ParseError::MalformedDelimiter)
    );
    assert_eq!(
        Seid::parse("singletoken"),
        Err(ParseError::MalformedDelimiter)
    );
}

#[test]
fn test_parser_block_length_limits() {
    // 1-char block token (< MIN_BLOCK_LEN = 2)
    let manifest = Manifest::new(1, [BlockType::TplText; 8]).to_string();
    let too_short = format!("u::{}", manifest);
    assert_eq!(
        Seid::parse(&too_short),
        Err(ParseError::Block {
            index: 0,
            source: BlockError::InvalidLength(1),
        })
    );

    // 9-char block token (> MAX_BLOCK_LEN = 8)
    let too_long = format!("123456789::{}", manifest);
    assert_eq!(
        Seid::parse(&too_long),
        Err(ParseError::Block {
            index: 0,
            source: BlockError::InvalidLength(9),
        })
    );
}

#[test]
fn test_parser_block_count_mismatches() {
    let m2 = Manifest::new(2, [BlockType::TplText; 8]).to_string();

    // Declares 2, found 1
    assert_eq!(
        Seid::parse(&format!("usr::{}", m2)),
        Err(ParseError::BlockCountMismatch {
            manifest_declared: 2,
            actual: 1
        })
    );

    // Declares 2, found 3
    assert_eq!(
        Seid::parse(&format!("usr::ord::inv::{}", m2)),
        Err(ParseError::BlockCountMismatch {
            manifest_declared: 2,
            actual: 3
        })
    );

    // 9 functional blocks + manifest = 10 tokens (> MAX_BLOCKS = 8)
    let tokens = "ab::ab::ab::ab::ab::ab::ab::ab::ab::00";
    assert_eq!(
        Seid::parse(tokens),
        Err(ParseError::TooManyBlocks { count: 10, max: 8 })
    );
}

