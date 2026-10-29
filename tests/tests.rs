use std::collections::{BTreeSet, HashSet};
use std::str::FromStr;

use seid::base62::charset::{self, CHARSET};
use seid::base62::{self, MAX_U64_BASE62_VAL};
use seid::block::{
    Auth, Blob, Block, BlockType, Cipher, InlineStr, Inst, Parity, Rand, RawBlock, Time, Tpl,
};
use seid::error::{
    Base62Error, BlockError, BufferError, BuilderError, CryptoError, ExtractError, ManifestError,
    ParseError,
};
use seid::{Manifest, Seid};

// =============================================================================
// Custom External Block Implementation for Tests
// =============================================================================

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct GeoCluster(pub u16);

impl Block for GeoCluster {
    const TYPE: BlockType = BlockType::Custom(8);

    fn encode(&self, dest: &mut [u8]) -> Result<usize, BufferError> {
        base62::encode_u64_into(self.0 as u64, dest)
    }

    fn decode(raw: &str) -> Result<Self, BlockError> {
        let val = base62::decode_u64(raw)?;
        Ok(GeoCluster(val as u16))
    }
}

// =============================================================================
// 1. Base62 Codec & Character Set Tests
// =============================================================================

#[test]
fn test_base62_exhaustive_256_byte_classification() {
    let mut valid_count = 0;
    for b in 0u8..=255u8 {
        let is_ascii_alnum = b.is_ascii_alphanumeric();
        assert_eq!(
            charset::is_base62(b),
            is_ascii_alnum,
            "Mismatch for byte {:#04x} ('{}')",
            b,
            b as char
        );

        match charset::decode_char(b) {
            Ok(val) => {
                assert!(is_ascii_alnum);
                assert!(val < 62);
                assert_eq!(charset::encode_char(val), b);
                valid_count += 1;
            }
            Err(e) => {
                assert!(!is_ascii_alnum);
                assert_eq!(e, Base62Error::InvalidChar(b));
            }
        }
    }
    assert_eq!(valid_count, 62);
}

#[test]
fn test_base62_lexicographical_properties() {
    for i in 0..61 {
        let c1 = CHARSET[i];
        let c2 = CHARSET[i + 1];
        assert!(c1 < c2);
        assert!(charset::decode_char(c1).unwrap() < charset::decode_char(c2).unwrap());
    }
}

#[test]
fn test_base62_u64_boundaries() {
    let mut buf = [0u8; 8];

    // 0 encodes to "00"
    let len = base62::encode_u64_into(0, &mut buf).unwrap();
    assert_eq!(&buf[..len], b"00");
    assert_eq!(base62::decode_u64("00").unwrap(), 0);

    // 1..=61 zero-padded to 2 chars
    for v in 1..62 {
        let len = base62::encode_u64_into(v, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(buf[0], b'0');
        assert_eq!(buf[1], CHARSET[v as usize]);
        let s = std::str::from_utf8(&buf[..len]).unwrap();
        assert_eq!(base62::decode_u64(s).unwrap(), v);
    }

    // Exact powers of 62
    let mut p = 62u64;
    for _ in 1..7 {
        let len = base62::encode_u64_into(p, &mut buf).unwrap();
        let s = std::str::from_utf8(&buf[..len]).unwrap();
        assert_eq!(base62::decode_u64(s).unwrap(), p);
        p *= 62;
    }

    // MAX_U64_BASE62_VAL (62^8 - 1)
    let len = base62::encode_u64_into(MAX_U64_BASE62_VAL, &mut buf).unwrap();
    assert_eq!(len, 8);
    assert_eq!(&buf[..len], b"zzzzzzzz");
    assert_eq!(base62::decode_u64("zzzzzzzz").unwrap(), MAX_U64_BASE62_VAL);
}

#[test]
fn test_base62_u64_overflow_and_errors() {
    let mut buf = [0u8; 8];

    // Value exceeding 62^8 - 1 in encode_u64_into
    assert_eq!(
        base62::encode_u64_into(MAX_U64_BASE62_VAL + 1, &mut buf),
        Err(BufferError::TooSmall {
            required: 8,
            provided: 8,
        })
    );

    // Empty string
    assert_eq!(base62::decode_u64(""), Err(Base62Error::Empty));

    // Overflows limit: 9 chars
    assert_eq!(base62::decode_u64("100000000"), Err(Base62Error::Overflow));

    // Overflow u64::MAX during accumulation
    assert_eq!(
        base62::decode_u64("zzzzzzzzzzzzzzzzzzz"),
        Err(Base62Error::Overflow)
    );

    // Invalid character
    assert_eq!(
        base62::decode_u64("12#4"),
        Err(Base62Error::InvalidChar(b'#'))
    );
}

#[test]
fn test_base62_u64_fixed_width() {
    let mut buf = [0u8; 8];

    for target_len in 2..=8 {
        let written = base62::encode_u64_fixed_into(42, target_len, &mut buf).unwrap();
        assert_eq!(written, target_len);
        for &b in &buf[..target_len - 1] {
            assert_eq!(b, b'0');
        }
        assert_eq!(buf[target_len - 1], CHARSET[42]);
    }

    // Invalid lengths
    assert!(base62::encode_u64_fixed_into(42, 1, &mut buf).is_err());
    assert!(base62::encode_u64_fixed_into(42, 9, &mut buf).is_err());

    // Buffer smaller than required fixed_len
    let mut small_buf = [0u8; 3];
    assert_eq!(
        base62::encode_u64_fixed_into(42, 5, &mut small_buf),
        Err(BufferError::TooSmall {
            required: 5,
            provided: 3
        })
    );
}

#[test]
fn test_base62_binary_all_lengths_roundtrip() {
    let test_vectors: &[&[u8]] = &[
        &[0x42],
        &[0x01, 0x02],
        &[0xAA, 0xBB, 0xCC],
        &[0x12, 0x34, 0x56, 0x78],
        &[0xFF, 0xEE, 0xDD, 0xCC, 0xBB],
        &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB],
    ];

    for &vec in test_vectors {
        let mut enc = [0u8; 8];
        let written = base62::encode_bytes_into(vec, &mut enc).unwrap();
        assert_eq!(written, base62::encoded_bytes_len(vec.len()));

        let s = std::str::from_utf8(&enc[..written]).unwrap();
        let mut dec = [0u8; 6];
        let dec_len = base62::decode_bytes_into(s, &mut dec).unwrap();
        assert_eq!(dec_len, vec.len());
        assert_eq!(&dec[..dec_len], vec);
    }
}

#[test]
fn test_base62_binary_leading_zeros_all_lengths() {
    let zeros_vectors: &[&[u8]] = &[
        &[0x00],
        &[0x00, 0x00],
        &[0x00, 0x00, 0x00],
        &[0x00, 0x00, 0x00, 0x00],
        &[0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    ];

    for &vec in zeros_vectors {
        let mut enc = [0u8; 8];
        let written = base62::encode_bytes_into(vec, &mut enc).unwrap();
        let s = std::str::from_utf8(&enc[..written]).unwrap();
        let mut dec = [0u8; 6];
        let dec_len = base62::decode_bytes_into(s, &mut dec).unwrap();
        assert_eq!(dec_len, vec.len());
        assert_eq!(&dec[..dec_len], vec);
    }
}

#[test]
fn test_base62_binary_errors() {
    let mut buf = [0u8; 8];

    // Empty slice
    assert_eq!(base62::encode_bytes_into(&[], &mut buf).unwrap(), 0);

    // Length > 6
    assert!(base62::encode_bytes_into(&[1; 7], &mut buf).is_err());

    // Numerical overflow for 6 bytes
    assert!(base62::encode_bytes_into(&[0xFF; 6], &mut buf).is_err());

    // Decode buffer too small: 5 Base62 characters decode to 3 bytes, but buffer only has 2
    let mut small = [0u8; 2];
    assert!(base62::decode_bytes_into("ZZZZZ", &mut small).is_err());
}

// =============================================================================
// 2. Manifest Bitfield & Metadata Tests
// =============================================================================

#[test]
fn test_manifest_block_count_and_types_roundtrip() {
    let all_types = [
        BlockType::TplText,
        BlockType::Rand,
        BlockType::Time,
        BlockType::Parity,
        BlockType::Auth,
        BlockType::Blob,
        BlockType::Cipher,
        BlockType::InstText,
    ];

    for count in 1..=8 {
        let mut types = [BlockType::TplText; 8];
        types[..count].copy_from_slice(&all_types[..count]);

        let manifest = Manifest::new(count as u8, types);
        assert_eq!(manifest.block_count(), count as u8);
        assert_eq!(manifest.block_types(), &types[..count]);

        for i in 0..count {
            assert_eq!(manifest.block_type(i), Some(types[i]));
            assert!(manifest.contains(types[i]));
        }
        assert_eq!(manifest.block_type(count), None);

        // Roundtrip via u64
        let u = manifest.to_u64();
        let from_u = Manifest::from_u64(u).unwrap();
        assert_eq!(manifest, from_u);

        // Roundtrip via string
        let s = manifest.to_string();
        let parsed = Manifest::decode(&s).unwrap();
        assert_eq!(manifest, parsed);
    }
}

#[test]
fn test_manifest_invalid_counts_and_extraneous_bits() {
    // Declared count 0
    assert_eq!(
        Manifest::from_u64(0),
        Err(ManifestError::InvalidBlockCount {
            declared: 0,
            max: 8
        })
    );

    // Declared count 9
    assert_eq!(
        Manifest::from_u64(9),
        Err(ManifestError::InvalidBlockCount {
            declared: 9,
            max: 8
        })
    );

    // Extraneous bits: declared count = 1 (uses bits 0..7), set bit 8
    let val_with_extra = 0x01 | (0x01 << 8);
    assert_eq!(
        Manifest::from_u64(val_with_extra),
        Err(ManifestError::ExtraneousBits)
    );

    // String length limits
    assert_eq!(Manifest::decode("0"), Err(ManifestError::InvalidLength(1)));
    assert_eq!(
        Manifest::decode("123456789"),
        Err(ManifestError::InvalidLength(9))
    );
}

#[test]
fn test_block_type_properties() {
    for nibble in 0..=15 {
        let bt = BlockType::from_u8(nibble);
        assert_eq!(bt.as_u8(), nibble);

        match nibble {
            0..=7 => {
                assert!(bt.is_standard());
                assert!(!bt.is_custom());
            }
            8..=14 => {
                assert!(!bt.is_standard());
                assert!(bt.is_custom());
            }
            15 => {
                assert!(!bt.is_standard());
                assert!(!bt.is_custom());
                assert_eq!(bt, BlockType::Escape);
            }
            _ => unreachable!(),
        }
    }

    assert_eq!(BlockType::TplText.to_string(), "TplText");
    assert_eq!(BlockType::Custom(9).to_string(), "Custom(9)");
    assert_eq!(BlockType::Escape.to_string(), "Escape");
}

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

// =============================================================================
// 4. Builder Lifecycle & Hook Tests
// =============================================================================

#[test]
fn test_builder_empty() {
    assert_eq!(Seid::builder().build(), Err(BuilderError::Empty));
}

#[test]
fn test_builder_inspection_methods() {
    let mut builder = Seid::builder();
    assert!(builder.is_empty());
    assert_eq!(builder.len(), 0);
    assert_eq!(builder.current_blocks().len(), 0);

    builder = builder.block(Tpl::new("usr").unwrap()).unwrap();
    assert!(!builder.is_empty());
    assert_eq!(builder.len(), 1);
    assert_eq!(builder.current_blocks()[0].as_str(), "usr");
}

#[test]
fn test_builder_block_with_context() {
    let id = Seid::builder()
        .block(Tpl::new("alpha").unwrap())
        .unwrap()
        .block_with(|preceding| {
            assert_eq!(preceding.len(), 1);
            assert_eq!(preceding[0].as_str(), "alpha");
            Tpl::new("beta").map_err(BuilderError::Block)
        })
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(id.block_count(), 2);
    assert_eq!(id[0].as_str(), "alpha");
    assert_eq!(id[1].as_str(), "beta");
}

#[test]
fn test_builder_hook_ordering_parity_before_auth() {
    let key = [0x77u8; 32];

    // Place Parity BEFORE Auth to verify two-pass build resolution:
    // Pass 1 seals Auth, Pass 2 computes Parity over finalized Auth
    let id = Seid::builder()
        .block(Parity::auto()) // Index 0: Parity
        .unwrap()
        .block(Auth::with_key(key)) // Index 1: Auth
        .unwrap()
        .block(Tpl::new("data").unwrap()) // Index 2: Tpl
        .unwrap()
        .build()
        .unwrap();

    assert!(id.is_fully_signed());
    assert!(id.verify_signature_at(1, &key).unwrap());
    assert!(id.check_parity().unwrap());
}

// =============================================================================
// 5. Standard Block Operations & Invariants
// =============================================================================

#[test]
fn test_inline_str_traits_and_boundaries() {
    // Boundary lengths
    assert!(InlineStr::try_new("a").is_err()); // 1 char
    assert!(InlineStr::try_new("123456789").is_err()); // 9 chars
    assert!(InlineStr::try_new("invalid_").is_err()); // non-base62

    let s1 = InlineStr::try_new("user").unwrap();
    let s2 = InlineStr::try_new("user").unwrap();
    let s3 = InlineStr::try_new("zone").unwrap();

    assert_eq!(s1, s2);
    assert!(s1 < s3);
    assert_eq!(s1.as_str(), "user");
    assert_eq!(s1.as_bytes(), b"user");
    assert_eq!(s1.len(), 4);
    assert!(!s1.is_empty());

    // Comparison with &str and str
    assert_eq!(s1, "user");
    assert_eq!("user", s1);
    assert_ne!(s1, "other");
    assert_eq!(format!("{}", s1), "user");
    assert_eq!(format!("{:?}", s1), "\"user\"");
}

#[test]
fn test_time_dual_block_resolution() {
    // 0 Time blocks
    let id0 = Seid::builder()
        .block(Tpl::new("usr").unwrap())
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(id0.timestamp(), None);

    // 1 Time block (coarse milliseconds)
    let id1 = Seid::builder()
        .block(Time::new(123456).unwrap())
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(id1.timestamp(), Some(123456));

    // 2 Time blocks: coarse * 1_000_000_000 + fine
    let id2 = Seid::builder()
        .block(Time::new(5).unwrap())
        .unwrap()
        .block(Time::new(42).unwrap())
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(id2.timestamp(), Some(5_000_000_042));
}

#[test]
fn test_rand_bounds_and_determinism() {
    assert!(Rand::new(MAX_U64_BASE62_VAL).is_ok());
    assert!(Rand::new(MAX_U64_BASE62_VAL + 1).is_err());

    let r1 = Rand::from_seed(42);
    let r2 = Rand::from_seed(42);
    assert_eq!(r1, r2);
    assert!(r1.value() <= MAX_U64_BASE62_VAL);

    let fast = Rand::fast();
    assert!(fast.value() <= MAX_U64_BASE62_VAL);
}

#[test]
fn test_auth_parity_exclusion_invariance() {
    let key = [0x11u8; 32];

    let id = Seid::builder()
        .block(Tpl::new("secure").unwrap())
        .unwrap()
        .block(Auth::with_key(key))
        .unwrap()
        .block(Parity::auto())
        .unwrap()
        .build()
        .unwrap();

    assert!(id.verify_signature(&key).unwrap());
    assert!(id.check_parity().unwrap());

    // Tampering with the Parity block does NOT invalidate the Auth signature
    // because Parity blocks are intentionally excluded from envelope authentication!
    let new_parity_token = InlineStr::try_new("999999").unwrap();
    let mut new_block_array = [RawBlock::new(BlockType::TplText, new_parity_token); 8];
    new_block_array[..3].copy_from_slice(id.blocks());
    new_block_array[2] = RawBlock::new(BlockType::Parity, new_parity_token);

    let id_tampered_parity = Seid::from_raw_parts(3, new_block_array);
    assert!(id_tampered_parity.verify_signature(&key).unwrap());
    assert!(!id_tampered_parity.check_parity().unwrap());
}

#[test]
fn test_multi_auth_independent_keys() {
    let key_a = [0xAAu8; 32];
    let key_b = [0xBBu8; 32];

    let unsigned = Seid::builder()
        .block(Auth::unsigned()) // Block 0: signed by key_a
        .unwrap()
        .block(Tpl::new("tx").unwrap()) // Block 1
        .unwrap()
        .block(Auth::unsigned()) // Block 2: signed by key_b
        .unwrap()
        .build()
        .unwrap();

    assert!(!unsigned.is_fully_signed());

    let signed_a = unsigned.sign_at(0, &key_a).unwrap();
    assert!(!signed_a.is_fully_signed());

    let signed_ab = signed_a.sign_at(2, &key_b).unwrap();
    assert!(signed_ab.is_fully_signed());

    // Verify independent key bindings
    assert!(signed_ab.verify_signature_at(0, &key_a).unwrap());
    assert!(!signed_ab.verify_signature_at(0, &key_b).unwrap());

    assert!(signed_ab.verify_signature_at(2, &key_b).unwrap());
    assert!(!signed_ab.verify_signature_at(2, &key_a).unwrap());
}

#[test]
fn test_multi_parity_symbols() {
    let id = Seid::builder()
        .block(Tpl::new("record").unwrap())
        .unwrap()
        .block(Inst::new("prod").unwrap())
        .unwrap()
        .block(Parity::auto()) // Symbol 0
        .unwrap()
        .block(Parity::auto()) // Symbol 1
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(id.block_count(), 4);
    assert_ne!(
        id[2].as_str(),
        id[3].as_str(),
        "Symbols must use different seeds"
    );
    assert!(id.check_parity().unwrap());
}

#[test]
fn test_cipher_keystream_chunk_isolation() {
    let key = [0x88u8; 32];
    let plaintext = b"SAME";

    // Encrypt identical text at chunk 0 vs chunk 1
    let c0 = Cipher::encrypt_chunk(plaintext, &key, 0).unwrap();
    let c1 = Cipher::encrypt_chunk(plaintext, &key, 1).unwrap();

    assert_ne!(
        c0.as_bytes(),
        c1.as_bytes(),
        "Keystream must be unique per chunk index"
    );

    let id = Seid::builder()
        .block(c0)
        .unwrap()
        .block(c1)
        .unwrap()
        .build()
        .unwrap();

    let mut out = [0u8; 8];
    let len = id.decrypt(&key, &mut out).unwrap();
    assert_eq!(len, 8);
    assert_eq!(&out[..4], plaintext);
    assert_eq!(&out[4..8], plaintext);
}

#[test]
fn test_cipher_errors() {
    let key = [0x12u8; 32];

    // Decrypt on an ID with no Cipher block
    let id_no_cipher = Seid::builder()
        .block(Tpl::new("usr").unwrap())
        .unwrap()
        .build()
        .unwrap();
    let mut out = [0u8; 10];
    assert_eq!(
        id_no_cipher.decrypt(&key, &mut out),
        Err(CryptoError::NoCipherBlock)
    );

    // Buffer too small for decryption
    let c = Cipher::encrypt(b"longpayload", &key);
    assert!(c.is_err(), "Exceeds 6 bytes limit");

    let valid_c = Cipher::encrypt(b"1234", &key).unwrap();
    let id = Seid::builder().block(valid_c).unwrap().build().unwrap();
    let mut tiny_buf = [0u8; 2];
    assert_eq!(
        id.decrypt(&key, &mut tiny_buf),
        Err(CryptoError::Buffer(BufferError::TooSmall {
            required: 4,
            provided: 2
        }))
    );
}

// =============================================================================
// 6. Extraction, Unpacking, and Query Operations
// =============================================================================

#[test]
fn test_unpack_all_tuple_sizes_1_to_8() {
    let b1 = Tpl::new("b1").unwrap();
    let b2 = Inst::new("b2").unwrap();
    let b3 = Time::new(3).unwrap();
    let b4 = Rand::new(4).unwrap();
    let b5 = Blob::from_slice(&[5]).unwrap();
    let b6 = Tpl::new("b6").unwrap();
    let b7 = Inst::new("b7").unwrap();
    let b8 = Rand::new(8).unwrap();

    // 1-tuple
    let id1 = Seid::builder().block(b1).unwrap().build().unwrap();
    let (u1,): (Tpl,) = id1.unpack().unwrap();
    assert_eq!(u1, b1);

    // 2-tuple
    let id2 = Seid::builder()
        .block(b1)
        .unwrap()
        .block(b2)
        .unwrap()
        .build()
        .unwrap();
    let (u1, u2): (Tpl, Inst) = id2.unpack().unwrap();
    assert_eq!((u1, u2), (b1, b2));

    // 3-tuple
    let id3 = Seid::builder()
        .block(b1)
        .unwrap()
        .block(b2)
        .unwrap()
        .block(b3)
        .unwrap()
        .build()
        .unwrap();
    let (u1, u2, u3): (Tpl, Inst, Time) = id3.unpack().unwrap();
    assert_eq!((u1, u2, u3), (b1, b2, b3));

    // 4-tuple
    let id4 = Seid::builder()
        .block(b1)
        .unwrap()
        .block(b2)
        .unwrap()
        .block(b3)
        .unwrap()
        .block(b4)
        .unwrap()
        .build()
        .unwrap();
    let (u1, u2, u3, u4): (Tpl, Inst, Time, Rand) = id4.unpack().unwrap();
    assert_eq!((u1, u2, u3, u4), (b1, b2, b3, b4));

    // 5-tuple
    let id5 = Seid::builder()
        .block(b1)
        .unwrap()
        .block(b2)
        .unwrap()
        .block(b3)
        .unwrap()
        .block(b4)
        .unwrap()
        .block(b5)
        .unwrap()
        .build()
        .unwrap();
    let (u1, u2, u3, u4, u5): (Tpl, Inst, Time, Rand, Blob) = id5.unpack().unwrap();
    assert_eq!((u1, u2, u3, u4, u5), (b1, b2, b3, b4, b5));

    // 6-tuple
    let id6 = Seid::builder()
        .block(b1)
        .unwrap()
        .block(b2)
        .unwrap()
        .block(b3)
        .unwrap()
        .block(b4)
        .unwrap()
        .block(b5)
        .unwrap()
        .block(b6)
        .unwrap()
        .build()
        .unwrap();
    let (u1, u2, u3, u4, u5, u6): (Tpl, Inst, Time, Rand, Blob, Tpl) = id6.unpack().unwrap();
    assert_eq!((u1, u2, u3, u4, u5, u6), (b1, b2, b3, b4, b5, b6));

    // 7-tuple
    let id7 = Seid::builder()
        .block(b1)
        .unwrap()
        .block(b2)
        .unwrap()
        .block(b3)
        .unwrap()
        .block(b4)
        .unwrap()
        .block(b5)
        .unwrap()
        .block(b6)
        .unwrap()
        .block(b7)
        .unwrap()
        .build()
        .unwrap();
    let (u1, u2, u3, u4, u5, u6, u7): (Tpl, Inst, Time, Rand, Blob, Tpl, Inst) =
        id7.unpack().unwrap();
    assert_eq!((u1, u2, u3, u4, u5, u6, u7), (b1, b2, b3, b4, b5, b6, b7));

    // 8-tuple
    let id8 = Seid::builder()
        .block(b1)
        .unwrap()
        .block(b2)
        .unwrap()
        .block(b3)
        .unwrap()
        .block(b4)
        .unwrap()
        .block(b5)
        .unwrap()
        .block(b6)
        .unwrap()
        .block(b7)
        .unwrap()
        .block(b8)
        .unwrap()
        .build()
        .unwrap();
    let (u1, u2, u3, u4, u5, u6, u7, u8): (Tpl, Inst, Time, Rand, Blob, Tpl, Inst, Rand) =
        id8.unpack().unwrap();
    assert_eq!(
        (u1, u2, u3, u4, u5, u6, u7, u8),
        (b1, b2, b3, b4, b5, b6, b7, b8)
    );
}

#[test]
fn test_unpack_primitive_types() {
    let id = Seid::builder()
        .block(Tpl::new("api").unwrap())
        .unwrap()
        .block(Time::new(500).unwrap())
        .unwrap()
        .build()
        .unwrap();

    let (s, val): (&str, u64) = id.unpack().unwrap();
    assert_eq!(s, "api");
    assert_eq!(val, 500);

    let (token, bt): (InlineStr, BlockType) = id.unpack().unwrap();
    assert_eq!(token.as_str(), "api");
    assert_eq!(bt, BlockType::Time);
}

#[test]
fn test_unpack_error_handling() {
    let id = Seid::builder()
        .block(Tpl::new("doc").unwrap())
        .unwrap()
        .build()
        .unwrap();

    // Count mismatch: expected 2, actual 1
    let err_count = id.unpack::<(Tpl, Tpl)>();
    assert_eq!(
        err_count,
        Err(ExtractError::CountMismatch {
            expected: 2,
            actual: 1
        })
    );

    // Type mismatch: expected Time, actual TplText
    let err_type = id.unpack::<(Time,)>();
    assert!(matches!(
        err_type,
        Err(ExtractError::Block {
            index: 0,
            source: BlockError::TypeMismatch {
                expected: BlockType::Time,
                actual: BlockType::TplText,
            }
        })
    ));
}

#[test]
fn test_seid_query_methods_exhaustive() {
    let id = Seid::builder()
        .block(Tpl::new("org").unwrap())
        .unwrap()
        .block(Inst::new("eu1").unwrap())
        .unwrap()
        .block(Tpl::new("repo").unwrap())
        .unwrap()
        .block(Time::new(42).unwrap())
        .unwrap()
        .build()
        .unwrap();

    // get_as out of bounds
    assert_eq!(id.get_as::<Tpl>(4), Err(ExtractError::OutOfBounds(4)));

    // first_of: multiple exist (returns first)
    let first_tpl = id.first_of::<Tpl>().unwrap().unwrap();
    assert_eq!(first_tpl.as_str(), "org");

    // first_of: absent
    let rand = id.first_of::<Rand>().unwrap();
    assert_eq!(rand, None);

    // template_path: yields only TplText blocks
    let path: Vec<&str> = id.template_path().collect();
    assert_eq!(path, vec!["org", "repo"]);

    // prefix matching
    assert!(id.starts_with("org"));
    assert!(!id.starts_with("eu1"));
    assert!(id.matches_prefix(&["org", "eu1"]));
    assert!(!id.matches_prefix(&["org", "us1"]));
    assert!(!id.matches_prefix(&["org", "eu1", "repo", "00000042", "extra"]));
}

#[test]
fn test_seid_ordering_and_hash() {
    let id_a = Seid::builder()
        .block(Tpl::new("aaa").unwrap())
        .unwrap()
        .build()
        .unwrap();
    let id_b = Seid::builder()
        .block(Tpl::new("bbb").unwrap())
        .unwrap()
        .build()
        .unwrap();
    let id_a_long = Seid::builder()
        .block(Tpl::new("aaa").unwrap())
        .unwrap()
        .block(Tpl::new("sub").unwrap())
        .unwrap()
        .build()
        .unwrap();

    assert!(id_a < id_b);
    assert!(
        id_a < id_a_long,
        "Shorter identifier with common prefix sorts first"
    );

    let mut set = HashSet::new();
    set.insert(id_a);
    set.insert(id_b);
    assert!(set.contains(&id_a));
    assert_eq!(set.len(), 2);

    let mut btree = BTreeSet::new();
    btree.insert(id_b);
    btree.insert(id_a);
    let ordered: Vec<_> = btree.into_iter().collect();
    assert_eq!(ordered, vec![id_a, id_b]);
}

#[test]
fn test_seid_traits_and_conversions() {
    let id = Seid::builder()
        .block(Tpl::new("test").unwrap())
        .unwrap()
        .build()
        .unwrap();

    // FromStr and TryFrom
    let s = id.to_encoded();
    assert_eq!(Seid::from_str(s.as_str()).unwrap(), id);
    assert_eq!(Seid::try_from(s.as_str()).unwrap(), id);

    // IntoIterator
    let block_names: Vec<&str> = (&id).into_iter().map(|b| b.as_str()).collect();
    assert_eq!(block_names, vec!["test"]);

    // EncodedSeid traits
    assert_eq!(s.len(), id.encoded_len());
    assert!(!s.is_empty());
    assert_eq!(s.as_bytes(), s.as_str().as_bytes());
    assert_eq!(format!("{}", s), s.as_str());
    assert_eq!(format!("{:?}", s), format!("\"{}\"", s.as_str()));
    assert_eq!(s, s);
}

#[test]
#[should_panic(expected = "Seid block index out of bounds")]
fn test_seid_index_out_of_bounds() {
    let id = Seid::builder()
        .block(Tpl::new("usr").unwrap())
        .unwrap()
        .build()
        .unwrap();
    let _ = id[1];
}

// =============================================================================
// 7. Security Invariance & Parity Mutation Tests
// =============================================================================

#[test]
fn test_bit_flip_parity_detection_exhaustive() {
    let id = Seid::builder()
        .block(Tpl::new("usr").unwrap())
        .unwrap()
        .block(Inst::new("eu1").unwrap())
        .unwrap()
        .block(Time::new(123456).unwrap())
        .unwrap()
        .block(Rand::new(654321).unwrap())
        .unwrap()
        .block(Parity::auto())
        .unwrap()
        .build()
        .unwrap();

    assert!(id.check_parity().unwrap());

    let encoded = id.to_encoded();
    let raw = encoded.as_str();

    // Flip every Base62 character one by one and assert check_parity returns false
    for (i, ch) in raw.char_indices() {
        if ch == ':' {
            continue;
        }
        let replacement = if ch == '0' { '1' } else { '0' };
        let mut tampered = raw.to_string();
        tampered.replace_range(i..i + 1, &replacement.to_string());

        if let Ok(tampered_id) = Seid::parse(&tampered) {
            let parity_ok = tampered_id.check_parity().unwrap_or(false);
            assert!(
                !parity_ok,
                "Parity failed to catch single-character corruption at index {}: {}",
                i, tampered
            );
        }
    }
}

#[test]
fn test_fuzz_random_garbage_inputs_never_panic() {
    let garbage_inputs = &[
        "🦀::🦀::🦀",
        "!!!::@@@::###",
        "usr::ord::\0\0::manifest",
        "a::b::c::d::e::f::g::h::i::j::k",
        "::::::::::::::::::",
        "..................",
        "usr..ord..mani",
        "usr::ord..mani",
        "   ::   ::   ",
        "\n\r::\t::manifest",
    ];

    for &input in garbage_inputs {
        let result = Seid::parse(input);
        assert!(
            result.is_err(),
            "Garbage input '{}' should fail gracefully",
            input
        );
    }
}

// =============================================================================
// 8. Original Regressions & Feature Tests
// =============================================================================

#[test]
fn test_builder_and_roundtrip() {
    let id = Seid::builder()
        .block(Tpl::new("usr").unwrap())
        .unwrap()
        .block(Inst::new("eu1").unwrap())
        .unwrap()
        .block(Time::new(123456789).unwrap())
        .unwrap()
        .block(Rand::new(9999).unwrap())
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(id.block_count(), 4);
    assert_eq!(id[0].as_str(), "usr");
    assert_eq!(id[1].as_str(), "eu1");

    let encoded = id.to_encoded();
    let parsed = Seid::parse(encoded.as_str()).unwrap();
    assert_eq!(id, parsed);
}

#[test]
fn test_custom_block_extension() {
    let id = Seid::builder()
        .block(Tpl::new("dev").unwrap())
        .unwrap()
        .block(GeoCluster(888))
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(id.block_count(), 2);
    assert_eq!(id[1].kind(), BlockType::Custom(8));

    let geo: GeoCluster = id.get_as(1).unwrap();
    assert_eq!(geo.0, 888);

    let s = id.to_encoded();
    let reparsed = Seid::parse(s.as_str()).unwrap();
    assert_eq!(reparsed[1].kind(), BlockType::Custom(8));
    let reparsed_geo: GeoCluster = reparsed.get_as(1).unwrap();
    assert_eq!(reparsed_geo.0, 888);
}

#[test]
fn test_parity_computation_and_verification() {
    let id = Seid::builder()
        .block(Tpl::new("order").unwrap())
        .unwrap()
        .block(Inst::new("us2").unwrap())
        .unwrap()
        .block(Rand::new(424242).unwrap())
        .unwrap()
        .block_with(|blocks| Ok(Parity::compute(blocks)))
        .unwrap()
        .build()
        .unwrap();

    assert!(id.contains_type(BlockType::Parity));
    assert!(id.check_parity().unwrap());

    let s = id.to_encoded();
    let mut tampered = s.as_str().to_string();
    tampered.replace_range(0..1, "x");
    let tampered_id = Seid::parse(&tampered).unwrap();
    assert!(!tampered_id.check_parity().unwrap());
}

#[test]
fn test_cryptographic_auth_sign_and_verify() {
    let secret_key = [7u8; 32];
    let wrong_key = [9u8; 32];

    let id = Seid::builder()
        .block(Tpl::new("doc").unwrap())
        .unwrap()
        .block(Inst::new("prod").unwrap())
        .unwrap()
        .block_with(|blocks| Ok(Auth::sign(blocks, &secret_key)))
        .unwrap()
        .build()
        .unwrap();

    assert!(id.verify_signature(&secret_key).unwrap());
    assert!(!id.verify_signature(&wrong_key).unwrap());

    let s = id.to_encoded();
    let mut tampered = s.as_str().to_string();
    tampered.replace_range(0..1, "z");
    let tampered_id = Seid::parse(&tampered).unwrap();
    assert!(!tampered_id.verify_signature(&secret_key).unwrap());
}

#[test]
fn test_cipher_encrypt_and_decrypt() {
    let key = [0x42u8; 32];
    let payload = b"secret";

    let cipher_block = Cipher::encrypt(payload, &key).unwrap();

    let id = Seid::builder()
        .block(Tpl::new("vault").unwrap())
        .unwrap()
        .block(cipher_block)
        .unwrap()
        .build()
        .unwrap();

    let mut decrypted = [0u8; 6];
    let len = id.decrypt(&key, &mut decrypted).unwrap();
    assert_eq!(&decrypted[..len], payload);
}

#[test]
fn test_schema_matching() {
    let id = Seid::builder()
        .block(Tpl::new("usr").unwrap())
        .unwrap()
        .block(Inst::new("eu1").unwrap())
        .unwrap()
        .block(Time::new(100).unwrap())
        .unwrap()
        .block(Rand::new(200).unwrap())
        .unwrap()
        .build()
        .unwrap();

    const USER_SCHEMA: &[BlockType] = &[
        BlockType::TplText,
        BlockType::InstText,
        BlockType::Time,
        BlockType::Rand,
    ];

    const OTHER_SCHEMA: &[BlockType] = &[BlockType::TplText, BlockType::Time, BlockType::Rand];

    assert!(id.matches_schema(USER_SCHEMA));
    assert!(!id.matches_schema(OTHER_SCHEMA));
}

#[test]
fn test_prefix_and_routing() {
    let id = Seid::builder()
        .block(Tpl::new("billing").unwrap())
        .unwrap()
        .block(Tpl::new("invoices").unwrap())
        .unwrap()
        .block(Inst::new("us").unwrap())
        .unwrap()
        .build()
        .unwrap();

    assert!(id.starts_with("billing"));
    assert!(id.matches_prefix(&["billing", "invoices"]));
    assert!(!id.matches_prefix(&["billing", "orders"]));

    let path: Vec<&str> = id.template_path().collect();
    assert_eq!(path, vec!["billing", "invoices"]);
}

#[test]
fn test_capacity_exceeded() {
    let mut builder = Seid::builder();
    for _ in 0..8 {
        builder = builder.block(Tpl::new("ab").unwrap()).unwrap();
    }
    assert!(builder.block(Tpl::new("ab").unwrap()).is_err());
}

#[test]
fn test_exact_limit_payload_bounds() {
    let five_bytes = [0xFFu8; 5];
    let blob5 = Blob::from_slice(&five_bytes).unwrap();
    let id = Seid::builder().block(blob5).unwrap().build().unwrap();
    let reparsed = Seid::parse(id.to_encoded().as_str()).unwrap();
    let extracted: Blob = reparsed.get_as(0).unwrap();
    assert_eq!(extracted.as_bytes(), &five_bytes);

    let valid_6_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let blob6 = Blob::from_slice(&valid_6_bytes).unwrap();
    let id6 = Seid::builder().block(blob6).unwrap().build().unwrap();
    let reparsed6 = Seid::parse(id6.to_encoded().as_str()).unwrap();
    let extracted6: Blob = reparsed6.get_as(0).unwrap();
    assert_eq!(extracted6.as_bytes(), &valid_6_bytes);

    let overflowing_6_bytes = [0xFFu8; 6];
    assert!(Blob::from_slice(&overflowing_6_bytes).is_err());
}

#[test]
fn test_zero_and_small_values_supported() {
    let id = Seid::builder()
        .block(Time::new(0).unwrap())
        .unwrap()
        .block(Rand::new(0).unwrap())
        .unwrap()
        .block(Blob::from_slice(&[7]).unwrap())
        .unwrap()
        .build()
        .unwrap();

    let reparsed = Seid::parse(id.to_encoded().as_str()).unwrap();
    assert_eq!(reparsed.get_as::<Time>(0).unwrap().value(), 0);
    assert_eq!(reparsed.get_as::<Rand>(1).unwrap().value(), 0);
    let blob: Blob = reparsed.get_as(2).unwrap();
    assert_eq!(blob.as_bytes(), &[7]);
}

#[test]
fn test_blob_preserves_leading_zeros() {
    let original = [0x00, 0x12, 0x34];
    let blob = Blob::from_slice(&original).unwrap();

    let id = Seid::builder().block(blob).unwrap().build().unwrap();
    let reparsed = Seid::parse(id.to_encoded().as_str()).unwrap();
    let extracted: Blob = reparsed.get_as(0).unwrap();
    assert_eq!(extracted.as_bytes(), &original[..]);
}

#[test]
fn test_multi_cipher_blocks_decrypt_cleanly() {
    let key = [0x55u8; 32];
    let chunk1 = b"AAAA";
    let chunk2 = b"BBBB";

    let c1 = Cipher::encrypt_chunk(chunk1, &key, 0).unwrap();
    let c2 = Cipher::encrypt_chunk(chunk2, &key, 1).unwrap();

    let id = Seid::builder()
        .block(c1)
        .unwrap()
        .block(c2)
        .unwrap()
        .build()
        .unwrap();

    let mut decrypted = [0u8; 8];
    let len = id.decrypt(&key, &mut decrypted).unwrap();
    assert_eq!(len, 8);
    assert_eq!(&decrypted[..4], chunk1);
    assert_eq!(&decrypted[4..8], chunk2);
}

#[test]
fn test_manifest_block_type_tampering_detected() {
    let id = Seid::builder()
        .block(Tpl::new("usr").unwrap())
        .unwrap()
        .block_with(|blocks| Ok(Parity::compute(blocks)))
        .unwrap()
        .build()
        .unwrap();

    assert!(id.check_parity().unwrap());

    let mut types = [BlockType::TplText; 8];
    types[0] = BlockType::InstText;
    types[1] = BlockType::Parity;
    let tampered_manifest = seid::Manifest::new(2, types);

    let tampered_raw = format!("usr::{}::{}", id[1].as_str(), tampered_manifest);
    let tampered_id = Seid::parse(&tampered_raw).unwrap();

    assert!(!tampered_id.check_parity().unwrap());
}

#[test]
fn test_chronological_time_sort_order() {
    let id_early = Seid::builder()
        .block(Time::new(3843).unwrap())
        .unwrap()
        .build()
        .unwrap();

    let id_late = Seid::builder()
        .block(Time::new(3844).unwrap())
        .unwrap()
        .build()
        .unwrap();

    assert!(id_early < id_late);
    assert!(id_early.to_encoded().as_str() < id_late.to_encoded().as_str());
}

#[test]
fn test_expand_up_to_8_auth_blocks() {
    let mut builder = Seid::builder();
    for _ in 0..8 {
        builder = builder.block(Auth::unsigned()).unwrap();
    }
    let id = builder.build().unwrap();
    assert_eq!(id.block_count(), 8);
    for i in 0..8 {
        assert_eq!(id[i].kind(), BlockType::Auth);
    }
}

#[test]
fn test_unsigned_auth_block_signed_later_anywhere() {
    let signing_key = [0x33u8; 32];
    let wrong_key = [0x44u8; 32];

    let unsigned_id = Seid::builder()
        .block(Tpl::new("contract").unwrap())
        .unwrap()
        .block(Auth::unsigned())
        .unwrap()
        .block(Inst::new("v2").unwrap())
        .unwrap()
        .build()
        .unwrap();

    assert!(!unsigned_id.is_fully_signed());
    assert!(unsigned_id.verify_signature(&signing_key).is_err());

    let signed_id = unsigned_id.sign_at(1, &signing_key).unwrap();
    assert!(signed_id.is_fully_signed());

    assert!(signed_id.verify_signature(&signing_key).unwrap());
    assert!(!signed_id.verify_signature(&wrong_key).unwrap());

    let raw = signed_id.to_encoded();
    let tampered_raw = raw.as_str().replace("v2", "v3");
    let tampered_id = Seid::parse(&tampered_raw).unwrap();
    assert!(!tampered_id.verify_signature(&signing_key).unwrap());
}

#[test]
fn test_auth_and_parity_with_hooks_anywhere() {
    let key = [0x99u8; 32];

    let id = Seid::builder()
        .block(Auth::with_key(key))
        .unwrap()
        .block(Tpl::new("orders").unwrap())
        .unwrap()
        .block(Parity::auto())
        .unwrap()
        .block(Inst::new("eu1").unwrap())
        .unwrap()
        .build()
        .unwrap();

    assert!(id.is_fully_signed());
    assert!(id.verify_signature(&key).unwrap());
    assert!(id.check_parity().unwrap());

    let raw = id.to_encoded();
    let tampered_raw = raw.as_str().replace("eu1", "eu2");
    let tampered_id = Seid::parse(&tampered_raw).unwrap();

    assert!(!tampered_id.verify_signature(&key).unwrap());
    assert!(!tampered_id.check_parity().unwrap());
}
