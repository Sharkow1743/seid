use seid::base62::charset::{self, CHARSET};
use seid::base62::{self, MAX_U64_BASE62_VAL};
use seid::error::{Base62Error, BufferError};

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
    ];

    for &vec in test_vectors {
        let mut enc = [0u8; 8];
        let written = base62::encode_bytes_into(vec, &mut enc).unwrap();
        assert_eq!(written, base62::encoded_bytes_len(vec.len()));

        let s = std::str::from_utf8(&enc[..written]).unwrap();
        let mut dec = [0u8; 5];
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
    ];

    for &vec in zeros_vectors {
        let mut enc = [0u8; 8];
        let written = base62::encode_bytes_into(vec, &mut enc).unwrap();
        let s = std::str::from_utf8(&enc[..written]).unwrap();
        let mut dec = [0u8; 5];
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

