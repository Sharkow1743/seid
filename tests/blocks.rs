use seid::base62::MAX_U64_BASE62_VAL;
use seid::block::{
    Auth, BlockType, Cipher, InlineStr, Inst, Parity, Rand, RawBlock, Time, Tpl,
};
use seid::error::{BufferError, CryptoError};
use seid::Seid;

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
    let id0 = Seid::builder()
        .block(Tpl::new("usr").unwrap())
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(id0.timestamp(), None);

    // Instance 0 only: 2000-01-01 + 1 day + 1 second → epoch nanos
    let id1 = Seid::builder()
        .block(Time::from_datetime_instance0(2000, 2, 1).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let ts1 = id1.timestamp().unwrap();
    assert_eq!(ts1, 86_401_000_000_000);
    let dt1 = id1.datetime().unwrap();
    assert_eq!((dt1.year, dt1.day_of_year, dt1.second), (2000, 2, 1));

    // +1 ms via second Time block
    let id2 = Seid::builder()
        .block(Time::from_datetime_instance0(2000, 2, 1).unwrap())
        .unwrap()
        .block(Time::from_subsecond_tier(2000, 1, 1).unwrap())
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(id2.timestamp(), Some(86_401_001_000_000));
    assert_eq!(id2.datetime().unwrap().millisecond(), 1);
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
        .auth(key)
        .unwrap()
        .parity()
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
    assert!(c.is_err(), "Exceeds 5 bytes limit");

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

