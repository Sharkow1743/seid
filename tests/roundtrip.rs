use seid::block::{
    Auth, Blob, BlockType, Cipher, Inst, MAX_BLOCK_LEN, MIN_BLOCK_LEN, Parity, Rand, Time, Tpl,
};
use seid::error::ParseError;
use seid::{InlineStr, RawBlock, Seid};

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
fn test_unknown_tag_roundtrip_lossless() {
    let placeholder =
        unsafe { InlineStr::from_raw_parts([b'0'; MAX_BLOCK_LEN], MIN_BLOCK_LEN as u8) };
    let mut blocks = [RawBlock::new(BlockType::TplText, placeholder); 8];
    blocks[0] = RawBlock::new(BlockType::TplText, InlineStr::try_new("dev").unwrap());
    blocks[1] = RawBlock::new(BlockType::Unknown(8), InlineStr::try_new("ab12").unwrap());

    let id = Seid::from_raw_parts(2, blocks);
    assert_eq!(id[1].kind(), BlockType::Unknown(8));
    assert_eq!(id[1].as_str(), "ab12");

    let encoded = id.to_encoded();
    let reparsed = Seid::parse(encoded.as_str()).unwrap();
    assert_eq!(reparsed.blocks(), id.blocks());
    assert_eq!(reparsed[1].kind(), BlockType::Unknown(8));
    assert_eq!(reparsed[1].as_str(), "ab12");
    assert_eq!(encoded.as_str(), reparsed.to_encoded().as_str());
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
    let payload = b"secr";

    let cipher_block = Cipher::encrypt(payload, &key).unwrap();

    let id = Seid::builder()
        .block(Tpl::new("vault").unwrap())
        .unwrap()
        .block(cipher_block)
        .unwrap()
        .build()
        .unwrap();

    let mut decrypted = [0u8; 5];
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
    // Stay within the 6-char fixed-width Time encoding tier so Base62 order
    // matches numerical order (crossing the 2-char/6-char boundary does not).
    let id_early = Seid::builder()
        .block(Time::new(100_000).unwrap())
        .unwrap()
        .build()
        .unwrap();

    let id_late = Seid::builder()
        .block(Time::new(100_001).unwrap())
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

#[test]
fn test_exact_limit_payload_bounds() {
    // 5-byte payload is 100% supported and infallible
    let five_bytes = [0xFFu8; 5];
    let blob5 = Blob::from_slice(&five_bytes).unwrap();
    let id = Seid::builder().block(blob5).unwrap().build().unwrap();
    let reparsed = Seid::parse(id.to_encoded().as_str()).unwrap();
    let extracted: Blob = reparsed.get_as(0).unwrap();
    assert_eq!(extracted.as_bytes(), &five_bytes);

    // 6-byte payloads are rejected cleanly upfront at compile/type boundary
    let six_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    assert!(Blob::from_slice(&six_bytes).is_err());
}

#[test]
fn test_multi_auth_independent_keys() {
    let key_a = [0xAAu8; 32];
    let key_b = [0xBBu8; 32];

    let unsigned = Seid::builder()
        .block(Auth::unsigned()) // Block 0: key_a slot
        .unwrap()
        .block(Tpl::new("tx").unwrap()) // Block 1: functional payload
        .unwrap()
        .block(Auth::unsigned()) // Block 2: key_b slot
        .unwrap()
        .build()
        .unwrap();

    // Sign slot 0, then sign slot 2
    let signed_a = unsigned.sign_at(0, &key_a).unwrap();
    let signed_ab = signed_a.sign_at(2, &key_b).unwrap();

    assert!(signed_ab.is_fully_signed());

    // Both signatures verify independently and concurrently
    assert!(signed_ab.verify_signature_at(0, &key_a).unwrap());
    assert!(!signed_ab.verify_signature_at(0, &key_b).unwrap());

    assert!(signed_ab.verify_signature_at(2, &key_b).unwrap());
    assert!(!signed_ab.verify_signature_at(2, &key_a).unwrap());
}

#[test]
fn test_nonced_cipher_isolation() {
    let key = [0x42u8; 32];
    let payload = b"data";
    let nonce1 = b"id_1";
    let nonce2 = b"id_2";

    let c1 = Cipher::encrypt_with_nonce(payload, &key, nonce1).unwrap();
    let c2 = Cipher::encrypt_with_nonce(payload, &key, nonce2).unwrap();

    // Keystream difference ensures different ciphertexts for identical plaintext
    assert_ne!(c1.as_bytes(), c2.as_bytes());

    let id1 = Seid::builder().block(c1).unwrap().build().unwrap();
    let mut out = [0u8; 4];
    assert_eq!(id1.decrypt_with_nonce(&key, nonce1, &mut out).unwrap(), 4);
    assert_eq!(&out, payload);

    // Decrypting with wrong nonce fails
    assert_ne!(id1.decrypt_with_nonce(&key, nonce2, &mut out).unwrap(), 0);
    assert_ne!(&out, payload);
}

#[test]
fn test_parser_consecutive_delimiters() {
    assert_eq!(
        Seid::parse("usr:::ord::manifest"),
        Err(ParseError::MalformedDelimiter)
    );
    assert_eq!(
        Seid::parse(":usr::ord::manifest"),
        Err(ParseError::MalformedDelimiter)
    );
    assert_eq!(
        Seid::parse("usr::ord::manifest:"),
        Err(ParseError::MalformedDelimiter)
    );
    assert_eq!(
        Seid::parse("usr:ord::manifest"),
        Err(ParseError::MalformedDelimiter)
    );
}
