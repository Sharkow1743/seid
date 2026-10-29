use std::collections::BTreeSet;

use seid::Seid;
use seid::base62;
use seid::block::{Auth, Blob, Block, BlockType, Cipher, Inst, Parity, Rand, Time, Tpl};
use seid::error::{BlockError, BufferError};

// =============================================================================
// Custom External Block Implementation
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
// Tests
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

    // Decode custom block via get_as
    let geo: GeoCluster = id.get_as(1).unwrap();
    assert_eq!(geo.0, 888);

    // Serialization and re-parsing
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

    // Tamper with serialized form and ensure parity verification fails
    let s = id.to_encoded();
    let mut tampered = s.as_str().to_string();
    // Modify one character in the first block
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

    // Tampered payload fails authentication
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
fn test_first_of_and_unpack() {
    let id = Seid::builder()
        .block(Tpl::new("api").unwrap())
        .unwrap()
        .block(Time::new(98765).unwrap())
        .unwrap()
        .build()
        .unwrap();

    // first_of lookup
    let tpl = id.first_of::<Tpl>().unwrap().unwrap();
    assert_eq!(tpl.as_str(), "api");

    let time = id.first_of::<Time>().unwrap().unwrap();
    assert_eq!(time.value(), 98765);

    let rand = id.first_of::<Rand>().unwrap();
    assert!(rand.is_none());

    // unpack tuple
    let (t, tm): (Tpl, Time) = id.unpack().unwrap();
    assert_eq!(t.as_str(), "api");
    assert_eq!(tm.value(), 98765);
}

#[test]
fn test_lexicographical_ordering() {
    let id1 = Seid::builder()
        .block(Tpl::new("aaa").unwrap())
        .unwrap()
        .build()
        .unwrap();

    let id2 = Seid::builder()
        .block(Tpl::new("bbb").unwrap())
        .unwrap()
        .build()
        .unwrap();

    let id3 = Seid::builder()
        .block(Tpl::new("zzz").unwrap())
        .unwrap()
        .build()
        .unwrap();

    assert!(id1 < id2);
    assert!(id2 < id3);

    // Matches string order exactly
    assert!(id1.to_encoded().as_str() < id2.to_encoded().as_str());

    // Usable in BTreeSet
    let mut set = BTreeSet::new();
    set.insert(id2);
    set.insert(id1);
    set.insert(id3);

    let ordered: Vec<_> = set.into_iter().collect();
    assert_eq!(ordered, vec![id1, id2, id3]);
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
    // 9th block should fail
    assert!(builder.block(Tpl::new("ab").unwrap()).is_err());
}

#[test]
fn test_blob_payload() {
    let data = &[1, 2, 3, 4, 5];
    let blob = Blob::from_slice(data).unwrap();

    let id = Seid::builder().block(blob).unwrap().build().unwrap();

    let reparsed = Seid::parse(id.to_encoded().as_str()).unwrap();
    let extracted_blob: Blob = reparsed.get_as(0).unwrap();
    assert_eq!(extracted_blob.as_bytes(), data);
}
