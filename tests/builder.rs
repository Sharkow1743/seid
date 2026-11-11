use seid::block::Tpl;
use seid::error::BuilderError;
use seid::Seid;

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
fn test_builder_sugar_helpers() {
    let id = Seid::builder()
        .template("usr")
        .unwrap()
        .instance("eu1")
        .unwrap()
        .rand_fast()
        .unwrap()
        .parity()
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(id.block_count(), 4);
    assert_eq!(id[0].kind(), seid::BlockType::TplText);
    assert_eq!(id[1].kind(), seid::BlockType::InstText);
    assert_eq!(id[2].kind(), seid::BlockType::Rand);
    assert_eq!(id[3].kind(), seid::BlockType::Parity);
    assert!(id.check_parity().unwrap());
}

#[test]
fn test_builder_hook_ordering_parity_before_auth() {
    let key = [0x77u8; 32];

    // Place Parity BEFORE Auth to verify two-pass build resolution:
    // Pass 1 seals Auth, Pass 2 computes Parity over finalized Auth
    let id = Seid::builder()
        .parity() // Index 0: Parity
        .unwrap()
        .auth(key) // Index 1: Auth
        .unwrap()
        .template("data") // Index 2: Tpl
        .unwrap()
        .build()
        .unwrap();

    assert!(id.is_fully_signed());
    assert!(id.verify_signature_at(1, &key).unwrap());
    assert!(id.check_parity().unwrap());
}

