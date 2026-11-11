use seid::block::BlockType;
use seid::error::ManifestError;
use seid::Manifest;

// =============================================================================
// 2. Manifest Bitfield & Metadata Tests
// =============================================================================

#[test]
fn test_manifest_block_count_and_types_roundtrip() {
    let all_types = [
        BlockType::TplText,
        BlockType::InstText,
        BlockType::Time,
        BlockType::Rand,
        BlockType::Parity,
        BlockType::Auth,
        BlockType::Blob,
        BlockType::Cipher,
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
                assert!(!bt.is_unknown());
            }
            8..=14 => {
                assert!(!bt.is_standard());
                assert!(bt.is_unknown());
                assert_eq!(bt, BlockType::Unknown(nibble));
            }
            15 => {
                assert!(!bt.is_standard());
                assert!(!bt.is_unknown());
                assert_eq!(bt, BlockType::Escape);
            }
            _ => unreachable!(),
        }
    }

    assert_eq!(BlockType::TplText.to_string(), "TplText");
    assert_eq!(BlockType::InstText.to_string(), "InstText");
    assert_eq!(BlockType::Unknown(9).to_string(), "Unknown(9)");
    assert_eq!(BlockType::Escape.to_string(), "Escape");
}

