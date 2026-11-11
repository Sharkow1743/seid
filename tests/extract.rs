use std::collections::{BTreeSet, HashSet};
use std::str::FromStr;

use seid::block::{Blob, BlockType, InlineStr, Inst, Rand, Time, Tpl};
use seid::error::{BlockError, ExtractError};
use seid::Seid;

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

