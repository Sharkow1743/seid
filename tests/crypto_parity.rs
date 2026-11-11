use seid::block::{Inst, Parity, Rand, Time, Tpl};
use seid::Seid;

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

