use authkestra_mcp::{canonicalize_json, compute_challenge_digest};
use serde_json::json;

#[test]
fn test_jcs_key_sorting_invariance() {
    let obj1 = json!({
        "z": 10,
        "a": 1,
        "m": 5
    });

    let obj2 = json!({
        "a": 1,
        "m": 5,
        "z": 10
    });

    let obj3 = json!({
        "m": 5,
        "z": 10,
        "a": 1
    });

    let canon1 = canonicalize_json(&obj1).expect("canonicalize succeeds");
    let canon2 = canonicalize_json(&obj2).expect("canonicalize succeeds");
    let canon3 = canonicalize_json(&obj3).expect("canonicalize succeeds");

    assert_eq!(canon1, canon2);
    assert_eq!(canon2, canon3);
    assert_eq!(canon1, br#"{"a":1,"m":5,"z":10}"#);
}

#[test]
fn test_jcs_nested_objects_recursive_sorting() {
    let obj1 = json!({
        "outer_b": {
            "inner_y": true,
            "inner_x": false
        },
        "outer_a": {
            "val": 42
        }
    });

    let obj2 = json!({
        "outer_a": {
            "val": 42
        },
        "outer_b": {
            "inner_x": false,
            "inner_y": true
        }
    });

    let canon1 = canonicalize_json(&obj1).unwrap();
    let canon2 = canonicalize_json(&obj2).unwrap();

    assert_eq!(canon1, canon2);
    assert_eq!(
        canon1,
        br#"{"outer_a":{"val":42},"outer_b":{"inner_x":false,"inner_y":true}}"#
    );
}

#[test]
fn test_jcs_array_order_preservation() {
    let arr1 = json!([3, 1, 2]);
    let arr2 = json!([1, 2, 3]);

    let canon1 = canonicalize_json(&arr1).unwrap();
    let canon2 = canonicalize_json(&arr2).unwrap();

    // In RFC 8785 arrays are semantically ordered and must NOT be sorted
    assert_ne!(canon1, canon2);
    assert_eq!(canon1, b"[3,1,2]");
    assert_eq!(canon2, b"[1,2,3]");
}

#[test]
fn test_jcs_nested_objects_inside_arrays() {
    let list1 = json!([
        {"z": 1, "a": 2},
        {"b": 4, "a": 3}
    ]);

    let list2 = json!([
        {"a": 2, "z": 1},
        {"a": 3, "b": 4}
    ]);

    let canon1 = canonicalize_json(&list1).unwrap();
    let canon2 = canonicalize_json(&list2).unwrap();

    assert_eq!(canon1, canon2);
    assert_eq!(canon1, br#"[{"a":2,"z":1},{"a":3,"b":4}]"#);
}

#[test]
fn test_jcs_whitespace_stripping() {
    let raw = r#"{
        "foo":   "bar",
        "nested": {
            "num":   123,
            "bool":  true
        }
    }"#;

    let val: serde_json::Value = serde_json::from_str(raw).unwrap();
    let canon = canonicalize_json(&val).unwrap();

    assert_eq!(canon, br#"{"foo":"bar","nested":{"bool":true,"num":123}}"#);
}

#[test]
fn test_jcs_utf16_code_unit_sorting_with_surrogates() {
    // In RFC 8785 §3.2.3, property keys are sorted by UTF-16 code units.
    // Emoji U+1F600 has UTF-16 surrogates [0xD83D, 0xDE00].
    // Hebrew letter Dalet U+FB33 is [0xFB33].
    // 0xD83D < 0xFB33, so U+1F600 sorts BEFORE U+FB33!
    let obj = json!({
        "\u{fb33}": "hebrew",
        "\u{1f600}": "emoji",
        "a": "latin"
    });

    let canon = canonicalize_json(&obj).unwrap();
    let canon_str = String::from_utf8(canon).unwrap();

    let emoji_idx = canon_str.find('\u{1f600}').unwrap();
    let hebrew_idx = canon_str.find('\u{fb33}').unwrap();
    let latin_idx = canon_str.find('a').unwrap();

    assert!(latin_idx < emoji_idx);
    assert!(
        emoji_idx < hebrew_idx,
        "emoji high surrogate 0xD83D must sort before 0xFB33"
    );
}

#[test]
fn test_challenge_digest_determinism_across_key_orders() {
    let session = "session_xyz";
    let tool = "transfer_funds";
    let expires = 1770000000;

    let args_order_a = json!({
        "recipient": "alice",
        "amount": 50,
        "currency": "USD"
    });

    let args_order_b = json!({
        "currency": "USD",
        "amount": 50,
        "recipient": "alice"
    });

    let jcs_a = canonicalize_json(&args_order_a).unwrap();
    let jcs_b = canonicalize_json(&args_order_b).unwrap();

    let digest_a = compute_challenge_digest(session, tool, &jcs_a, expires);
    let digest_b = compute_challenge_digest(session, tool, &jcs_b, expires);

    assert_eq!(
        digest_a, digest_b,
        "digests must be strictly identical across key permutations"
    );
    assert_eq!(
        digest_a.len(),
        64,
        "SHA-256 hex digest must be 64 characters"
    );
}

#[test]
fn test_challenge_digest_domain_separation() {
    let jcs = canonicalize_json(&json!({"amount": 50})).unwrap();
    let expires = 1770000000;

    let d_base = compute_challenge_digest("sess_1", "tool_a", &jcs, expires);

    // Changing session must alter digest
    let d_sess = compute_challenge_digest("sess_2", "tool_a", &jcs, expires);
    assert_ne!(d_base, d_sess);

    // Changing tool must alter digest
    let d_tool = compute_challenge_digest("sess_1", "tool_b", &jcs, expires);
    assert_ne!(d_base, d_tool);

    // Changing expiry must alter digest
    let d_exp = compute_challenge_digest("sess_1", "tool_a", &jcs, expires + 1);
    assert_ne!(d_base, d_exp);
}
