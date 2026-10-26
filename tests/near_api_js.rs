//! Transactions built by near-api-js 5 (the SDK agents use), decoded by the signer.

use base64::Engine as _;
use euthyna_signer::tx::{Action, DecodeError, decode, encode};

const PREPARE: &str = "HQAAAG5hb21pLWFnZW50Lm1hbmRhdGVvcy50ZXN0bmV0AAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHKgAAAAAAAAAcAAAAYWNtZS12YXVsdC5tYW5kYXRlb3MudGVzdG5ldAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJAQAAAAIHAAAAcHJlcGFyZTAAAAB7InJvbGUiOiJwYXltZW50cyIsInJlcXVlc3QiOnsiY2hhaW5faWQiOjg0NTMyfX0AQHoQ81oAAAAAAAAAAAAAAAAAAAAAAAA=";
const TRANSFER: &str = "HQAAAG5hb21pLWFnZW50Lm1hbmRhdGVvcy50ZXN0bmV0AAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHKgAAAAAAAAAcAAAAYWNtZS12YXVsdC5tYW5kYXRlb3MudGVzdG5ldAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJAQAAAAMBAAAAAAAAAAAAAAAAAAAA";
const ADD_KEY: &str = "HQAAAG5hb21pLWFnZW50Lm1hbmRhdGVvcy50ZXN0bmV0AAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHKgAAAAAAAAAdAAAAbmFvbWktYWdlbnQubWFuZGF0ZW9zLnRlc3RuZXQJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQEAAAAFAAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHAAAAAAAAAAAB";

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

#[test]
fn decodes_a_near_api_js_function_call_exactly() {
    let bytes = b64(PREPARE);
    let tx = decode(&bytes).expect("decodes");
    assert_eq!(tx.signer_id, "naomi-agent.mandateos.testnet");
    assert_eq!(tx.receiver_id, "acme-vault.mandateos.testnet");
    assert_eq!(tx.public_key, [7u8; 32]);
    assert_eq!(tx.block_hash, [9u8; 32]);
    assert_eq!(tx.nonce, 42);
    let [Action::FunctionCall(call)] = tx.actions.as_slice() else {
        panic!("one function call")
    };
    assert_eq!(call.method_name, "prepare");
    assert_eq!(call.gas, 100_000_000_000_000);
    assert_eq!(call.deposit, 0);
    assert_eq!(
        String::from_utf8(call.args.clone()).unwrap(),
        r#"{"role":"payments","request":{"chain_id":84532}}"#
    );
    // Our encoder gives back the same bytes, byte for byte.
    assert_eq!(encode(&tx), bytes);
}

#[test]
fn refuses_to_decode_other_actions() {
    assert_eq!(
        decode(&b64(TRANSFER)),
        Err(DecodeError::UnsupportedAction(3))
    );
    assert_eq!(
        decode(&b64(ADD_KEY)),
        Err(DecodeError::UnsupportedAction(5))
    );
}

#[test]
fn refuses_trailing_bytes_and_truncation() {
    let mut bytes = b64(PREPARE);
    bytes.push(0);
    assert_eq!(decode(&bytes), Err(DecodeError::TrailingBytes));
    let bytes = b64(PREPARE);
    for cut in [0, 10, bytes.len() / 2, bytes.len() - 1] {
        assert!(decode(&bytes[..cut]).is_err(), "truncated at {cut}");
    }
}
