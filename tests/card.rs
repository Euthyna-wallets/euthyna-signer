//! The agent's spending card signs market payments, and nothing else.

use std::path::Path;

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use euthyna_signer::server::{Config, State, handle_line};
use euthyna_signer::store::{AgentRecord, CardRecord, DEFAULT_METHODS, Store};
use euthyna_signer::tx::{
    Action, DELEGATE_ACTION_PREFIX, DelegateAction, FunctionCall, encode_delegate,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const AGENT: &str = "larry-09d0b2-agent.euthyna.testnet";
const CARD: &str = "larry-09d0b2-card.euthyna.testnet";
const VAULT: &str = "acme-vault.euthyna.testnet";
const USDC: &str = "3e2210e1184b45b64c8a434c0a7e7b23cc04ea7eb7a6c3c32520d03d4afcb8af";
const SELLER: &str = "megaai.nomos.euthyna.testnet";

fn me() -> u32 {
    unsafe { libc::geteuid() }
}

/// A one-route NEAR RPC: `block` answers height 1000.
async fn rpc() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buffer = vec![0u8; 8192];
                let _ = stream.read(&mut buffer).await;
                let body = r#"{"jsonrpc":"2.0","id":"x","result":{"header":{"height":1000}}}"#;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    format!("http://{address}")
}

async fn setup(dir: &Path, with_card: bool) -> (State, Option<CardRecord>) {
    setup_with(dir, with_card, Some(rpc().await))
}

fn setup_with(
    dir: &Path,
    with_card: bool,
    near_rpc_url: Option<String>,
) -> (State, Option<CardRecord>) {
    let config = Config {
        near_rpc_url,
        socket_path: dir.join("signer.sock"),
        socket_gid: None,
        allowed_uids: vec![me()],
        state_dir: dir.join("state"),
        audit_log: dir.join("audit.log"),
        rate_per_minute: 100,
    };
    let store = Store::open(&config.state_dir).unwrap();
    let mut record = AgentRecord::new(AGENT, "testnet", VAULT, vec!["prepare".into()], None);
    let card = with_card.then(|| {
        CardRecord::with_account(CardRecord::unassigned(USDC, 5_000_000), CARD, 5_000_000)
    });
    record.card = card.clone();
    store.save(&record).unwrap();
    (State::new(config).unwrap(), card)
}

fn transfer(args: &str, gas: u64, deposit: u128) -> Action {
    Action::FunctionCall(FunctionCall {
        method_name: "ft_transfer".into(),
        args: args.as_bytes().to_vec(),
        gas,
        deposit,
    })
}

fn payment(card: &CardRecord, receiver: &str, actions: Vec<Action>) -> DelegateAction {
    DelegateAction {
        sender_id: CARD.into(),
        receiver_id: receiver.into(),
        actions,
        nonce: 42,
        max_block_height: 5_000,
        public_key: card.signing_key().unwrap().verifying_key().to_bytes(),
    }
}

fn good_args(amount: &str) -> String {
    format!(r#"{{"receiver_id":"{SELLER}","amount":"{amount}"}}"#)
}

async fn sign(state: &State, delegate: &DelegateAction) -> Value {
    let b64 = base64::engine::general_purpose::STANDARD.encode(encode_delegate(delegate));
    handle_line(
        state,
        me(),
        &json!({ "op": "sign_delegate", "agent": AGENT, "delegate_borsh_b64": b64 }).to_string(),
    )
    .await
}

fn error(reply: &Value) -> &str {
    reply["error"].as_str().unwrap_or("none")
}

#[tokio::test]
async fn signs_an_ft_transfer_and_the_signature_is_the_one_near_checks() {
    let dir = tempfile::tempdir().unwrap();
    let (state, card) = setup(dir.path(), true).await;
    let card = card.unwrap();
    let delegate = payment(
        &card,
        USDC,
        vec![transfer(&good_args("2000000"), 30_000_000_000_000, 1)],
    );
    let reply = sign(&state, &delegate).await;
    assert_eq!(reply["ok"], true, "{reply}");
    // NEAR verifies the signature over sha256(borsh(u32 2^30+366) ++ borsh(delegate action)).
    let mut message = DELEGATE_ACTION_PREFIX.to_le_bytes().to_vec();
    message.extend_from_slice(&encode_delegate(&delegate));
    let hash: [u8; 32] = Sha256::digest(&message).into();
    let signature = bs58::decode(
        reply["signature"]
            .as_str()
            .unwrap()
            .trim_start_matches("ed25519:"),
    )
    .into_vec()
    .unwrap();
    let key =
        VerifyingKey::from_bytes(&card.signing_key().unwrap().verifying_key().to_bytes()).unwrap();
    key.verify(&hash, &Signature::from_slice(&signature).unwrap())
        .unwrap();
    assert_eq!(DELEGATE_ACTION_PREFIX, 1_073_742_190);
}

#[tokio::test]
async fn refuses_everything_that_is_not_a_capped_token_payment() {
    let dir = tempfile::tempdir().unwrap();
    let (state, card) = setup(dir.path(), true).await;
    let card = card.unwrap();
    let ok = good_args("1000000");
    let cases: Vec<(DelegateAction, &str)> = vec![
        (
            payment(
                &card,
                "usdc.fakes.testnet",
                vec![transfer(&ok, 30_000_000_000_000, 1)],
            ),
            "RECEIVER_NOT_ALLOWED",
        ),
        (
            payment(&card, VAULT, vec![transfer(&ok, 30_000_000_000_000, 1)]),
            "RECEIVER_NOT_ALLOWED",
        ),
        (
            payment(
                &card,
                USDC,
                vec![transfer(&good_args("5000001"), 30_000_000_000_000, 1)],
            ),
            "AMOUNT_NOT_ALLOWED",
        ),
        (
            payment(
                &card,
                USDC,
                vec![transfer(&good_args("0"), 30_000_000_000_000, 1)],
            ),
            "AMOUNT_NOT_ALLOWED",
        ),
        (
            payment(&card, USDC, vec![transfer(&ok, 31_000_000_000_000, 1)]),
            "GAS_TOO_HIGH",
        ),
        (
            payment(&card, USDC, vec![transfer(&ok, 30_000_000_000_000, 2)]),
            "DEPOSIT_TOO_HIGH",
        ),
        (
            payment(
                &card,
                USDC,
                vec![
                    transfer(&ok, 30_000_000_000_000, 1),
                    transfer(&ok, 30_000_000_000_000, 1),
                ],
            ),
            "TOO_MANY_ACTIONS",
        ),
        (payment(&card, USDC, vec![]), "NO_ACTION"),
        (
            payment(
                &card,
                USDC,
                vec![Action::FunctionCall(FunctionCall {
                    method_name: "ft_transfer_call".into(),
                    args: ok.clone().into_bytes(),
                    gas: 30_000_000_000_000,
                    deposit: 1,
                })],
            ),
            "METHOD_NOT_ALLOWED",
        ),
        (
            payment(
                &card,
                USDC,
                vec![Action::FunctionCall(FunctionCall {
                    method_name: "storage_withdraw".into(),
                    args: b"{}".to_vec(),
                    gas: 30_000_000_000_000,
                    deposit: 1,
                })],
            ),
            "METHOD_NOT_ALLOWED",
        ),
        (
            payment(
                &card,
                USDC,
                vec![transfer(
                    &format!(r#"{{"receiver_id":"{SELLER}","amount":"1","msg":"x"}}"#),
                    30_000_000_000_000,
                    1,
                )],
            ),
            "MALFORMED_TRANSACTION",
        ),
        (
            payment(
                &card,
                USDC,
                vec![transfer(
                    r#"{"receiver_id":"Bad Account","amount":"1"}"#,
                    30_000_000_000_000,
                    1,
                )],
            ),
            "MALFORMED_TRANSACTION",
        ),
        (
            payment(
                &card,
                USDC,
                vec![transfer(
                    r#"{"receiver_id":"a.testnet","amount":1}"#,
                    30_000_000_000_000,
                    1,
                )],
            ),
            "MALFORMED_TRANSACTION",
        ),
    ];
    for (delegate, code) in cases {
        assert_eq!(error(&sign(&state, &delegate).await), code);
    }
    // Another sender, or another key, is refused.
    let mut other = payment(&card, USDC, vec![transfer(&ok, 30_000_000_000_000, 1)]);
    other.sender_id = AGENT.into();
    assert_eq!(error(&sign(&state, &other).await), "SIGNER_MISMATCH");
    let mut wrong_key = payment(&card, USDC, vec![transfer(&ok, 30_000_000_000_000, 1)]);
    wrong_key.public_key = [7; 32];
    assert_eq!(error(&sign(&state, &wrong_key).await), "KEY_MISMATCH");
    // Trailing bytes, or another action kind, never get to the policy.
    let mut bytes = encode_delegate(&payment(
        &card,
        USDC,
        vec![transfer(&ok, 30_000_000_000_000, 1)],
    ));
    bytes.push(0);
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let reply = handle_line(
        &state,
        me(),
        &json!({ "op": "sign_delegate", "agent": AGENT, "delegate_borsh_b64": b64 }).to_string(),
    )
    .await;
    assert_eq!(error(&reply), "MALFORMED_TRANSACTION");
    assert_eq!(
        error(&sign(&state, &payment(&card, USDC, vec![Action::Other(3)])).await),
        "ACTION_NOT_ALLOWED"
    );
}

#[tokio::test]
async fn no_card_no_signature_and_the_card_key_never_signs_vault_calls() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _) = setup(dir.path(), false).await;
    let card = CardRecord::with_account(CardRecord::unassigned(USDC, 1), CARD, 1);
    assert_eq!(
        error(
            &sign(
                &state,
                &payment(
                    &card,
                    USDC,
                    vec![transfer(&good_args("1"), 30_000_000_000_000, 1)]
                )
            )
            .await
        ),
        "NO_CARD"
    );
    let info = handle_line(
        &state,
        me(),
        &json!({ "op": "card_info", "agent": AGENT }).to_string(),
    )
    .await;
    assert_eq!(error(&info), "NO_CARD");
}

#[tokio::test]
async fn card_info_is_public_facts_only() {
    let dir = tempfile::tempdir().unwrap();
    let (state, card) = setup(dir.path(), true).await;
    let info = handle_line(
        &state,
        me(),
        &json!({ "op": "card_info", "agent": AGENT }).to_string(),
    )
    .await;
    assert_eq!(info["card"], CARD);
    assert_eq!(info["token"], USDC);
    assert_eq!(info["max_per_payment"], "5000000");
    assert_eq!(info["public_key"], card.unwrap().public_key().unwrap());
    assert!(!info.to_string().contains("seed"));
}

#[tokio::test]
async fn cheques_cannot_outlive_a_few_thousand_blocks_or_hide_duplicate_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (state, card) = setup(dir.path(), true).await;
    let card = card.unwrap();
    let mut late = payment(
        &card,
        USDC,
        vec![transfer(&good_args("1000000"), 30_000_000_000_000, 1)],
    );
    late.max_block_height = 1_000 + euthyna_signer::policy::MAX_CHEQUE_BLOCKS + 1;
    assert_eq!(error(&sign(&state, &late).await), "EXPIRES_TOO_LATE");
    late.max_block_height = u64::MAX;
    assert_eq!(error(&sign(&state, &late).await), "EXPIRES_TOO_LATE");
    // Duplicate keys, other order, spaces: refused, even when the values look fine.
    for args in [
        format!(r#"{{"receiver_id":"{SELLER}","amount":"6000000","amount":"1"}}"#),
        format!(r#"{{"amount":"1","receiver_id":"{SELLER}"}}"#),
        format!(r#"{{ "receiver_id":"{SELLER}","amount":"1"}}"#),
    ] {
        assert_eq!(
            error(
                &sign(
                    &state,
                    &payment(&card, USDC, vec![transfer(&args, 30_000_000_000_000, 1)])
                )
                .await
            ),
            "MALFORMED_TRANSACTION",
            "{args}"
        );
    }
    let memo = format!(r#"{{"receiver_id":"{SELLER}","amount":"1","memo":"market:t1"}}"#);
    assert_eq!(
        sign(
            &state,
            &payment(&card, USDC, vec![transfer(&memo, 30_000_000_000_000, 1)])
        )
        .await["ok"],
        true
    );
}

#[tokio::test]
async fn refuses_to_sign_when_it_cannot_read_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (state, card) = setup_with(dir.path(), true, Some("http://127.0.0.1:9".into()));
    let card = card.unwrap();
    let reply = sign(
        &state,
        &payment(
            &card,
            USDC,
            vec![transfer(&good_args("1"), 30_000_000_000_000, 1)],
        ),
    )
    .await;
    assert_eq!(error(&reply), "CHAIN_UNREACHABLE");
}

#[test]
fn the_ai_cannot_create_the_card_through_the_api_op() {
    assert!(!euthyna_signer::policy::api_path_allowed(
        "POST",
        "/v1/agent/card"
    ));
}

#[test]
fn new_agents_may_call_the_vault_near_methods() {
    assert!(DEFAULT_METHODS.contains(&"execute_near"));
    assert!(DEFAULT_METHODS.contains(&"release_near_unconfirmed"));
}
