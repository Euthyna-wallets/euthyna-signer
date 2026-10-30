//! The signer signs a vault request, and refuses everything else.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use euthyna_signer::policy::api_path_allowed;
use euthyna_signer::server::{Config, State, handle_line, serve};
use euthyna_signer::store::{AgentRecord, Store};
use euthyna_signer::tx::{Action, FunctionCall, Transaction, encode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const AGENT: &str = "naomi-agent.euthyna.testnet";
const VAULT: &str = "acme-vault.euthyna.testnet";

fn config(dir: &Path, allowed_uids: Vec<u32>, rate: u32) -> Config {
    Config {
        socket_path: dir.join("signer.sock"),
        socket_gid: None,
        allowed_uids,
        state_dir: dir.join("state"),
        audit_log: dir.join("audit.log"),
        rate_per_minute: rate,
        near_rpc_url: None,
    }
}

fn setup(dir: &Path, rate: u32) -> (State, AgentRecord) {
    let config = config(dir, vec![me()], rate);
    let store = Store::open(&config.state_dir).unwrap();
    let methods = ["prepare", "authorize", "cancel_nonce"]
        .map(String::from)
        .to_vec();
    let record = AgentRecord::new(AGENT, "testnet", VAULT, methods, None);
    store.save(&record).unwrap();
    (State::new(config).unwrap(), record)
}

fn me() -> u32 {
    unsafe { libc::geteuid() }
}

fn call(method: &str, gas: u64, deposit: u128) -> Action {
    Action::FunctionCall(FunctionCall {
        method_name: method.into(),
        args: br#"{"role":"payments"}"#.to_vec(),
        gas,
        deposit,
    })
}

fn tx(record: &AgentRecord, receiver: &str, actions: Vec<Action>) -> Transaction {
    Transaction {
        signer_id: AGENT.into(),
        public_key: record.signing_key().unwrap().verifying_key().to_bytes(),
        nonce: 7,
        receiver_id: receiver.into(),
        block_hash: [1; 32],
        actions,
    }
}

async fn sign(state: &State, t: &Transaction) -> Value {
    let b64 = base64::engine::general_purpose::STANDARD.encode(encode(t));
    handle_line(
        state,
        me(),
        &json!({ "op": "sign_near_tx", "agent": AGENT, "tx_borsh_b64": b64 }).to_string(),
    )
    .await
}

fn error(reply: &Value) -> &str {
    reply["error"].as_str().unwrap_or("none")
}

#[tokio::test]
async fn signs_a_vault_prepare_and_the_signature_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let (state, record) = setup(dir.path(), 30);
    let t = tx(
        &record,
        VAULT,
        vec![call("prepare", 100_000_000_000_000, 0)],
    );
    let reply = sign(&state, &t).await;
    assert_eq!(reply["ok"], true, "{reply}");

    let public = record.signing_key().unwrap().verifying_key();
    assert_eq!(reply["public_key"], record.public_key().unwrap());
    let sig_bytes = bs58::decode(
        reply["signature"]
            .as_str()
            .unwrap()
            .trim_start_matches("ed25519:"),
    )
    .into_vec()
    .unwrap();
    let signature = Signature::from_slice(&sig_bytes).unwrap();
    let hash: [u8; 32] = Sha256::digest(encode(&t)).into();
    VerifyingKey::from_bytes(&public.to_bytes())
        .unwrap()
        .verify(&hash, &signature)
        .expect("valid NEAR signature");
}

#[tokio::test]
async fn refuses_everything_that_is_not_a_vault_request() {
    let dir = tempfile::tempdir().unwrap();
    let (state, record) = setup(dir.path(), 100);
    let gas = 100_000_000_000_000;

    let cases: Vec<(&str, Transaction)> = vec![
        (
            "RECEIVER_NOT_ALLOWED",
            tx(&record, "usdc.fakes.testnet", vec![call("prepare", gas, 0)]),
        ),
        (
            "METHOD_NOT_ALLOWED",
            tx(&record, VAULT, vec![call("ft_transfer", gas, 0)]),
        ),
        (
            "METHOD_NOT_ALLOWED",
            tx(&record, VAULT, vec![call("renounce_role", gas, 0)]),
        ),
        (
            "TOO_MANY_ACTIONS",
            tx(
                &record,
                VAULT,
                vec![call("prepare", gas, 0), call("authorize", gas, 0)],
            ),
        ),
        ("NO_ACTION", tx(&record, VAULT, vec![])),
        (
            "ACTION_NOT_ALLOWED",
            tx(&record, VAULT, vec![Action::Other(3)]),
        ),
        (
            "GAS_TOO_HIGH",
            tx(
                &record,
                VAULT,
                vec![call("prepare", 300_000_000_000_001, 0)],
            ),
        ),
        (
            "DEPOSIT_TOO_HIGH",
            tx(&record, VAULT, vec![call("prepare", gas, 2)]),
        ),
    ];
    for (expected, t) in cases {
        let reply = sign(&state, &t).await;
        assert_eq!(reply["ok"], false, "{expected}: {reply}");
        assert_eq!(error(&reply), expected, "{reply}");
    }

    let mut other_signer = tx(&record, VAULT, vec![call("prepare", gas, 0)]);
    other_signer.signer_id = "attacker.testnet".into();
    assert_eq!(error(&sign(&state, &other_signer).await), "SIGNER_MISMATCH");

    let mut other_key = tx(&record, VAULT, vec![call("prepare", gas, 0)]);
    other_key.public_key = [9; 32];
    assert_eq!(error(&sign(&state, &other_key).await), "KEY_MISMATCH");

    let mut trailing = encode(&tx(&record, VAULT, vec![call("prepare", gas, 0)]));
    trailing.push(0);
    let b64 = base64::engine::general_purpose::STANDARD.encode(trailing);
    let reply = handle_line(
        &state,
        me(),
        &json!({ "op": "sign_near_tx", "agent": AGENT, "tx_borsh_b64": b64 }).to_string(),
    )
    .await;
    assert_eq!(error(&reply), "MALFORMED_TRANSACTION");
}

#[tokio::test]
async fn has_no_way_to_hand_out_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _) = setup(dir.path(), 30);
    for op in [
        "export_key",
        "get_secret",
        "secret_key",
        "private_key",
        "dump",
        "read_file",
    ] {
        let reply = handle_line(
            &state,
            me(),
            &json!({ "op": op, "agent": AGENT }).to_string(),
        )
        .await;
        assert_eq!(error(&reply), "UNKNOWN_OP", "{op}");
    }
    // Neither the replies nor the audit log ever contain the secret seed.
    let file: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(format!("state/agents/{AGENT}.json"))).unwrap(),
    )
    .unwrap();
    let seed = file["secret_seed"].as_str().unwrap().to_owned();
    for line in [
        json!({ "op": "status" }),
        json!({ "op": "public_key", "agent": AGENT }),
    ] {
        let reply = handle_line(&state, me(), &line.to_string()).await;
        assert!(!reply.to_string().contains(&seed));
    }
    let audit = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(audit.contains("UNKNOWN_OP"));
    assert!(!audit.contains(&seed));
}

#[tokio::test]
async fn key_files_are_private_and_a_readable_one_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (state, record) = setup(dir.path(), 30);
    let path = dir.path().join(format!("state/agents/{AGENT}.json"));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(dir.path().join("state"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let reply = sign(&state, &tx(&record, VAULT, vec![call("prepare", 1, 0)])).await;
    assert_eq!(error(&reply), "UNKNOWN_AGENT", "{reply}");
    assert!(
        reply["detail"]
            .as_str()
            .unwrap()
            .contains("readable by others")
    );
}

#[tokio::test]
async fn limits_signatures_per_minute() {
    let dir = tempfile::tempdir().unwrap();
    let (state, record) = setup(dir.path(), 3);
    let t = tx(&record, VAULT, vec![call("prepare", 1, 0)]);
    for _ in 0..3 {
        assert_eq!(sign(&state, &t).await["ok"], true);
    }
    assert_eq!(error(&sign(&state, &t).await), "RATE_LIMITED");
}

#[tokio::test]
async fn rotate_then_promote_switches_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let (state, mut record) = setup(dir.path(), 30);
    let old = record.public_key().unwrap();
    record.rotate();
    let next = record.next_public_key().unwrap().unwrap();
    Store::open(&dir.path().join("state"))
        .unwrap()
        .save(&record)
        .unwrap();
    // Until promoted, the old key signs.
    let reply = sign(&state, &tx(&record, VAULT, vec![call("prepare", 1, 0)])).await;
    assert_eq!(reply["public_key"], old);
    record.promote().unwrap();
    Store::open(&dir.path().join("state"))
        .unwrap()
        .save(&record)
        .unwrap();
    assert_eq!(record.public_key().unwrap(), next);
    let reply = sign(&state, &tx(&record, VAULT, vec![call("prepare", 1, 0)])).await;
    assert_eq!(reply["public_key"], next);
}

#[test]
fn forwards_only_the_agent_api_paths() {
    for (method, path) in [
        ("POST", "/v1/operations/pay"),
        ("POST", "/v1/operations/gas-quote"),
        ("POST", "/v1/operations/check"),
        ("POST", "/v1/operations/0a1b2c/authorization"),
        ("POST", "/v1/operations/0a1b2c/cancellation"),
        ("GET", "/v1/operations/0a1b2c"),
        ("GET", "/v1/agent/mandate"),
        ("GET", "/v1/agent/share-revenue?amountWei=1000"),
    ] {
        assert!(api_path_allowed(method, path), "{method} {path}");
    }
    for (method, path) in [
        ("GET", "/v1/console/omniroles/status"),
        ("POST", "/v1/console/agents"),
        ("GET", "/api/auth/get-session"),
        ("POST", "/v1/operations/../console/agents"),
        ("POST", "/v1/operations/pay?x=1"),
        ("GET", "/v1/operations/not-hex"),
        ("GET", "/v1/agent/share-revenue?amountWei=1&evil=1"),
        ("DELETE", "/v1/operations/0a1b2c"),
        ("GET", "//evil.example/v1/operations/pay"),
    ] {
        assert!(!api_path_allowed(method, path), "{method} {path}");
    }
}

async fn ask(socket: &Path, line: Value) -> Value {
    let stream = UnixStream::connect(socket).await.unwrap();
    let (read, mut write) = stream.into_split();
    write
        .write_all(format!("{line}\n").as_bytes())
        .await
        .unwrap();
    let mut reply = String::new();
    BufReader::new(read).read_line(&mut reply).await.unwrap();
    serde_json::from_str(&reply).unwrap()
}

async fn start(config: Config) {
    let socket = config.socket_path.clone();
    tokio::spawn(serve(config));
    for _ in 0..100 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("socket never appeared");
}

#[tokio::test]
async fn the_socket_checks_who_is_calling() {
    let dir = tempfile::tempdir().unwrap();
    let allowed = config(dir.path(), vec![me()], 30);
    start(allowed.clone()).await;
    assert_eq!(
        std::fs::metadata(&allowed.socket_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o660
    );
    let reply = ask(&allowed.socket_path, json!({ "op": "status" })).await;
    assert_eq!(reply["ok"], true, "{reply}");

    let other = tempfile::tempdir().unwrap();
    let refused = config(other.path(), vec![me().wrapping_add(4242)], 30);
    start(refused.clone()).await;
    let reply = ask(&refused.socket_path, json!({ "op": "status" })).await;
    assert_eq!(error(&reply), "UID_NOT_ALLOWED", "{reply}");
}
