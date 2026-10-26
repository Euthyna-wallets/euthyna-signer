//! Pairing sends only the public key, and keeps what the API returns.

use euthyna_signer::pair::{apply, check_api_url, http_client, new_unpaired_record, redeem};
use euthyna_signer::server::{Config, State, handle_line};
use euthyna_signer::store::Store;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A one-request HTTP server: returns the request body it received.
async fn fake_api(status: u16, reply: Value) -> (String, tokio::task::JoinHandle<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let body = loop {
            let n = socket.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&buf).to_string();
            if let Some(split) = text.find("\r\n\r\n") {
                let head = text[..split].to_lowercase();
                assert!(head.starts_with("post /v1/agents/pair "), "{head}");
                let length: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                if buf.len() >= split + 4 + length {
                    break serde_json::from_slice::<Value>(&buf[split + 4..split + 4 + length])
                        .unwrap();
                }
            }
        };
        let payload = reply.to_string();
        let response = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
            payload.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        body
    });
    (url, handle)
}

#[tokio::test]
async fn pairs_with_the_public_key_only_and_keeps_the_api_key() {
    let (url, server) = fake_api(
        201,
        json!({
            "agentId": "a1", "accountId": "mario-83d781-agent.mandateos.testnet",
            "vaultAccountId": "acme-ai-vault.mandateos.testnet", "networkId": "testnet",
            "role": "yield-manager", "apiKey": "mdo_secret_from_api"
        }),
    )
    .await;
    let mut record = new_unpaired_record();
    let public_key = record.public_key().unwrap();
    let paired = redeem(
        &http_client().unwrap(),
        &url,
        " EUT-AAAA-BBBB ",
        &public_key,
        "box",
    )
    .await
    .unwrap();
    let sent = server.await.unwrap();
    assert_eq!(
        sent,
        json!({ "code": "EUT-AAAA-BBBB", "publicKey": public_key, "hostname": "box" })
    );

    apply(&mut record, &paired, &format!("{url}/"));
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        socket_path: dir.path().join("s.sock"),
        socket_gid: None,
        allowed_uids: vec![],
        state_dir: dir.path().join("state"),
        audit_log: dir.path().join("audit.log"),
        rate_per_minute: 10,
    };
    Store::open(&config.state_dir)
        .unwrap()
        .save(&record)
        .unwrap();
    let state = State::new(config).unwrap();

    let info = handle_line(
        &state,
        0,
        r#"{"op":"agent_info","agent":"mario-83d781-agent.mandateos.testnet"}"#,
    )
    .await;
    assert_eq!(info["ok"], true);
    assert_eq!(info["vault"], "acme-ai-vault.mandateos.testnet");
    assert_eq!(info["role"], "yield-manager");
    assert_eq!(info["public_key"], public_key);
    assert_eq!(info["api"], true);
    let text = info.to_string();
    assert!(
        !text.contains("mdo_secret_from_api"),
        "agent_info leaked the API key"
    );
    assert!(!text.contains("seed"), "agent_info leaked the key");
}

#[tokio::test]
async fn shows_the_api_refusal() {
    let (url, server) = fake_api(
        404,
        json!({ "error": "pairing_invalid", "message": "This pairing code is unknown, already used or expired." }),
    )
    .await;
    let error = redeem(&http_client().unwrap(), &url, "EUT-OLD", "ed25519:x", "box")
        .await
        .unwrap_err();
    server.await.unwrap();
    assert!(error.to_string().contains("already used or expired"));
}

#[tokio::test]
async fn refuses_an_account_id_it_cannot_store() {
    let (url, server) = fake_api(
        201,
        json!({ "agentId": "a", "accountId": "../../etc/passwd", "vaultAccountId": "v.testnet",
                "networkId": "testnet", "role": "r", "apiKey": "k" }),
    )
    .await;
    assert!(
        redeem(&http_client().unwrap(), &url, "EUT-X", "ed25519:x", "h")
            .await
            .is_err()
    );
    server.await.unwrap();
}

#[test]
fn plain_http_only_to_this_machine() {
    assert!(check_api_url("https://api.euthyna.ai").is_ok());
    assert!(check_api_url("http://localhost:3000").is_ok());
    assert!(check_api_url("http://api.euthyna.ai").is_err());
}
