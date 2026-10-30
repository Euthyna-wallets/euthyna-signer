//! The Unix-socket server: one JSON request per line, one JSON reply per line.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::policy;
use crate::store::{Store, near_public_key};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_LINE: usize = 512 * 1024;
const MAX_API_BODY: usize = 256 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub socket_path: PathBuf,
    /// Group that owns the socket (mode 0660). The agent's user must be in it.
    #[serde(default)]
    pub socket_gid: Option<u32>,
    /// Only these system users may talk to the signer; checked on every connection.
    pub allowed_uids: Vec<u32>,
    pub state_dir: PathBuf,
    pub audit_log: PathBuf,
    /// Signatures per agent per minute.
    #[serde(default = "default_rate")]
    pub rate_per_minute: u32,
    /// NEAR RPC used to read the current block height before signing a card
    /// payment (bounds how long a cheque lives). Default: FastNEAR for the
    /// agent's network.
    #[serde(default)]
    pub near_rpc_url: Option<String>,
}

fn default_rate() -> u32 {
    30
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&text).context("config is not valid JSON")
    }
}

pub struct Audit {
    path: PathBuf,
}

impl Audit {
    pub fn write(&self, entry: Value) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut line = json!({ "ts_ms": ts });
        if let (Some(map), Value::Object(extra)) = (line.as_object_mut(), entry) {
            map.extend(extra);
        }
        let opened = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(&self.path);
        if let Ok(mut file) = opened {
            let _ = writeln!(file, "{line}");
        }
    }
}

struct Limiter {
    per_minute: u32,
    windows: HashMap<String, (Instant, u32)>,
}

impl Limiter {
    fn allow(&mut self, agent: &str) -> bool {
        let now = Instant::now();
        let window = self.windows.entry(agent.to_owned()).or_insert((now, 0));
        if now.duration_since(window.0) >= Duration::from_secs(60) {
            *window = (now, 0);
        }
        window.1 += 1;
        window.1 <= self.per_minute
    }
}

pub struct State {
    pub config: Config,
    store: Store,
    audit: Audit,
    limiter: Mutex<Limiter>,
    /// Built on first use: signing never depends on TLS or the network.
    http: tokio::sync::OnceCell<reqwest::Client>,
}

impl State {
    pub fn new(config: Config) -> Result<State> {
        let store = Store::open(&config.state_dir)?;
        let audit = Audit {
            path: config.audit_log.clone(),
        };
        let limiter = Mutex::new(Limiter {
            per_minute: config.rate_per_minute,
            windows: HashMap::new(),
        });
        let http = tokio::sync::OnceCell::new();
        Ok(State {
            config,
            store,
            audit,
            limiter,
            http,
        })
    }
}

#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    tx_borsh_b64: Option<String>,
    #[serde(default)]
    delegate_borsh_b64: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    body: Option<Value>,
}

fn refuse(code: &str, detail: impl ToString) -> Value {
    json!({ "ok": false, "error": code, "detail": detail.to_string() })
}

pub async fn handle_line(state: &State, uid: u32, line: &str) -> Value {
    let request: Request = match serde_json::from_str(line) {
        Ok(request) => request,
        Err(error) => return refuse("BAD_REQUEST", error),
    };
    match request.op.as_str() {
        "status" => {
            let agents = state.store.list().unwrap_or_default();
            json!({ "ok": true, "version": VERSION, "agents": agents })
        }
        "public_key" => {
            let Some(agent) = request.agent.as_deref() else {
                return refuse("BAD_REQUEST", "agent is required");
            };
            match state.store.load(agent).and_then(|r| r.public_key()) {
                Ok(key) => json!({ "ok": true, "public_key": key }),
                Err(error) => refuse("UNKNOWN_AGENT", error),
            }
        }
        // Public facts only, so the MCP server needs no config but the agent's name.
        "agent_info" => {
            let Some(agent) = request.agent.as_deref() else {
                return refuse("BAD_REQUEST", "agent is required");
            };
            match state.store.load(agent) {
                Ok(record) => match record.public_key() {
                    Ok(public_key) => json!({
                        "ok": true,
                        "agent": record.account_id,
                        "network": record.network_id,
                        "vault": record.vault_id,
                        "role": record.role,
                        "methods": record.allowed_methods,
                        "public_key": public_key,
                        "api": record.api.is_some(),
                    }),
                    Err(error) => refuse("UNKNOWN_AGENT", error),
                },
                Err(error) => refuse("UNKNOWN_AGENT", error),
            }
        }
        // The agent's spending card: public facts only.
        "card_info" => {
            let Some(agent) = request.agent.as_deref() else {
                return refuse("BAD_REQUEST", "agent is required");
            };
            match state.store.load(agent) {
                Ok(record) => match record.card.as_ref() {
                    Some(card) if !card.account_id.is_empty() => match card.public_key() {
                        Ok(public_key) => json!({
                            "ok": true, "card": card.account_id, "token": card.token,
                            "max_per_payment": card.max_per_payment, "public_key": public_key,
                        }),
                        Err(error) => refuse("AGENT_KEY_UNREADABLE", error),
                    },
                    _ => refuse(
                        "NO_CARD",
                        "this agent has no spending card: sudo euthyna-signer card <agent>",
                    ),
                },
                Err(error) => refuse("UNKNOWN_AGENT", error),
            }
        }
        "sign_near_tx" => sign(state, uid, &request).await,
        "sign_delegate" => sign_delegate(state, uid, &request).await,
        "api" => api(state, uid, &request).await,
        other => {
            state.audit.write(
                json!({ "uid": uid, "op": other, "result": "refused", "error": "UNKNOWN_OP" }),
            );
            refuse("UNKNOWN_OP", other)
        }
    }
}

async fn sign(state: &State, uid: u32, request: &Request) -> Value {
    let Some(agent_id) = request.agent.as_deref() else {
        return refuse("BAD_REQUEST", "agent is required");
    };
    let Some(b64) = request.tx_borsh_b64.as_deref() else {
        return refuse("BAD_REQUEST", "tx_borsh_b64 is required");
    };
    let bytes = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(bytes) => bytes,
        Err(error) => return refuse("BAD_REQUEST", error),
    };
    let record = match state.store.load(agent_id) {
        Ok(record) => record,
        Err(error) => return refuse("UNKNOWN_AGENT", error),
    };
    let key = match record.signing_key() {
        Ok(key) => key,
        Err(error) => return refuse("AGENT_KEY_UNREADABLE", error),
    };
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    let hash_b58 = bs58::encode(hash).into_string();
    let accepted = match policy::check(&record, &key.verifying_key().to_bytes(), &bytes) {
        Ok(accepted) => accepted,
        Err(refusal) => {
            state.audit.write(json!({
                "uid": uid, "op": "sign_near_tx", "agent": agent_id, "result": "refused",
                "error": refusal.code(), "detail": refusal.to_string(), "tx_hash": hash_b58,
            }));
            return refuse(refusal.code(), refusal);
        }
    };
    if !state.limiter.lock().await.allow(agent_id) {
        state.audit.write(json!({ "uid": uid, "op": "sign_near_tx", "agent": agent_id, "result": "refused", "error": "RATE_LIMITED" }));
        return refuse(
            "RATE_LIMITED",
            format!(
                "more than {} signatures a minute",
                state.config.rate_per_minute
            ),
        );
    }
    let signature = key.sign(&hash);
    state.audit.write(json!({
        "uid": uid, "op": "sign_near_tx", "agent": agent_id, "result": "signed",
        "receiver": accepted.tx.receiver_id, "method": accepted.method, "nonce": accepted.tx.nonce, "tx_hash": hash_b58,
    }));
    json!({
        "ok": true,
        "signature": format!("ed25519:{}", bs58::encode(signature.to_bytes()).into_string()),
        "public_key": near_public_key(&key),
        "tx_hash": hash_b58,
    })
}

/// A payment from the agent's card: an `ft_transfer` delegate action (NEP-366)
/// that a relayer (the market) sends. Signed over sha256(NEP-461 prefix + action).
async fn sign_delegate(state: &State, uid: u32, request: &Request) -> Value {
    let Some(agent_id) = request.agent.as_deref() else {
        return refuse("BAD_REQUEST", "agent is required");
    };
    let Some(b64) = request.delegate_borsh_b64.as_deref() else {
        return refuse("BAD_REQUEST", "delegate_borsh_b64 is required");
    };
    let bytes = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(bytes) => bytes,
        Err(error) => return refuse("BAD_REQUEST", error),
    };
    let record = match state.store.load(agent_id) {
        Ok(record) => record,
        Err(error) => return refuse("UNKNOWN_AGENT", error),
    };
    let Some(card) = record
        .card
        .as_ref()
        .filter(|card| !card.account_id.is_empty())
    else {
        let refusal = policy::Refusal::NoCard;
        return refuse(refusal.code(), refusal);
    };
    let key = match card.signing_key() {
        Ok(key) => key,
        Err(error) => return refuse("AGENT_KEY_UNREADABLE", error),
    };
    let mut message = crate::tx::DELEGATE_ACTION_PREFIX.to_le_bytes().to_vec();
    message.extend_from_slice(&bytes);
    let hash: [u8; 32] = Sha256::digest(&message).into();
    let hash_b58 = bs58::encode(hash).into_string();
    // Fail closed: without the current height, nothing bounds the cheque's life.
    let height = match block_height(state, &record.network_id).await {
        Ok(height) => height,
        Err(error) => {
            let refusal = policy::Refusal::ChainUnreachable(error.to_string());
            return refuse(refusal.code(), refusal);
        }
    };
    let accepted = match policy::check_payment(
        card,
        &key.verifying_key().to_bytes(),
        &bytes,
        height,
    ) {
        Ok(accepted) => accepted,
        Err(refusal) => {
            state.audit.write(json!({
                "uid": uid, "op": "sign_delegate", "agent": agent_id, "card": card.account_id, "result": "refused",
                "error": refusal.code(), "detail": refusal.to_string(), "hash": hash_b58,
            }));
            return refuse(refusal.code(), refusal);
        }
    };
    // Cards and vault calls share the agent's rate limit.
    if !state.limiter.lock().await.allow(agent_id) {
        state.audit.write(json!({ "uid": uid, "op": "sign_delegate", "agent": agent_id, "result": "refused", "error": "RATE_LIMITED" }));
        return refuse(
            "RATE_LIMITED",
            format!(
                "more than {} signatures a minute",
                state.config.rate_per_minute
            ),
        );
    }
    let signature = key.sign(&hash);
    state.audit.write(json!({
        "uid": uid, "op": "sign_delegate", "agent": agent_id, "card": card.account_id, "result": "signed",
        "token": card.token, "to": accepted.receiver_id, "amount": accepted.amount.to_string(),
        "nonce": accepted.delegate.nonce, "max_block_height": accepted.delegate.max_block_height, "hash": hash_b58,
    }));
    json!({
        "ok": true,
        "signature": format!("ed25519:{}", bs58::encode(signature.to_bytes()).into_string()),
        "public_key": near_public_key(&key),
        "hash": hash_b58,
    })
}

async fn http(state: &State) -> Result<&reqwest::Client> {
    state
        .http
        .get_or_try_init(|| async {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
        })
        .await
        .context("set up HTTPS")
}

/// The final block height, from the configured RPC (or FastNEAR for the network).
async fn block_height(state: &State, network: &str) -> Result<u64> {
    let url = match (&state.config.near_rpc_url, network) {
        (Some(url), _) => url.clone(),
        (None, "testnet") => "https://rpc.testnet.fastnear.com".to_owned(),
        (None, "mainnet") => "https://rpc.mainnet.fastnear.com".to_owned(),
        (None, other) => anyhow::bail!("set near_rpc_url in the config for network {other}"),
    };
    let reply: Value = http(state)
        .await?
        .post(&url)
        .json(&json!({ "jsonrpc": "2.0", "id": "euthyna-signer", "method": "block", "params": { "finality": "final" } }))
        .send()
        .await?
        .json()
        .await?;
    reply["result"]["header"]["height"]
        .as_u64()
        .context("no block height in the RPC answer")
}

async fn api(state: &State, uid: u32, request: &Request) -> Value {
    let Some(agent_id) = request.agent.as_deref() else {
        return refuse("BAD_REQUEST", "agent is required");
    };
    let method = request.method.as_deref().unwrap_or("GET");
    let Some(path) = request.path.as_deref() else {
        return refuse("BAD_REQUEST", "path is required");
    };
    if !policy::api_path_allowed(method, path) {
        state.audit.write(json!({ "uid": uid, "op": "api", "agent": agent_id, "result": "refused", "error": "PATH_NOT_ALLOWED", "method": method, "path": path }));
        return refuse("PATH_NOT_ALLOWED", format!("{method} {path}"));
    }
    let record = match state.store.load(agent_id) {
        Ok(record) => record,
        Err(error) => return refuse("UNKNOWN_AGENT", error),
    };
    let Some(access) = record.api.clone() else {
        return refuse("NO_API_ACCESS", "this agent has no API key in the signer");
    };
    let url = format!("{}{}", access.url.trim_end_matches('/'), path);
    let http = match state
        .http
        .get_or_try_init(|| async {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
        })
        .await
    {
        Ok(http) => http,
        Err(error) => return refuse("API_UNREACHABLE", error),
    };
    let mut call = match method {
        "GET" => http.get(&url),
        _ => {
            let body = request.body.clone().unwrap_or(json!({}));
            if body.to_string().len() > MAX_API_BODY {
                return refuse("BAD_REQUEST", "body too large");
            }
            http.post(&url).json(&body)
        }
    };
    call = call.header("x-api-key", access.key.as_str());
    let result = match call.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.json::<Value>().await.unwrap_or(json!({}));
            json!({ "ok": true, "status": status, "body": body })
        }
        Err(error) => refuse("API_UNREACHABLE", error),
    };
    state.audit.write(json!({ "uid": uid, "op": "api", "agent": agent_id, "result": if result["ok"] == true { "forwarded" } else { "failed" }, "method": method, "path": path, "status": result["status"] }));
    result
}

async fn serve_connection(state: Arc<State>, stream: UnixStream) {
    let uid = match stream.peer_cred() {
        Ok(cred) => cred.uid(),
        Err(_) => return,
    };
    let (read, mut write) = stream.into_split();
    if !state.config.allowed_uids.contains(&uid) {
        state.audit.write(
            json!({ "uid": uid, "op": "connect", "result": "refused", "error": "UID_NOT_ALLOWED" }),
        );
        let _ = write
            .write_all(format!("{}\n", refuse("UID_NOT_ALLOWED", uid)).as_bytes())
            .await;
        return;
    }
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut reader)
            .take(MAX_LINE as u64 + 1)
            .read_line(&mut line)
            .await
        {
            Ok(0) | Err(_) => return,
            Ok(n) if n > MAX_LINE => {
                let _ = write
                    .write_all(format!("{}\n", refuse("BAD_REQUEST", "line too long")).as_bytes())
                    .await;
                return;
            }
            Ok(_) => {}
        }
        let reply = handle_line(&state, uid, line.trim_end()).await;
        if write
            .write_all(format!("{reply}\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
    }
}

pub async fn serve(config: Config) -> Result<()> {
    let socket = config.socket_path.clone();
    let config_for_state = config.clone();
    let state = Arc::new(State::new(config_for_state)?);
    if let Some(dir) = socket.parent() {
        fs::create_dir_all(dir)?;
    }
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    // The socket is created 0660 from the start: no window where others may connect.
    let previous = unsafe { libc::umask(0o117) };
    let bound = UnixListener::bind(&socket);
    unsafe { libc::umask(previous) };
    let listener = bound.with_context(|| format!("bind {}", socket.display()))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660))?;
    if let Some(gid) = config.socket_gid
        && let Err(error) = std::os::unix::fs::chown(&socket, None, Some(gid))
    {
        let _ = fs::remove_file(&socket);
        anyhow::bail!(
            "cannot give the socket to group {gid} ({error}): the signer's user must be a member of that group"
        );
    }
    state
        .audit
        .write(json!({ "op": "start", "version": VERSION, "socket": socket }));
    eprintln!("euthyna-signer {VERSION} listening on {}", socket.display());
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                if let Ok((stream, _)) = accepted {
                    tokio::spawn(serve_connection(state.clone(), stream));
                }
            }
            _ = tokio::signal::ctrl_c() => {
                let _ = fs::remove_file(&socket);
                return Ok(());
            }
        }
    }
}
