//! Pairing: the console gives a one-time code; the signer sends it with the
//! new agent's PUBLIC key and receives the agent's account, vault and API key.
//! The private key is made here and never leaves this machine.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::json;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::store::{AgentRecord, ApiAccess, DEFAULT_METHODS, valid_account_id};

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct Paired {
    pub account_id: String,
    pub vault_account_id: String,
    pub network_id: String,
    pub role: String,
    api_key: String,
}

impl std::fmt::Debug for Paired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paired")
            .field("account_id", &self.account_id)
            .field("vault_account_id", &self.vault_account_id)
            .field("network_id", &self.network_id)
            .field("role", &self.role)
            .field("api_key", &"<hidden>")
            .finish()
    }
}

/// `https://…`, or plain http only to this machine (development).
pub fn check_api_url(url: &str) -> Result<()> {
    let local = ["http://localhost", "http://127.0.0.1", "http://[::1]"]
        .iter()
        .any(|prefix| url.starts_with(prefix));
    if url.starts_with("https://") || local {
        Ok(())
    } else {
        bail!("the API URL must be https (or localhost for development)")
    }
}

/// A fresh agent key, not yet tied to an account: the API names the account.
pub fn new_unpaired_record() -> AgentRecord {
    let methods = DEFAULT_METHODS.iter().map(|m| m.to_string()).collect();
    AgentRecord::new("unpaired", "testnet", "unpaired", methods, None)
}

/// Built before `sudo` is dropped, so the system's CA certificates are read
/// whatever their permissions.
pub fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("could not set up HTTPS")
}

pub async fn redeem(
    http: &reqwest::Client,
    api_url: &str,
    code: &str,
    public_key: &str,
    hostname: &str,
) -> Result<Paired> {
    check_api_url(api_url)?;
    let url = format!("{}/v1/agents/pair", api_url.trim_end_matches('/'));
    let response = http
        .post(&url)
        .json(&json!({ "code": code.trim(), "publicKey": public_key, "hostname": hostname }))
        .send()
        .await
        .with_context(|| format!("could not reach {url}"))?;
    let status = response.status();
    let mut body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let message = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v["message"]
                    .as_str()
                    .or(v["error"].as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| status.to_string());
        bail!("{message}");
    }
    let parsed = serde_json::from_str::<Paired>(&body);
    body.zeroize();
    let paired = parsed.context("unexpected answer from the API")?;
    if !valid_account_id(&paired.account_id) || !valid_account_id(&paired.vault_account_id) {
        bail!("the API returned an invalid NEAR account id");
    }
    if !matches!(paired.network_id.as_str(), "testnet" | "mainnet") {
        bail!("the API returned an unknown network");
    }
    Ok(paired)
}

/// Ties the key to what the API hired.
pub fn apply(record: &mut AgentRecord, paired: &Paired, api_url: &str) {
    record.account_id = paired.account_id.clone();
    record.vault_id = paired.vault_account_id.clone();
    record.network_id = paired.network_id.clone();
    record.role = Some(paired.role.clone());
    record.api = Some(ApiAccess {
        url: api_url.trim_end_matches('/').to_owned(),
        key: paired.api_key.clone(),
    });
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    if !ok {
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end])
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(64)
        .collect()
}
