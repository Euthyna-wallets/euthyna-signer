//! What the signer agrees to sign: a request to the agent's vault, and
//! nothing else.

use std::fmt;

use crate::store::AgentRecord;
use crate::tx::{self, Action, Transaction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Malformed(String),
    SignerMismatch,
    KeyMismatch,
    ReceiverNotAllowed(String),
    NoAction,
    TooManyActions(usize),
    ActionNotAllowed(u8),
    MethodNotAllowed(String),
    GasTooHigh(u64),
    DepositTooHigh(u128),
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::Malformed(_) => "MALFORMED_TRANSACTION",
            Refusal::SignerMismatch => "SIGNER_MISMATCH",
            Refusal::KeyMismatch => "KEY_MISMATCH",
            Refusal::ReceiverNotAllowed(_) => "RECEIVER_NOT_ALLOWED",
            Refusal::NoAction => "NO_ACTION",
            Refusal::TooManyActions(_) => "TOO_MANY_ACTIONS",
            Refusal::ActionNotAllowed(_) => "ACTION_NOT_ALLOWED",
            Refusal::MethodNotAllowed(_) => "METHOD_NOT_ALLOWED",
            Refusal::GasTooHigh(_) => "GAS_TOO_HIGH",
            Refusal::DepositTooHigh(_) => "DEPOSIT_TOO_HIGH",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Malformed(why) => write!(f, "{why}"),
            Refusal::SignerMismatch => write!(f, "signer_id is not this agent"),
            Refusal::KeyMismatch => write!(f, "public_key is not this agent's key"),
            Refusal::ReceiverNotAllowed(r) => write!(f, "{r}"),
            Refusal::NoAction => write!(f, "no action"),
            Refusal::TooManyActions(n) => write!(f, "{n} actions"),
            Refusal::ActionNotAllowed(kind) => write!(f, "action kind {kind}"),
            Refusal::MethodNotAllowed(m) => write!(f, "{m}"),
            Refusal::GasTooHigh(g) => write!(f, "{g}"),
            Refusal::DepositTooHigh(d) => write!(f, "{d}"),
        }
    }
}

/// The transaction and the one call it makes, once accepted.
pub struct Accepted {
    pub tx: Transaction,
    pub method: String,
}

pub fn check(
    agent: &AgentRecord,
    agent_public_key: &[u8; 32],
    bytes: &[u8],
) -> Result<Accepted, Refusal> {
    let tx = tx::decode(bytes).map_err(|error| match error {
        tx::DecodeError::UnsupportedAction(kind) => Refusal::ActionNotAllowed(kind),
        other => Refusal::Malformed(other.to_string()),
    })?;
    if tx.signer_id != agent.account_id {
        return Err(Refusal::SignerMismatch);
    }
    if &tx.public_key != agent_public_key {
        return Err(Refusal::KeyMismatch);
    }
    if tx.receiver_id != agent.vault_id {
        return Err(Refusal::ReceiverNotAllowed(tx.receiver_id.clone()));
    }
    let call = match tx.actions.as_slice() {
        [] => return Err(Refusal::NoAction),
        [Action::FunctionCall(call)] => call,
        [Action::Other(kind)] => return Err(Refusal::ActionNotAllowed(*kind)),
        many => return Err(Refusal::TooManyActions(many.len())),
    };
    if !agent.allowed_methods.iter().any(|m| m == &call.method_name) {
        return Err(Refusal::MethodNotAllowed(call.method_name.clone()));
    }
    if call.gas > agent.max_gas {
        return Err(Refusal::GasTooHigh(call.gas));
    }
    let max_deposit = agent
        .max_deposit()
        .map_err(|e| Refusal::Malformed(e.to_string()))?;
    if call.deposit > max_deposit {
        return Err(Refusal::DepositTooHigh(call.deposit));
    }
    let method = call.method_name.clone();
    Ok(Accepted { tx, method })
}

/// The agent API paths the signer forwards with the agent's API key.
pub fn api_path_allowed(method: &str, path: &str) -> bool {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    if path.contains("..") || path.contains("//") {
        return false;
    }
    let hex = |s: &str| (2..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit());
    let segments: Vec<&str> = path.split('/').collect();
    match (method, segments.as_slice()) {
        ("POST", ["", "v1", "operations", "pay" | "gas-quote" | "check"]) => query.is_empty(),
        ("POST", ["", "v1", "operations", id, "authorization" | "cancellation"]) => {
            hex(id) && query.is_empty()
        }
        ("GET", ["", "v1", "operations", id]) => hex(id) && query.is_empty(),
        ("GET", ["", "v1", "agent", "mandate"]) => query.is_empty(),
        ("GET", ["", "v1", "agent", "share-revenue"]) => query
            .strip_prefix("amountWei=")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())),
        _ => false,
    }
}
