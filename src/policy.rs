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
    AmountTooHigh(u128),
    NoCard,
    ExpiresTooLate(u64),
    ChainUnreachable(String),
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
            Refusal::AmountTooHigh(_) => "AMOUNT_NOT_ALLOWED",
            Refusal::NoCard => "NO_CARD",
            Refusal::ExpiresTooLate(_) => "EXPIRES_TOO_LATE",
            Refusal::ChainUnreachable(_) => "CHAIN_UNREACHABLE",
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
            Refusal::AmountTooHigh(a) => write!(f, "{a} is zero or above the card's cap"),
            Refusal::NoCard => write!(f, "this agent has no spending card"),
            Refusal::ExpiresTooLate(h) => write!(
                f,
                "max_block_height {h} is more than {MAX_CHEQUE_BLOCKS} blocks ahead"
            ),
            Refusal::ChainUnreachable(why) => write!(f, "cannot read the block height: {why}"),
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

/// What a card agrees to sign: one `ft_transfer` of its token, 1 yoctoNEAR,
/// to someone, up to its cap. Nothing else: no other method, contract or
/// action, no `ft_transfer_call` (it would run code on the receiver).
pub struct AcceptedPayment {
    pub delegate: tx::DelegateAction,
    pub receiver_id: String,
    pub amount: u128,
}

/// A signed cheque stays valid until its `max_block_height`; this many blocks
/// (about a day and a half at 0.6 s a block, enough for the market's longest
/// SLA) is the longest the signer allows, so a stock of signed cheques cannot
/// outlive a revocation or a refill for long.
pub const MAX_CHEQUE_BLOCKS: u64 = 200_000;

pub fn check_payment(
    card: &crate::store::CardRecord,
    card_public_key: &[u8; 32],
    bytes: &[u8],
    current_height: u64,
) -> Result<AcceptedPayment, Refusal> {
    let delegate = tx::decode_delegate(bytes).map_err(|error| match error {
        tx::DecodeError::UnsupportedAction(kind) => Refusal::ActionNotAllowed(kind),
        other => Refusal::Malformed(other.to_string()),
    })?;
    if delegate.sender_id != card.account_id {
        return Err(Refusal::SignerMismatch);
    }
    if &delegate.public_key != card_public_key {
        return Err(Refusal::KeyMismatch);
    }
    if delegate.max_block_height > current_height.saturating_add(MAX_CHEQUE_BLOCKS) {
        return Err(Refusal::ExpiresTooLate(delegate.max_block_height));
    }
    if delegate.receiver_id != card.token {
        return Err(Refusal::ReceiverNotAllowed(delegate.receiver_id.clone()));
    }
    let call = match delegate.actions.as_slice() {
        [] => return Err(Refusal::NoAction),
        [Action::FunctionCall(call)] => call,
        [Action::Other(kind)] => return Err(Refusal::ActionNotAllowed(*kind)),
        many => return Err(Refusal::TooManyActions(many.len())),
    };
    if call.method_name != "ft_transfer" {
        return Err(Refusal::MethodNotAllowed(call.method_name.clone()));
    }
    if call.deposit != 1 {
        return Err(Refusal::DepositTooHigh(call.deposit));
    }
    if call.gas > crate::store::CARD_MAX_GAS {
        return Err(Refusal::GasTooHigh(call.gas));
    }
    // The args, exactly: receiver_id, amount (decimal string), optional memo; nothing else.
    let args: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&call.args)
        .map_err(|_| Refusal::Malformed("ft_transfer args are not a JSON object".to_owned()))?;
    if args
        .keys()
        .any(|key| !matches!(key.as_str(), "receiver_id" | "amount" | "memo"))
    {
        return Err(Refusal::Malformed(
            "ft_transfer args carry unknown fields".to_owned(),
        ));
    }
    let receiver_id = args
        .get("receiver_id")
        .and_then(|v| v.as_str())
        .filter(|id| crate::store::valid_account_id(id))
        .ok_or_else(|| Refusal::Malformed("receiver_id".to_owned()))?
        .to_owned();
    let amount: u128 = args
        .get("amount")
        .and_then(|v| v.as_str())
        .filter(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|a| a.parse().ok())
        .ok_or_else(|| Refusal::Malformed("amount".to_owned()))?;
    // Printable ASCII, as the market's gateway accepts.
    if let Some(memo) = args.get("memo")
        && !(memo.is_null()
            || memo
                .as_str()
                .is_some_and(|m| m.len() <= 120 && m.bytes().all(|b| (0x20..0x7f).contains(&b))))
    {
        return Err(Refusal::Malformed("memo".to_owned()));
    }
    // Byte for byte the canonical form: no duplicate key, no other order or escape
    // that the token could read differently from what was checked here.
    let memo = args.get("memo").and_then(|m| m.as_str());
    let canonical = match memo {
        Some(memo) => {
            serde_json::json!({ "receiver_id": receiver_id, "amount": amount.to_string(), "memo": memo })
        }
        None => serde_json::json!({ "receiver_id": receiver_id, "amount": amount.to_string() }),
    };
    let expected = match memo {
        Some(memo) => format!(
            r#"{{"receiver_id":{},"amount":"{amount}","memo":{}}}"#,
            canonical["receiver_id"],
            serde_json::Value::String(memo.to_owned())
        ),
        None => format!(
            r#"{{"receiver_id":{},"amount":"{amount}"}}"#,
            canonical["receiver_id"]
        ),
    };
    if call.args != expected.as_bytes() {
        return Err(Refusal::Malformed(
            "ft_transfer args must be exactly {\"receiver_id\":…,\"amount\":\"…\"} (+ \"memo\" last)".to_owned(),
        ));
    }
    let max = card.max().map_err(|e| Refusal::Malformed(e.to_string()))?;
    if amount == 0 || amount > max {
        return Err(Refusal::AmountTooHigh(amount));
    }
    Ok(AcceptedPayment {
        delegate,
        receiver_id,
        amount,
    })
}
