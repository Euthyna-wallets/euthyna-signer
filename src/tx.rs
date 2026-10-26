//! Minimal, strict decoder for an unsigned NEAR `Transaction` (V0, Borsh).
//!
//! Only what the policy needs is decoded, and only one action kind is
//! understood: `FunctionCall`. Any other action, a non-ed25519 key, or a
//! single trailing byte makes decoding fail, so the policy never sees a
//! transaction it does not fully understand.

use std::fmt;

pub const ACTION_FUNCTION_CALL: u8 = 2;
const KEY_TYPE_ED25519: u8 = 0;
const MAX_STRING: usize = 128;
const MAX_ARGS: usize = 64 * 1024;
const MAX_ACTIONS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionCall {
    pub method_name: String,
    pub args: Vec<u8>,
    pub gas: u64,
    pub deposit: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    FunctionCall(FunctionCall),
    /// Any other action kind: kept only so the policy can name it in the refusal.
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub signer_id: String,
    pub public_key: [u8; 32],
    pub nonce: u64,
    pub receiver_id: String,
    pub block_hash: [u8; 32],
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEnd,
    TrailingBytes,
    KeyType(u8),
    TooLong(&'static str),
    Utf8,
    /// An action other than FunctionCall: its body is not decoded, so the
    /// transaction cannot be decoded either.
    UnsupportedAction(u8),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnexpectedEnd => write!(f, "transaction ends early"),
            DecodeError::TrailingBytes => write!(f, "bytes after the transaction"),
            DecodeError::KeyType(t) => write!(f, "key type {t} is not ed25519"),
            DecodeError::TooLong(what) => write!(f, "{what} is too long"),
            DecodeError::Utf8 => write!(f, "invalid UTF-8"),
            DecodeError::UnsupportedAction(t) => write!(f, "action kind {t} is not allowed"),
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.at.checked_add(n).ok_or(DecodeError::UnexpectedEnd)?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or(DecodeError::UnexpectedEnd)?;
        self.at = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    fn u128(&mut self) -> Result<u128, DecodeError> {
        Ok(u128::from_le_bytes(
            self.take(16)?.try_into().expect("16 bytes"),
        ))
    }
    fn array32(&mut self) -> Result<[u8; 32], DecodeError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }
    fn bytes(&mut self, max: usize, what: &'static str) -> Result<Vec<u8>, DecodeError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(DecodeError::TooLong(what));
        }
        Ok(self.take(len)?.to_vec())
    }
    fn string(&mut self, what: &'static str) -> Result<String, DecodeError> {
        String::from_utf8(self.bytes(MAX_STRING, what)?).map_err(|_| DecodeError::Utf8)
    }
    fn public_key(&mut self) -> Result<[u8; 32], DecodeError> {
        let kind = self.u8()?;
        if kind != KEY_TYPE_ED25519 {
            return Err(DecodeError::KeyType(kind));
        }
        self.array32()
    }
}

pub fn decode(bytes: &[u8]) -> Result<Transaction, DecodeError> {
    let mut r = Reader { bytes, at: 0 };
    let signer_id = r.string("signer_id")?;
    let public_key = r.public_key()?;
    let nonce = r.u64()?;
    let receiver_id = r.string("receiver_id")?;
    let block_hash = r.array32()?;
    let count = r.u32()? as usize;
    if count > MAX_ACTIONS {
        return Err(DecodeError::TooLong("actions"));
    }
    let mut actions = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = r.u8()?;
        if kind != ACTION_FUNCTION_CALL {
            return Err(DecodeError::UnsupportedAction(kind));
        }
        let method_name = r.string("method_name")?;
        let args = r.bytes(MAX_ARGS, "args")?;
        let gas = r.u64()?;
        let deposit = r.u128()?;
        actions.push(Action::FunctionCall(FunctionCall {
            method_name,
            args,
            gas,
            deposit,
        }));
    }
    if r.at != bytes.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(Transaction {
        signer_id,
        public_key,
        nonce,
        receiver_id,
        block_hash,
        actions,
    })
}

/// Borsh encoding of a transaction, used by tests and by callers that build one.
pub fn encode(tx: &Transaction) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u32).to_le_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    let mut out = Vec::new();
    string(&mut out, &tx.signer_id);
    out.push(KEY_TYPE_ED25519);
    out.extend_from_slice(&tx.public_key);
    out.extend_from_slice(&tx.nonce.to_le_bytes());
    string(&mut out, &tx.receiver_id);
    out.extend_from_slice(&tx.block_hash);
    out.extend_from_slice(&(tx.actions.len() as u32).to_le_bytes());
    for action in &tx.actions {
        match action {
            Action::FunctionCall(call) => {
                out.push(ACTION_FUNCTION_CALL);
                string(&mut out, &call.method_name);
                out.extend_from_slice(&(call.args.len() as u32).to_le_bytes());
                out.extend_from_slice(&call.args);
                out.extend_from_slice(&call.gas.to_le_bytes());
                out.extend_from_slice(&call.deposit.to_le_bytes());
            }
            // Transfer { deposit: u128 } is the simplest other action; tests use it.
            Action::Other(kind) => {
                out.push(*kind);
                out.extend_from_slice(&1u128.to_le_bytes());
            }
        }
    }
    out
}
