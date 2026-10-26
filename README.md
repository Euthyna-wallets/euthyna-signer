# euthyna-signer

Keeps an Euthyna agent's keys out of the AI's reach. The AI can ask the signer
to sign **a request to its company's vault**, and nothing else. It cannot read
the key, export it, or have it sign anything else.

```
 user "alice" (the AI and its MCP server)          user "euthyna-signer"
┌──────────────────────────────────────┐          ┌─────────────────────────────────────────┐
│ Claude / Cursor / any agent          │          │ euthyna-signer serve                    │
│   └─ Euthyna MCP server              │  Unix    │   /var/lib/euthyna-signer/agents/*.json │
│        • builds the NEAR transaction │  socket  │     (0600, directory 0700)              │
│        • holds NO key, NO API key    │ ───────▶ │   1. who is calling? (peer UID)         │
│                                      │ ◀─────── │   2. decode the whole transaction       │
└──────────────────────────────────────┘          │   3. vault + allowed method only        │
                                                  │   4. sign, write the audit log          │
                                                  └─────────────────────────────────────────┘
```

## What it guarantees

| The AI tries to… | Result |
| --- | --- |
| read the key file | `Permission denied`: the file belongs to another system user (mode 0600, directory 0700) |
| ask the signer for the key | there is no such operation; anything but `status`, `public_key`, `sign_near_tx`, `api` is `UNKNOWN_OP` |
| have it sign a NEAR transfer, an `AddKey`, a call to another contract | refused: `ACTION_NOT_ALLOWED`, `RECEIVER_NOT_ALLOWED` |
| have it sign a vault method outside the list | refused: `METHOD_NOT_ALLOWED` |
| batch several actions, attach a deposit, raise the gas | refused: `TOO_MANY_ACTIONS`, `DEPOSIT_TOO_HIGH`, `GAS_TOO_HIGH` |
| sign as another account or key | refused: `SIGNER_MISMATCH`, `KEY_MISMATCH` |
| hide bytes after the transaction | refused: `MALFORMED_TRANSACTION` |
| use the agent API key for something else | only the agent endpoints are forwarded (`PATH_NOT_ALLOWED` otherwise) |
| connect from another system user | refused: `UID_NOT_ALLOWED` (kernel-checked peer credentials) |
| sign in a loop | refused after `rate_per_minute`: `RATE_LIMITED` |
| read the audit log | `Permission denied` |

The signer receives the **whole unsigned transaction**, never a hash, so it
always knows what it signs. Its decoder understands exactly one action kind
(`FunctionCall`) and rejects the rest before any check runs.

What a signed request can do is decided on chain: the vault checks the
agent's role, budget and the Guard's visa, and only NEAR MPC signs money
movements. A stolen request is still bounded by the role.

## What it does not protect against

- **root** on the machine can read everything. Do not give the agent `sudo`
  or access to Docker (membership of the `docker` group is root).
- An agent running **as the `euthyna-signer` user** can read the key. Run the
  agent as a normal user.
- An agent that can run `sudo` can become root. Run the agent as a user
  without `sudo`, or at least without cached `sudo` (`Defaults timestamp_timeout=0`).
- Linux and macOS (Unix sockets and kernel peer credentials). On Windows, run
  the agent and the signer in WSL 2 for now.

## Protocol

One JSON object per line on the socket, one reply per line.

```json
→ {"op":"status"}
← {"ok":true,"version":"0.1.0","agents":["naomi-agent.euthyna.testnet"]}

→ {"op":"public_key","agent":"naomi-agent.euthyna.testnet"}
← {"ok":true,"public_key":"ed25519:…"}

→ {"op":"sign_near_tx","agent":"naomi-agent.euthyna.testnet","tx_borsh_b64":"<Borsh Transaction, base64>"}
← {"ok":true,"signature":"ed25519:…","public_key":"ed25519:…","tx_hash":"…"}
← {"ok":false,"error":"METHOD_NOT_ALLOWED","detail":"ft_transfer"}

→ {"op":"api","agent":"…","method":"POST","path":"/v1/operations/pay","body":{…}}
← {"ok":true,"status":200,"body":{…}}
```

`signature` is ed25519 over `sha256(tx_borsh)`, as NEAR expects; the caller
builds the `SignedTransaction` and sends it. NEAR's own access-key nonce
prevents replay on chain.

## Install (Linux, systemd)

```bash
cargo build --release
sudo sh packaging/install-linux.sh target/release/euthyna-signer alice   # alice = the user the AI runs as
sudo -u euthyna-signer euthyna-signer add-agent \
  --account naomi-agent.euthyna.testnet --vault acme-vault.euthyna.testnet
# prints the PUBLIC key to register for the agent (onboarding vote)
```

To let the signer keep the agent's API key as well, so the MCP server has no
secret at all:

```bash
sudo -u euthyna-signer euthyna-signer set-api --account naomi-agent.euthyna.testnet --api-url https://api.euthyna.ai
# paste the API key shown once by the console, Enter, Ctrl-D
```

The unit (`packaging/systemd/euthyna-signer.service`) runs the daemon with no
capabilities, a read-only system, no access to `/home`, and its own state,
runtime and log directories.

## Install (macOS, launchd)

```bash
cargo build --release
sudo sh packaging/install-macos.sh target/release/euthyna-signer alice
sudo -u _euthyna-signer euthyna-signer --config /usr/local/etc/euthyna-signer/config.json \
  add-agent --account naomi-agent.euthyna.testnet --vault acme-vault.euthyna.testnet
```

The script creates a hidden system user `_euthyna-signer` and a group
`_euthyna` (ids in 200–399), puts the agent users in the group, writes the
config under `/usr/local/etc/euthyna-signer`, and loads
`/Library/LaunchDaemons/ai.euthyna.signer.plist`.

## Rotate a key

```bash
sudo -u euthyna-signer euthyna-signer rotate  --account naomi-agent.euthyna.testnet   # prints the next key
# register the next key by vote, then:
sudo -u euthyna-signer euthyna-signer promote --account naomi-agent.euthyna.testnet
```

## Develop

```bash
cargo test          # policy, decoder against near-api-js bytes, socket UID check
cargo clippy --all-targets -- -D warnings
```

Rust edition 2024, Rust 1.99.1 (pinned in `rust-toolchain.toml`).
