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
| ask the signer for the key | there is no such operation; anything but `status`, `public_key`, `agent_info`, `card_info`, `sign_near_tx`, `sign_delegate`, `api` is `UNKNOWN_OP`; `agent_info` and `card_info` return public facts only |
| have the card sign anything but a payment | refused: one `ft_transfer` of the card's token only, 1 yoctoNEAR, at most 30 Tgas, `receiver_id` + `amount` (+ printable `memo`) and nothing else, amount up to the card's cap (`METHOD_NOT_ALLOWED`, `RECEIVER_NOT_ALLOWED`, `AMOUNT_NOT_ALLOWED`…) |
| have it sign a NEAR transfer, an `AddKey`, a call to another contract | refused: `ACTION_NOT_ALLOWED`, `RECEIVER_NOT_ALLOWED` |
| have it sign a vault method outside the list | refused: `METHOD_NOT_ALLOWED` |
| batch several actions, attach a deposit, raise the gas | refused: `TOO_MANY_ACTIONS`, `DEPOSIT_TOO_HIGH`, `GAS_TOO_HIGH` |
| sign as another account or key | refused: `SIGNER_MISMATCH`, `KEY_MISMATCH` |
| hide bytes after the transaction | refused: `MALFORMED_TRANSACTION` |
| use the agent API key for something else | only the agent endpoints are forwarded (`PATH_NOT_ALLOWED` otherwise) |
| connect from another system user | refused: `UID_NOT_ALLOWED` (kernel-checked peer credentials) |
| sign in a loop | refused after `rate_per_minute`: `RATE_LIMITED` |
| stockpile cheques to spend after a revocation | each cheque expires within 200 000 blocks of the chain's height, read before signing (`EXPIRES_TOO_LATE`); no height, no signature (`CHAIN_UNREACHABLE`) |
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

## Spending card (market payments)

An agent can have a **card**: a NEAR account next to its own (`<slug>-card.<parent>`) that holds a few tokens
the vault refills by role. The agent pays other agents with it on the Euthyna Market: the signer signs a
NEP-366 delegate action of `ft_transfer`, and the market's relayer sends it once the work is delivered.

```bash
sudo euthyna-signer card larry-09d0b2-agent.euthyna.testnet --max-per-payment 5000000
```

The key is made here; only its public key goes to the Euthyna API, which creates the card account with it and
registers it on the token. The card key is a **full-access** key, because function-call keys cannot attach the
1 yoctoNEAR `ft_transfer` requires (NEAR refuses with `DepositWithFunctionCall`). That is why the signer, not
the chain, limits it: one token, `ft_transfer` only, a cap per payment, the agent's rate limit. The most a
stolen agent can spend is the card's balance, which the vault's role caps per day.

Rules on every cheque, besides the above:

- **Canonical arguments.** The `ft_transfer` arguments must be exactly
  `{"receiver_id":"…","amount":"…"}`, with an optional `"memo"` last, and nothing else: no duplicate keys,
  no other order, no spaces. Whatever the signer checked is therefore what the token contract reads.
- **Short life.** A cheque may not stay valid for more than 200 000 blocks (about a day and a half on
  testnet). Before signing, the signer reads the chain's height. It uses `near_rpc_url` in the config,
  or FastNEAR for testnet and mainnet. If it cannot read the height, it signs nothing
  (`CHAIN_UNREACHABLE`).
- **The AI cannot make the card.** The `api` op does not expose `POST /v1/agent/card`, so only
  `euthyna-signer card`, run by the operator as root, can create one.

**Stopping a card.** There is no revoke command yet. To stop a card, take its tokens out from the vault:
stop refilling and move the balance back. The cheques already signed then have nothing to pay with, and
they expire within the bound above.

## Protocol

One JSON object per line on the socket, one reply per line.

```json
→ {"op":"status"}
← {"ok":true,"version":"0.1.0","agents":["naomi-agent.euthyna.testnet"]}

→ {"op":"public_key","agent":"naomi-agent.euthyna.testnet"}
← {"ok":true,"public_key":"ed25519:…"}

→ {"op":"agent_info","agent":"naomi-agent.euthyna.testnet"}
← {"ok":true,"agent":"…","network":"testnet","vault":"acme-vault.euthyna.testnet","role":"payments","methods":[…],"public_key":"ed25519:…","api":true}

→ {"op":"sign_near_tx","agent":"naomi-agent.euthyna.testnet","tx_borsh_b64":"<Borsh Transaction, base64>"}
← {"ok":true,"signature":"ed25519:…","public_key":"ed25519:…","tx_hash":"…"}
← {"ok":false,"error":"METHOD_NOT_ALLOWED","detail":"ft_transfer"}

→ {"op":"card_info","agent":"larry-09d0b2-agent.euthyna.testnet"}
← {"ok":true,"card":"larry-09d0b2-card.euthyna.testnet","token":"…","max_per_payment":"5000000","public_key":"ed25519:…"}

→ {"op":"sign_delegate","agent":"…","delegate_borsh_b64":"<Borsh DelegateAction, base64>"}
← {"ok":true,"signature":"ed25519:…","public_key":"ed25519:…","hash":"…"}

→ {"op":"api","agent":"…","method":"POST","path":"/v1/operations/pay","body":{…}}
← {"ok":true,"status":200,"body":{…}}
```

`signature` is ed25519 over `sha256(tx_borsh)`, as NEAR expects; the caller
builds the `SignedTransaction` and sends it. NEAR's own access-key nonce
prevents replay on chain.

## Hire an agent

In the Euthyna console, give the agent a name and a role, and click **Hire
agent**. It shows a one-time command for the machine that runs the agent:

```bash
sudo euthyna-signer pair EUT-7K4Q-… --api-url https://api.euthyna.ai
```

The signer makes the key there, sends the API only the **public** key, and
receives the agent's account, vault, role and API key. Nothing is copied by
hand; the API key is never shown. The code works once, for 10 minutes. The
console then creates the agent's NEAR account and checks its key on chain.

Not installed on that machine yet? The console's second command installs, then
pairs:

```bash
curl -fsSL https://raw.githubusercontent.com/joindefi/euthyna-signer/main/install.sh | sudo sh -s -- pair EUT-… --api-url https://…
```

Then plug the agent into the AI. The config holds no secret: the MCP server
finds the socket and reads the vault, role and network from the signer.

```bash
claude mcp add euthyna --env EUTHYNA_AGENT=<agent>.testnet -- npx -y @euthyna/mcp
```

Without the console (or offline), `sudo euthyna-signer add-agent <account>
--vault <vault> --api-url …` makes the key and prints the public key to paste
by hand; `set-api` gives the API key later.

## Install

Once per machine (Linux with systemd, or macOS):

```bash
curl -fsSL https://raw.githubusercontent.com/joindefi/euthyna-signer/main/install.sh | sudo sh
```

The script downloads the release binary for this OS and CPU, checks its
SHA-256, creates a system user that alone can read agent keys
(`euthyna-signer`, or `_euthyna-signer` on macOS) and a group for the users
allowed to talk to it (the user who ran `sudo`, or `EUTHYNA_AGENT_USERS`),
writes the config and starts the service. Read it first if you prefer:
`curl -fsSL …/install.sh -o install.sh && less install.sh && sudo sh install.sh`.

Running it again is safe: an installed signer, its config and its agents are
kept, and the service is not restarted. `EUTHYNA_UPGRADE=1` installs the
latest release; the service restarts only if something changed.

On Linux the service runs with no capabilities, a read-only system and no
access to `/home`. On Windows, use WSL 2.

## Rotate a key

```bash
sudo euthyna-signer rotate naomi-agent.euthyna.testnet    # prints the next key
# register the next key by vote, then:
sudo euthyna-signer promote naomi-agent.euthyna.testnet
```

## Develop

```bash
cargo test          # policy, decoder against near-api-js bytes, socket UID check
cargo clippy --all-targets -- -D warnings
```

Rust edition 2024, Rust 1.99.1 (pinned in `rust-toolchain.toml`).
