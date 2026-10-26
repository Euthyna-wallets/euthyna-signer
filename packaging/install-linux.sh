#!/bin/sh
# Installs euthyna-signer as a systemd service under its own user.
# Usage: sudo sh install-linux.sh <path-to-binary> <agent-user> [<agent-user>...]
#   <agent-user>: the system user(s) the AI agent runs as; only they may use the signer.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
[ $# -ge 2 ] || { echo "usage: sudo sh $0 <binary> <agent-user>..." >&2; exit 1; }
BIN=$1; shift

getent group euthyna >/dev/null || groupadd --system euthyna
id euthyna-signer >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /var/lib/euthyna-signer \
  --shell /usr/sbin/nologin --user-group euthyna-signer
usermod -aG euthyna euthyna-signer

install -m 0755 "$BIN" /usr/local/bin/euthyna-signer
install -d -m 0755 /etc/euthyna-signer

UIDS=""
for user in "$@"; do
  uid=$(id -u "$user")
  [ "$uid" -ne 0 ] || { echo "refusing: the agent must not run as root" >&2; exit 1; }
  usermod -aG euthyna "$user"
  UIDS="${UIDS:+$UIDS,}$uid"
done
GID=$(getent group euthyna | cut -d: -f3)

cat > /etc/euthyna-signer/config.json <<JSON
{
  "socket_path": "/run/euthyna-signer/signer.sock",
  "socket_gid": $GID,
  "allowed_uids": [$UIDS],
  "state_dir": "/var/lib/euthyna-signer",
  "audit_log": "/var/log/euthyna-signer/audit.log",
  "rate_per_minute": 30
}
JSON
chmod 0644 /etc/euthyna-signer/config.json

install -m 0644 "$(dirname "$0")/systemd/euthyna-signer.service" /etc/systemd/system/euthyna-signer.service
systemctl daemon-reload
systemctl enable --now euthyna-signer

echo "euthyna-signer is running. Add an agent with:"
echo "  sudo -u euthyna-signer euthyna-signer add-agent --account <agent>.testnet --vault <vault>.testnet"
echo "Agent users must log in again to pick up the 'euthyna' group."
