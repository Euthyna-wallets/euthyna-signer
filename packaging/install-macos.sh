#!/bin/sh
# Installs euthyna-signer as a launchd daemon under its own hidden system user.
# Usage: sudo sh install-macos.sh <path-to-binary> <agent-user> [<agent-user>...]
#   <agent-user>: the macOS user(s) the AI agent runs as; only they may use the signer.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
[ "$(uname -s)" = "Darwin" ] || { echo "this script is for macOS" >&2; exit 1; }
[ $# -ge 2 ] || { echo "usage: sudo sh $0 <binary> <agent-user>..." >&2; exit 1; }
BIN=$1; shift
HERE=$(cd "$(dirname "$0")" && pwd)

# First free id in the hidden system range (200-399) for both the user and the group.
free_id() {
  used=$( (dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID) | awk '{print $2}')
  id=200
  while [ $id -lt 400 ]; do
    echo "$used" | grep -qx "$id" || { echo $id; return; }
    id=$((id + 1))
  done
  echo "no free system id between 200 and 399" >&2; exit 1
}

if ! dscl . -read /Groups/_euthyna >/dev/null 2>&1; then
  gid=$(free_id)
  dscl . -create /Groups/_euthyna
  dscl . -create /Groups/_euthyna PrimaryGroupID "$gid"
  dscl . -create /Groups/_euthyna RealName "Euthyna signer clients"
  dscl . -create /Groups/_euthyna Password '*'
fi
GID=$(dscl . -read /Groups/_euthyna PrimaryGroupID | awk '{print $2}')

if ! dscl . -read /Users/_euthyna-signer >/dev/null 2>&1; then
  uid=$(free_id)
  dscl . -create /Users/_euthyna-signer
  dscl . -create /Users/_euthyna-signer UniqueID "$uid"
  dscl . -create /Users/_euthyna-signer PrimaryGroupID "$GID"
  dscl . -create /Users/_euthyna-signer UserShell /usr/bin/false
  dscl . -create /Users/_euthyna-signer NFSHomeDirectory /var/empty
  dscl . -create /Users/_euthyna-signer RealName "Euthyna signer"
  dscl . -create /Users/_euthyna-signer Password '*'
  dscl . -create /Users/_euthyna-signer IsHidden 1
fi
dseditgroup -o edit -a _euthyna-signer -t user _euthyna

UIDS=""
for user in "$@"; do
  uid=$(id -u "$user")
  [ "$uid" -ne 0 ] || { echo "refusing: the agent must not run as root" >&2; exit 1; }
  dseditgroup -o edit -a "$user" -t user _euthyna
  UIDS="${UIDS:+$UIDS,}$uid"
done

ETC=/usr/local/etc/euthyna-signer
STATE=/usr/local/var/lib/euthyna-signer
RUN=/usr/local/var/run/euthyna-signer
LOG=/usr/local/var/log/euthyna-signer
install -d -m 0755 /usr/local/bin "$ETC"
install -m 0755 "$BIN" /usr/local/bin/euthyna-signer
install -d -m 0700 -o _euthyna-signer -g _euthyna "$STATE"
install -d -m 0750 -o _euthyna-signer -g _euthyna "$RUN" "$LOG"

cat > "$ETC/config.json" <<JSON
{
  "socket_path": "$RUN/signer.sock",
  "socket_gid": $GID,
  "allowed_uids": [$UIDS],
  "state_dir": "$STATE",
  "audit_log": "$LOG/audit.log",
  "rate_per_minute": 30
}
JSON
chmod 0644 "$ETC/config.json"

PLIST=/Library/LaunchDaemons/ai.euthyna.signer.plist
install -m 0644 -o root -g wheel "$HERE/macos/ai.euthyna.signer.plist" "$PLIST"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"

echo "euthyna-signer is running. Add an agent with:"
echo "  sudo -u _euthyna-signer euthyna-signer --config $ETC/config.json add-agent --account <agent>.testnet --vault <vault>.testnet"
echo "Agent users must log out and back in to pick up the '_euthyna' group."
