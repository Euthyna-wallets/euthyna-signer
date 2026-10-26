#!/bin/sh
# euthyna-signer installer (Linux with systemd, or macOS with launchd).
#
#   curl -fsSL https://raw.githubusercontent.com/joindefi/euthyna-signer/main/install.sh | sudo sh
#
# What it does, once per machine:
#   - downloads the release binary for this OS/CPU and checks its SHA-256;
#   - creates a system user that alone can read agent keys, and a group whose
#     members (the user who ran sudo, by default) may talk to the signer;
#   - writes the config and starts the service.
#
# Options (environment variables):
#   EUTHYNA_AGENT_USERS  users the AI runs as (default: the user who ran sudo)
#   EUTHYNA_SIGNER_VERSION  release tag (default: latest)
#   EUTHYNA_SIGNER_BIN   install this local binary instead of downloading
#   EUTHYNA_NO_SERVICE=1 write everything but do not start the service
set -eu

REPO="joindefi/euthyna-signer"
say() { printf '  %s\n' "$*"; }
die() { printf 'euthyna-signer install: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run it with sudo: curl -fsSL … | sudo sh"

OS=$(uname -s)
ARCH=$(uname -m)
case "$OS/$ARCH" in
  Linux/x86_64) TARGET=x86_64-unknown-linux-gnu ;;
  Linux/aarch64 | Linux/arm64) TARGET=aarch64-unknown-linux-gnu ;;
  Darwin/arm64) TARGET=aarch64-apple-darwin ;;
  Darwin/x86_64) TARGET=x86_64-apple-darwin ;;
  *) die "unsupported system $OS/$ARCH (Linux or macOS; on Windows use WSL 2)" ;;
esac

AGENT_USERS=${EUTHYNA_AGENT_USERS:-${SUDO_USER:-}}
[ -n "$AGENT_USERS" ] || die "tell me which user runs the AI: EUTHYNA_AGENT_USERS=alice … | sudo -E sh"
for user in $AGENT_USERS; do
  id "$user" >/dev/null 2>&1 || die "no such user: $user"
  [ "$(id -u "$user")" -ne 0 ] || die "the AI must not run as root"
done

# 1. The binary ---------------------------------------------------------------
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
if [ -n "${EUTHYNA_SIGNER_BIN:-}" ]; then
  cp "$EUTHYNA_SIGNER_BIN" "$WORK/euthyna-signer"
else
  command -v curl >/dev/null || die "curl is required"
  VERSION=${EUTHYNA_SIGNER_VERSION:-latest}
  if [ "$VERSION" = latest ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
  else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
  fi
  ASSET="euthyna-signer-$TARGET.tar.gz"
  say "downloading $ASSET"
  curl -fsSL "$BASE/$ASSET" -o "$WORK/$ASSET" || die "download failed: $BASE/$ASSET"
  curl -fsSL "$BASE/$ASSET.sha256" -o "$WORK/$ASSET.sha256" || die "checksum download failed"
  expected=$(awk '{print $1}' "$WORK/$ASSET.sha256")
  if command -v sha256sum >/dev/null; then
    actual=$(sha256sum "$WORK/$ASSET" | awk '{print $1}')
  else
    actual=$(shasum -a 256 "$WORK/$ASSET" | awk '{print $1}')
  fi
  [ "$expected" = "$actual" ] || die "checksum mismatch for $ASSET: refusing to install"
  tar -xzf "$WORK/$ASSET" -C "$WORK"
fi
chmod 0755 "$WORK/euthyna-signer"
"$WORK/euthyna-signer" --version >/dev/null || die "the binary does not run on this machine"

# 2. Users, directories, config ----------------------------------------------
write_config() { # socket gid uids state audit path
  cat > "$6" <<JSON
{
  "socket_path": "$1",
  "socket_gid": $2,
  "allowed_uids": [$3],
  "state_dir": "$4",
  "audit_log": "$5",
  "rate_per_minute": 30
}
JSON
  chmod 0644 "$6"
}

UIDS=""
for user in $AGENT_USERS; do UIDS="${UIDS:+$UIDS,}$(id -u "$user")"; done

if [ "$OS" = Linux ]; then
  SIGNER_USER=euthyna-signer
  GROUP=euthyna
  getent group "$GROUP" >/dev/null || groupadd --system "$GROUP"
  id "$SIGNER_USER" >/dev/null 2>&1 || useradd --system --no-create-home \
    --home-dir /var/lib/euthyna-signer --shell /usr/sbin/nologin --gid "$GROUP" "$SIGNER_USER"
  for user in $AGENT_USERS; do usermod -aG "$GROUP" "$user"; done
  GID=$(getent group "$GROUP" | cut -d: -f3)

  install -m 0755 "$WORK/euthyna-signer" /usr/local/bin/euthyna-signer
  install -d -m 0755 /etc/euthyna-signer
  install -d -m 0700 -o "$SIGNER_USER" -g "$GROUP" /var/lib/euthyna-signer
  install -d -m 0750 -o "$SIGNER_USER" -g "$GROUP" /var/log/euthyna-signer
  write_config /run/euthyna-signer/signer.sock "$GID" "$UIDS" /var/lib/euthyna-signer \
    /var/log/euthyna-signer/audit.log /etc/euthyna-signer/config.json

  cat > /etc/systemd/system/euthyna-signer.service <<'UNIT'
[Unit]
Description=Euthyna signer: holds agent keys outside the AI's reach
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=euthyna-signer
Group=euthyna
ExecStart=/usr/local/bin/euthyna-signer --config /etc/euthyna-signer/config.json serve
Restart=on-failure
RestartSec=2
RuntimeDirectory=euthyna-signer
RuntimeDirectoryMode=0750
StateDirectory=euthyna-signer
StateDirectoryMode=0700
LogsDirectory=euthyna-signer
LogsDirectoryMode=0750
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
UNIT
  if [ -z "${EUTHYNA_NO_SERVICE:-}" ]; then
    systemctl daemon-reload
    systemctl enable --now euthyna-signer >/dev/null
    systemctl restart euthyna-signer
  fi
  SOCKET=/run/euthyna-signer/signer.sock
else
  SIGNER_USER=_euthyna-signer
  GROUP=_euthyna
  free_id() {
    used=$( (dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID) | awk '{print $2}')
    n=200
    while [ $n -lt 400 ]; do
      echo "$used" | grep -qx "$n" || { echo $n; return; }
      n=$((n + 1))
    done
    die "no free system id between 200 and 399"
  }
  if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    gid=$(free_id)
    dscl . -create "/Groups/$GROUP" PrimaryGroupID "$gid"
    dscl . -create "/Groups/$GROUP" RealName "Euthyna signer clients"
    dscl . -create "/Groups/$GROUP" Password '*'
  fi
  GID=$(dscl . -read "/Groups/$GROUP" PrimaryGroupID | awk '{print $2}')
  if ! dscl . -read "/Users/$SIGNER_USER" >/dev/null 2>&1; then
    uid=$(free_id)
    dscl . -create "/Users/$SIGNER_USER" UniqueID "$uid"
    dscl . -create "/Users/$SIGNER_USER" PrimaryGroupID "$GID"
    dscl . -create "/Users/$SIGNER_USER" UserShell /usr/bin/false
    dscl . -create "/Users/$SIGNER_USER" NFSHomeDirectory /var/empty
    dscl . -create "/Users/$SIGNER_USER" RealName "Euthyna signer"
    dscl . -create "/Users/$SIGNER_USER" Password '*'
    dscl . -create "/Users/$SIGNER_USER" IsHidden 1
  fi
  for user in $AGENT_USERS; do dseditgroup -o edit -a "$user" -t user "$GROUP"; done

  ETC=/usr/local/etc/euthyna-signer
  STATE=/usr/local/var/lib/euthyna-signer
  RUN=/usr/local/var/run/euthyna-signer
  LOG=/usr/local/var/log/euthyna-signer
  install -d -m 0755 /usr/local/bin "$ETC"
  install -m 0755 "$WORK/euthyna-signer" /usr/local/bin/euthyna-signer
  install -d -m 0700 -o "$SIGNER_USER" -g "$GROUP" "$STATE"
  install -d -m 0750 -o "$SIGNER_USER" -g "$GROUP" "$RUN" "$LOG"
  write_config "$RUN/signer.sock" "$GID" "$UIDS" "$STATE" "$LOG/audit.log" "$ETC/config.json"

  PLIST=/Library/LaunchDaemons/ai.euthyna.signer.plist
  cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>ai.euthyna.signer</string>
  <key>UserName</key><string>$SIGNER_USER</string>
  <key>GroupName</key><string>$GROUP</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/euthyna-signer</string>
    <string>--config</string>
    <string>$ETC/config.json</string>
    <string>serve</string>
  </array>
  <key>Umask</key><integer>63</integer>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$LOG/daemon.log</string>
</dict>
</plist>
PLIST
  chown root:wheel "$PLIST"
  chmod 0644 "$PLIST"
  if [ -z "${EUTHYNA_NO_SERVICE:-}" ]; then
    launchctl bootout system "$PLIST" 2>/dev/null || true
    launchctl bootstrap system "$PLIST"
  fi
  SOCKET="$RUN/signer.sock"
fi

echo
say "euthyna-signer $(/usr/local/bin/euthyna-signer --version | awk '{print $2}') is installed."
say "Keys: readable only by $SIGNER_USER. Socket: $SOCKET (users: $AGENT_USERS)."
say "Next, when you hire an agent, the console shows a command like:"
say "  sudo euthyna-signer add-agent <agent>.testnet --vault <vault>.testnet --api-url <API>"
say "Log out and back in once, so $AGENT_USERS picks up the '$GROUP' group."
