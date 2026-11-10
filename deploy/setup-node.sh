#!/usr/bin/env bash
# Set up a heritage hosting node on Debian/Ubuntu/Raspberry Pi OS (amd64 or arm64).
# Run from a checkout of this repo, as a user with sudo:
#
#   sudo deploy/setup-node.sh path/to/allowed_signers
#
# Installs Kubo (IPFS) and the node as two systemd services running as the
# "heritage" user, with everything under /var/lib/heritage-node and config in
# /etc/heritage-node. Safe to re-run: it updates the code and keeps the config.
#
# Override ports if something else on the machine already uses IPFS's defaults:
#   IPFS_SWARM_PORT=4001 IPFS_API_PORT=5001 IPFS_GATEWAY_PORT=8080
set -euo pipefail

SIGNERS="${1:?usage: setup-node.sh ALLOWED_SIGNERS_FILE}"
KUBO_VERSION="${KUBO_VERSION:-v0.43.1}"
SWARM="${IPFS_SWARM_PORT:-4001}"
API="${IPFS_API_PORT:-5001}"
GATEWAY="${IPFS_GATEWAY_PORT:-8080}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
CODE=/opt/heritage-node
ETC=/etc/heritage-node
VAR=/var/lib/heritage-node
export IPFS_PATH="$VAR/ipfs"

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -f "$SIGNERS" ] || { echo "$SIGNERS not found" >&2; exit 1; }

echo "==> packages"
apt-get update -q
apt-get install -y -q git python3 curl openssh-client
python3 -c 'import tomllib' 2>/dev/null || apt-get install -y -q python3-tomli

echo "==> kubo $KUBO_VERSION"
if ! command -v ipfs >/dev/null || ! ipfs version | grep -q "${KUBO_VERSION#v}"; then
  tmp=$(mktemp -d)
  arch=$(dpkg --print-architecture)
  url="https://github.com/ipfs/kubo/releases/download/$KUBO_VERSION/kubo_${KUBO_VERSION}_linux-$arch.tar.gz"
  curl -fsSL -o "$tmp/kubo.tgz" "$url"
  curl -fsSL "$url.sha512" | sed "s#kubo_.*#$tmp/kubo.tgz#" | sha512sum -c -
  tar -xzf "$tmp/kubo.tgz" -C "$tmp"
  install -m 755 "$tmp/kubo/ipfs" /usr/local/bin/ipfs
  rm -rf "$tmp"
fi

echo "==> user and directories"
id heritage >/dev/null 2>&1 || useradd --system --home-dir "$VAR" --shell /usr/sbin/nologin heritage
install -d -o heritage -g heritage -m 750 "$VAR" "$VAR/data"
install -d -m 755 "$CODE" "$ETC"
install -m 644 "$SRC/heritage_add.py" "$SRC/heritage_node.py" "$CODE/"
install -m 644 "$SIGNERS" "$ETC/allowed_signers"

echo "==> ipfs repo"
as_heritage() { sudo -u heritage env IPFS_PATH="$IPFS_PATH" "$@"; }
[ -d "$IPFS_PATH" ] || as_heritage ipfs init --profile server >/dev/null
as_heritage ipfs config Addresses.API "/ip4/127.0.0.1/tcp/$API"
as_heritage ipfs config Addresses.Gateway "/ip4/127.0.0.1/tcp/$GATEWAY"   # never an open gateway
as_heritage ipfs config --json Addresses.Swarm \
  "[\"/ip4/0.0.0.0/tcp/$SWARM\",\"/ip6/::/tcp/$SWARM\",\"/ip4/0.0.0.0/udp/$SWARM/quic-v1\",\"/ip6/::/udp/$SWARM/quic-v1\"]"

echo "==> config"
if [ ! -f "$ETC/node.toml" ]; then
  sed -e "s#^allowed_signers = .*#allowed_signers = \"$ETC/allowed_signers\"#" \
      -e "s#^data_dir = .*#data_dir = \"$VAR/data\"#" \
      -e "s#^\# ipfs_path = .*#ipfs_path = \"$IPFS_PATH\"#" \
      "$SRC/node.example.toml" > "$ETC/node.toml"
  echo "    wrote $ETC/node.toml: edit max_storage and favourites"
fi

echo "==> services"
cat > /etc/systemd/system/heritage-ipfs.service <<EOF
[Unit]
Description=IPFS daemon for the heritage node
After=network-online.target
Wants=network-online.target

[Service]
User=heritage
Environment=IPFS_PATH=$IPFS_PATH
ExecStart=/usr/local/bin/ipfs daemon --migrate
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$VAR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/heritage-node.service <<EOF
[Unit]
Description=Heritage hosting node
After=heritage-ipfs.service
Requires=heritage-ipfs.service

[Service]
User=heritage
Environment=IPFS_PATH=$IPFS_PATH PYTHONDONTWRITEBYTECODE=1
ExecStartPre=/bin/sh -c 'for i in \$(seq 60); do /usr/local/bin/ipfs --api=/ip4/127.0.0.1/tcp/$API id >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'
ExecStart=/usr/bin/python3 $CODE/heritage_node.py run --config $ETC/node.toml
Restart=on-failure
RestartSec=30
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$VAR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now heritage-ipfs.service
systemctl enable heritage-node.service
systemctl restart heritage-node.service

if command -v ufw >/dev/null && ufw status | grep -q active; then
  ufw allow "$SWARM/tcp" >/dev/null && ufw allow "$SWARM/udp" >/dev/null
  echo "    opened IPFS port $SWARM in ufw"
fi

echo
echo "Done. Logs:      journalctl -u heritage-node -f"
echo "Review UI:       ssh -L 8090:127.0.0.1:8090 <this machine>, then http://127.0.0.1:8090/"
echo "IPFS must be reachable on port $SWARM (tcp+udp) for others to fetch the photos."
