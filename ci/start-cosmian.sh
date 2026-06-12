#!/usr/bin/env bash
# Starts a throwaway Cosmian KMS for the kmipclient integration tests.
# Usage: ci/start-cosmian.sh <workdir>
# Uses cosmian_kms from PATH, or $COSMIAN_KMS_BIN when set.
# Appends KMIP_* test variables to $GITHUB_ENV when set (CI);
# otherwise prints "export KMIP_*=..." lines for eval (local use).
# The server keeps running; stop it with: kill "$(cat <workdir>/cosmian.pid)"
set -euo pipefail

WORKDIR="${1:?usage: start-cosmian.sh <workdir>}"
BIN="${COSMIAN_KMS_BIN:-$(command -v cosmian_kms || true)}"
if [ -z "$BIN" ]; then
  echo "cosmian_kms not found on PATH; install it or set COSMIAN_KMS_BIN" >&2
  exit 1
fi
mkdir -p "$WORKDIR"
WORKDIR="$(cd "$WORKDIR" && pwd)"
cd "$WORKDIR"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout ca.key -out ca.pem -subj '/CN=libkmip-test-ca'
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1'
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 1 -out server.pem -copy_extensions copy
openssl pkcs12 -export -out server.p12 -inkey server.key -in server.pem \
  -password pass:test
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj '/CN=libkmip-test-client'
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 1 -out client.pem

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
KMIP_PORT="$(free_port)"
HTTP_PORT="$(free_port)"

cat > kms.toml <<TOML
default_username = "admin"

[db]
database_type = "sqlite"
sqlite_path   = "$WORKDIR/db"
clear_database = true

[tls]
tls_p12_file         = "$WORKDIR/server.p12"
tls_p12_password     = "test"
clients_ca_cert_file = "$WORKDIR/ca.pem"

[socket_server]
socket_server_start    = true
socket_server_port     = $KMIP_PORT
socket_server_hostname = "127.0.0.1"

[http]
port     = $HTTP_PORT
hostname = "127.0.0.1"

[logging]
rust_log = "info,cosmian_kms=info"
TOML

# Cosmian needs OPENSSL_MODULES; autodetect common locations when unset.
if [ -z "${OPENSSL_MODULES:-}" ]; then
  for d in /usr/local/cosmian/lib/ossl-modules /usr/lib64/ossl-modules \
           /usr/lib/x86_64-linux-gnu/ossl-modules \
           /usr/lib/aarch64-linux-gnu/ossl-modules; do
    if [ -d "$d" ]; then
      export OPENSSL_MODULES="$d"
      break
    fi
  done
fi

"$BIN" -c "$WORKDIR/kms.toml" > "$WORKDIR/cosmian.log" 2>&1 &
echo $! > "$WORKDIR/cosmian.pid"

ready=""
for _ in $(seq 1 75); do  # 15 s total, 200 ms steps
  if curl -fsSk -m 1 "https://127.0.0.1:$HTTP_PORT/version" > /dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.2
done
if [ -z "$ready" ]; then
  echo "cosmian_kms did not become ready within 15s" >&2
  cat "$WORKDIR/cosmian.log" >&2
  kill "$(cat "$WORKDIR/cosmian.pid")" 2> /dev/null || true
  exit 1
fi

VARS="KMIP_ADDR=127.0.0.1
KMIP_PORT=$KMIP_PORT
KMIP_CLIENT_CA=$WORKDIR/client.pem
KMIP_CLIENT_KEY=$WORKDIR/client.key
KMIP_SERVER_CA=$WORKDIR/ca.pem
KMIP_TIMEOUT_MS=5000
KMIP_RUN_2_0_TESTS=1"

if [ -n "${GITHUB_ENV:-}" ]; then
  echo "$VARS" >> "$GITHUB_ENV"
else
  echo "$VARS" | sed 's/^/export /'
fi
