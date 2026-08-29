#!/usr/bin/env bash
# Demo PKI for example 08 (mutual TLS). DEMO ONLY — a throw-away CA with well-known key material.
#
#   scripts/gen-certs.sh                      → examples/08-mtls/certs/ (git-ignored)
#   OUT_DIR=/tmp/certs PUBLIC_HOST=10.0.0.5 scripts/gen-certs.sh
#
# Produces:
#   ca.crt / ca.key                 the demo CA that both sides trust
#   server.crt / server.key         SAN: IP:<PUBLIC_HOST>, IP:127.0.0.1, DNS:localhost
#   alice.crt / alice.key           client cert, OU=mcp-user   → scopes [mcp:tools]
#   bob.crt / bob.key               client cert, OU=mcp-admin  → scopes [mcp:tools, mcp:admin]
#   expired-alice.crt / .key        client cert whose validity ended yesterday (negative path)
#   rogue-ca.crt / rogue-ca.key     a second CA the server does NOT trust
#   rogue-client.crt / .key         client cert signed by the rogue CA (negative path)
# Requires openssl ≥ 3.5 for -not_before/-not_after (used for the expired certificate).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$ROOT/.env" ] && set -a && . "$ROOT/.env" && set +a
OUT_DIR="${OUT_DIR:-$ROOT/examples/08-mtls/certs}"
if [ -z "${PUBLIC_HOST:-}" ]; then
  PUBLIC_HOST="$(node -e 'const o=require("os").networkInterfaces();for(const k of Object.keys(o))for(const a of o[k])if(a.family==="IPv4"&&!a.internal){console.log(a.address);process.exit(0)}console.log("127.0.0.1")')"
fi
DAYS="${DAYS:-3650}"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

if [ -f ca.crt ] && [ "${1:-}" != "--force" ]; then
  echo "certificates exist in $OUT_DIR (use --force to regenerate)"; exit 0
fi

ca() { # name subject
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key" 2>/dev/null
  openssl req -x509 -new -key "$1.key" -sha256 -days "$DAYS" -subj "$2" -out "$1.crt" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}
leaf() { # name subject ca extfile [extra openssl x509 args…]
  local name="$1" subject="$2" caname="$3" ext="$4"; shift 4
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$name.key" 2>/dev/null
  openssl req -new -key "$name.key" -subj "$subject" -out "$name.csr" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA "$caname.crt" -CAkey "$caname.key" -CAcreateserial -sha256 \
    -extfile "$ext" -out "$name.crt" "$@" 2>/dev/null
  rm -f "$name.csr"
}

ca ca "/CN=mcp-auth-demo CA/O=mcp-auth-demo DEMO"
ca rogue-ca "/CN=rogue CA/O=not trusted"

cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:${PUBLIC_HOST},IP:127.0.0.1,DNS:localhost
EOF
cat > client.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF

leaf server "/CN=${PUBLIC_HOST}/O=mcp-auth-demo DEMO" ca server.ext -days "$DAYS"
leaf alice "/CN=alice/OU=mcp-user/O=mcp-auth-demo DEMO" ca client.ext -days "$DAYS"
leaf bob "/CN=bob/OU=mcp-admin/O=mcp-auth-demo DEMO" ca client.ext -days "$DAYS"
# validity window entirely in the past → TLS handshake failure (certificate expired)
leaf expired-alice "/CN=alice/OU=mcp-user/O=mcp-auth-demo DEMO" ca client.ext \
  -not_before "$(date -u -d '30 days ago' +%Y%m%d%H%M%SZ)" -not_after "$(date -u -d '1 day ago' +%Y%m%d%H%M%SZ)"
leaf rogue-client "/CN=alice/OU=mcp-admin/O=rogue" rogue-ca client.ext -days "$DAYS"

rm -f server.ext client.ext ./*.srl
chmod 600 ./*.key
echo "demo PKI written to $OUT_DIR (server SAN: IP:${PUBLIC_HOST}, IP:127.0.0.1, DNS:localhost)"
for f in server alice bob expired-alice rogue-client; do
  printf '  %-14s %s\n' "$f" "$(openssl x509 -in "$f.crt" -noout -subject -enddate | tr '\n' ' ')"
done
