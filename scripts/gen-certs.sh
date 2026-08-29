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
# Works with openssl 3.0+ (the expired certificate is issued with `openssl ca -startdate/-enddate`;
# `x509 -not_before/-not_after` would need 3.5+, which CI runners do not have).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Load .env WITHOUT overriding variables the caller exported (same precedence as dotenv
# on the TypeScript side): shell environment wins over .env.
_caller_public_host="${PUBLIC_HOST:-}"; _caller_out_dir="${OUT_DIR:-}"; _caller_days="${DAYS:-}"
[ -f "$ROOT/.env" ] && set -a && . "$ROOT/.env" && set +a
[ -n "$_caller_public_host" ] && PUBLIC_HOST="$_caller_public_host"
[ -n "$_caller_out_dir" ] && OUT_DIR="$_caller_out_dir"
[ -n "$_caller_days" ] && DAYS="$_caller_days"
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
# Run openssl quietly, but print its stderr and fail loudly when it errors — a silent
# `2>/dev/null` turns an unsupported flag into an empty file and a mystery TLS failure later.
ossl() {
  local err; err="$(mktemp)"
  if ! openssl "$@" 2>"$err"; then
    echo "gen-certs: openssl $1 failed:" >&2; cat "$err" >&2; rm -f "$err"; return 1
  fi
  rm -f "$err"
}

csr() { # name subject
  ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"
  ossl req -new -key "$1.key" -subj "$2" -out "$1.csr"
}

leaf() { # name subject ca extfile [extra openssl x509 args…]
  local name="$1" subject="$2" caname="$3" ext="$4"; shift 4
  csr "$name" "$subject"
  ossl x509 -req -in "$name.csr" -CA "$caname.crt" -CAkey "$caname.key" -CAcreateserial -sha256 \
    -extfile "$ext" -out "$name.crt" "$@"
  rm -f "$name.csr"
}

# An already-expired certificate. `openssl x509` only learned -not_before/-not_after in 3.5, so use
# `openssl ca`, whose -startdate/-enddate have been there for decades and work on every runner.
expired_leaf() { # name subject ca extfile
  local name="$1" subject="$2" caname="$3" ext="$4"
  csr "$name" "$subject"
  mkdir -p ca-db/newcerts; : > ca-db/index.txt; echo 01 > ca-db/serial
  cat > ca-db/ca.cnf <<'CNF'
[ca]
default_ca = CA_default
[CA_default]
dir = ./ca-db
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
default_md = sha256
policy = policy_any
email_in_dn = no
rand_serial = no
unique_subject = no
[policy_any]
commonName = supplied
organizationalUnitName = optional
organizationName = optional
CNF
  ossl ca -batch -config ca-db/ca.cnf -cert "$caname.crt" -keyfile "$caname.key" \
    -extfile "$ext" -in "$name.csr" -out "$name.crt" -notext \
    -startdate "$(date -u -d '30 days ago' +%Y%m%d%H%M%SZ)" \
    -enddate "$(date -u -d '1 day ago' +%Y%m%d%H%M%SZ)"
  rm -rf "$name.csr" ca-db
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
expired_leaf expired-alice "/CN=alice/OU=mcp-user/O=mcp-auth-demo DEMO" ca client.ext
leaf rogue-client "/CN=alice/OU=mcp-admin/O=rogue" rogue-ca client.ext -days "$DAYS"

rm -f server.ext client.ext ./*.srl
chmod 600 ./*.key
echo "demo PKI written to $OUT_DIR (server SAN: IP:${PUBLIC_HOST}, IP:127.0.0.1, DNS:localhost)"
for f in server alice bob expired-alice rogue-client; do
  printf '  %-14s %s\n' "$f" "$(openssl x509 -in "$f.crt" -noout -subject -enddate | tr '\n' ' ')"
done
