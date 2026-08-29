#!/usr/bin/env bash
# Keycloak lifecycle helper: scripts/kc.sh up|down|reset|logs|status|wait|keys
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# Load .env WITHOUT overriding variables the caller exported (shell environment wins,
# same precedence as dotenv on the TypeScript side).
_caller_env="$(export -p)"
[ -f .env ] && set -a && . ./.env && set +a
eval "$_caller_env"
if [ -z "${PUBLIC_HOST:-}" ]; then
  PUBLIC_HOST="$(node -e 'const o=require("os").networkInterfaces();for(const k of Object.keys(o))for(const a of o[k])if(a.family==="IPv4"&&!a.internal){console.log(a.address);process.exit(0)}console.log("127.0.0.1")')"
  echo "PUBLIC_HOST not set — using detected LAN address ${PUBLIC_HOST}" >&2
fi
export PUBLIC_HOST
export KEYCLOAK_PORT="${KEYCLOAK_PORT:-8180}"
COMPOSE=(docker compose -p mcp-auth-demo -f keycloak/docker-compose.yml)
BASE="http://${PUBLIC_HOST}:${KEYCLOAK_PORT}"
GEN=keycloak/.generated
JWT_KEY="$GEN/mcp-service-jwt.key"
JWT_PUB="$GEN/mcp-service-jwt.pub"
gen_keys() {
  # RSA key pair for the private_key_jwt client (example 05 variant). The PUBLIC key goes into the
  # realm (base64 DER, one line); the private key stays on disk, git-ignored, DEMO only.
  mkdir -p "$GEN"
  if [ -f "$JWT_KEY" ] && [ "${1:-}" != "--force" ]; then
    echo "keys exist: $JWT_KEY (use 'keys --force' to regenerate, then 'reset' to re-import)"; return 0
  fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$JWT_KEY" 2>/dev/null
  chmod 600 "$JWT_KEY"
  openssl pkey -in "$JWT_KEY" -pubout -out "$JWT_PUB" 2>/dev/null
  echo "generated $JWT_KEY and $JWT_PUB"
}
render_realm() {
  # Render keycloak/realm-mcp.template.json -> keycloak/.generated/realm-mcp.json
  # ({{VAR}} placeholders; Keycloak validates redirect URIs before it would
  # substitute ${env.VAR}, so we render ourselves — works with any Keycloak).
  [ -f "$JWT_KEY" ] || gen_keys
  local pubkey
  pubkey="$(grep -v -- '-----' "$JWT_PUB" | tr -d '\n')"
  sed -e "s|{{PUBLIC_HOST}}|${PUBLIC_HOST}|g" \
      -e "s|{{OAUTH_CALLBACK_PORT}}|${OAUTH_CALLBACK_PORT:-4199}|g" \
      -e "s|{{MCP_SERVICE_CLIENT_SECRET}}|${MCP_SERVICE_CLIENT_SECRET:-mcp-service-secret-demo}|g" \
      -e "s|{{MCP_SERVER_CLIENT_SECRET}}|${MCP_SERVER_CLIENT_SECRET:-mcp-server-secret-demo}|g" \
      -e "s|{{MCP_SERVICE_JWT_PUBLIC_KEY}}|${pubkey}|g" \
      keycloak/realm-mcp.template.json > "$GEN/realm-mcp.json"
  if grep -q '{{' "$GEN/realm-mcp.json"; then echo "unrendered placeholder in realm file" >&2; exit 1; fi
}
wait_ready() {
  echo -n "waiting for Keycloak at ${BASE}/realms/${KEYCLOAK_REALM:-mcp} "
  for _ in $(seq 1 90); do
    if curl -sf "${BASE}/realms/${KEYCLOAK_REALM:-mcp}/.well-known/openid-configuration" >/dev/null 2>&1; then echo " ready"; return 0; fi
    echo -n "."; sleep 2
  done
  echo " TIMEOUT"; "${COMPOSE[@]}" logs --tail=50 keycloak; return 1
}
case "${1:-}" in
  up)     render_realm; "${COMPOSE[@]}" up -d; wait_ready
          echo "Keycloak: ${BASE}  admin console: ${BASE}/admin (${KC_ADMIN_USER:-admin}/${KC_ADMIN_PASSWORD:-admin})" ;;
  down)   "${COMPOSE[@]}" down ;;
  reset)  render_realm; "${COMPOSE[@]}" down -v; "${COMPOSE[@]}" up -d --force-recreate; wait_ready ;;
  logs)   "${COMPOSE[@]}" logs -f keycloak ;;
  status) "${COMPOSE[@]}" ps; curl -s "${BASE}/realms/${KEYCLOAK_REALM:-mcp}/.well-known/openid-configuration" | jq -r '"issuer: " + .issuer' ;;
  wait)   wait_ready ;;
  keys)   gen_keys "${2:-}" ;;
  render) render_realm; echo "rendered $GEN/realm-mcp.json" ;;
  *) echo "usage: $0 up|down|reset|logs|status|wait|keys [--force]|render" >&2; exit 2 ;;
esac
