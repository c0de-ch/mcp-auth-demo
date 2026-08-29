# Keycloak for the examples

`npm run kc:up` starts Keycloak 26 (`quay.io/keycloak/keycloak:26.7.2`) in dev mode on
`http://${PUBLIC_HOST}:${KEYCLOAK_PORT:-8180}` and imports the **`mcp`** realm.

`scripts/kc.sh` renders `realm-mcp.template.json` → `.generated/realm-mcp.json` (git-ignored),
substituting `{{PUBLIC_HOST}}`, `{{OAUTH_CALLBACK_PORT}}` and the demo client secrets, because
Keycloak validates redirect URIs before it would resolve its own `${env.…}` placeholders.

| What | Value |
|---|---|
| Issuer | `http://${PUBLIC_HOST}:8180/realms/mcp` — pinned via `KC_HOSTNAME`, identical from every machine |
| Admin console | `http://${PUBLIC_HOST}:8180/admin` — `admin` / `admin` (demo) |
| Users | `alice` / `password` (role `mcp-user`), `bob` / `password` (roles `mcp-user`, `mcp-admin`) |
| Client `mcp-cli` | public, PKCE S256, authorization-code (+ password grant for headless tests), redirect URIs on `OAUTH_CALLBACK_PORT` for localhost, 127.0.0.1 and `PUBLIC_HOST` |
| Client `mcp-service` | confidential, service account (`client_credentials`), role `mcp-user` — example 05 |
| Client `mcp-server` | confidential, introspection + standard token exchange — examples 07 / 10 |
| Client `downstream-api` | audience-only placeholder for the downstream API — example 10 |
| Client scopes | `mcp:tools` (default; adds `aud=mcp-server`), `mcp:admin` (optional; `aud=mcp-server`), `downstream-api` (optional; `aud=downstream-api`) |
| Dynamic Client Registration | anonymous registration allowed; registered clients get consent-required, default scopes, and may request `mcp:tools` / `mcp:admin` / `offline_access` (**not** `openid` — not a Keycloak client scope) |
| Token lifetime | access tokens 15 min |

Everything above is **demo configuration**: HTTP without TLS, well-known passwords, brute-force
protection off. See `docs/keycloak.md` for the reasoning behind each setting and how to point the
examples at an existing Keycloak or another OpenID Connect provider.
