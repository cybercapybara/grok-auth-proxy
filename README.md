# grok-auth-proxy

OpenAI-compatible HTTP proxy for Grok (xAI). Clients use **your** API keys; the proxy authenticates to xAI with a session token from Grok CLI `auth.json`, refreshes it automatically, and hot-reloads the file on change.

## Features

- `POST /v1/chat/completions` and `GET /v1/models` (streaming SSE supported)
- Local API key management (create / list / revoke) with hashed storage
- Reads `auth.json` (Grok CLI format), OIDC token refresh, file watch
- SQLite or **external PostgreSQL** (recommended; no PVC required)
- Auth token refresh persisted to DB (`auth_states`) so pods stay stateless
- Request/response **audit log** in DB with admin API (`/admin/audit`)
- Rate limiting (global + per-key), CORS, Prometheus metrics
- Graceful shutdown, `/health` and `/ready`
- Docker Compose ready

## Quick start

### Prerequisites

- Go 1.24+
- A Grok CLI `auth.json` (usually `~/.grok/auth.json` after `grok login`)

### Local run

```bash
cp .env.example .env
# set GAP_SERVER_ADMIN_KEY to a strong secret
export GAP_SERVER_ADMIN_KEY='your-admin-secret'
export GAP_AUTH_FILE="$HOME/.grok/auth.json"
export GAP_DB_DSN="./data/proxy.db"

make build
./bin/grok-auth-proxy
```

### Create an API key

```bash
curl -sS -X POST http://localhost:8080/admin/keys \
  -H "Authorization: Bearer your-admin-secret" \
  -H "Content-Type: application/json" \
  -d '{"name":"dev"}' | jq .
# save the returned "key" (shown only once)
```

### Chat completions

```bash
export GAP_API_KEY='sk-gap-...'

curl -sS http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $GAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "grok-4.5",
    "messages": [{"role":"user","content":"Hello"}]
  }' | jq .
```

Streaming:

```bash
curl -N http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $GAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "grok-4.5",
    "stream": true,
    "messages": [{"role":"user","content":"Hello"}]
  }'
```

### Docker Compose

```bash
cp .env.example .env
# edit GAP_SERVER_ADMIN_KEY
cp ~/.grok/auth.json ./auth.json   # mount path (rw — tokens may be written back)

docker compose up --build -d
```

Optional Postgres:

```bash
# in .env:
# GAP_DB_DRIVER=postgres
# GAP_DB_DSN=host=postgres user=proxy password=proxy dbname=proxy port=5432 sslmode=disable
docker compose --profile postgres up --build -d
```

## Configuration

Priority: **flags → env (`GAP_*`) → config file → defaults**.

| Variable | Default | Description |
|----------|---------|-------------|
| `GAP_SERVER_ADDR` | `:8080` | Listen address |
| `GAP_SERVER_ADMIN_KEY` | **required** | Admin API secret |
| `GAP_AUTH_FILE` | `./auth.json` | Path to Grok `auth.json` |
| `GAP_AUTH_UPSTREAM_BASE` | `https://api.x.ai/v1` | Upstream API base |
| `GAP_AUTH_REFRESH_SKEW` | `5m` | Refresh before expiry |
| `GAP_AUTH_ISSUER` | `https://auth.x.ai` | OIDC issuer |
| `GAP_AUTH_CLIENT_ID` | | OIDC client id (if not in auth entry) |
| `GAP_DB_DRIVER` | `sqlite` | `sqlite` or `postgres` (prefer postgres in prod) |
| `GAP_DB_DSN` | `./data/proxy.db` | SQLite path or Postgres DSN |
| `GAP_RATE_LIMIT_RPS` | `10` | Default RPS per API key |
| `GAP_RATE_LIMIT_BURST` | `20` | Burst size |
| `GAP_LOG_LEVEL` | `info` | `debug\|info\|warn\|error` |
| `GAP_LOG_REDACT` | `true` | Redact secrets in logs |
| `GAP_AUDIT_ENABLED` | `true` | Store request/response bodies in DB |
| `GAP_AUDIT_MAX_BODY_BYTES` | `65536` | Max body size stored per side |
| `GAP_METRICS_ENABLED` | `true` | Prometheus metrics |
| `GAP_CONFIG` | | Optional config file path |

Example file: [`configs/config.example.yaml`](configs/config.example.yaml).

## HTTP API

**Full reference with request/response examples:** [docs/API.md](docs/API.md).

### Public / OpenAI-compatible

Client auth: `Authorization: Bearer sk-gap-…` (create via admin).

| Method | Path | Auth |
|--------|------|------|
| `POST` | `/v1/chat/completions` | API key |
| `GET` | `/v1/models` | API key |
| `POST` | `/v1/completions` | API key |
| `POST` | `/v1/embeddings` | API key |
| `POST` | `/v1/responses` | API key |
| `GET` | `/health` | none |
| `GET` | `/ready` | none |
| `GET` | `/metrics` | none |

Bodies for `/v1/*` are OpenAI-compatible and proxied to xAI. For IDE clients (Roo Code, etc.) set base URL to `https://<host>/v1` and a model id from `GET /v1/models`.

### Admin

Auth: `Authorization: Bearer <admin_key>` or `X-Admin-Key: <admin_key>`.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/admin/keys` | Create key (`{"name","rate_limit_rps"}`); plaintext `key` only once |
| `GET` | `/admin/keys` | List keys (no secrets) |
| `DELETE` | `/admin/keys/:id` | Revoke key |
| `POST` | `/admin/reload-auth` | Reload `auth.json` from disk |
| `GET` | `/admin/audit` | List audit logs (query filters) |
| `GET` | `/admin/audit/:id` | Get one audit entry (includes bodies) |

## Security notes

- API keys are stored as **bcrypt** hashes (plus a SHA-256 lookup key); plaintext is returned **only once** on create.
- The real Grok access/refresh tokens are never returned to clients and are redacted from logs when `GAP_LOG_REDACT=true`.
- Refreshed Grok credentials are also stored in the DB (`auth_states`), so a **read-only** auth Secret + external Postgres works **without PVC**.
- Audit rows may contain full prompts/completions — protect `/admin` and the database.
- Prefer **Postgres** for multi-replica / no-PVC deploys. SQLite still works for local single-node.

## Development

```bash
make test
make build
```

## Project layout

```
cmd/proxy/           # entrypoint
internal/
  auth/              # auth.json load, refresh, watch
  config/            # viper config
  handlers/          # health, admin
  middleware/        # auth, rate limit, CORS, logging
  metrics/           # Prometheus
  proxy/             # upstream reverse proxy + SSE
  server/            # gin wiring
  store/             # API keys (GORM)
configs/             # example config
docs/                # API reference
testdata/            # sample auth.json
```

## License

See [LICENSE](LICENSE).
