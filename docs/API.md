# HTTP API reference

OpenAI-compatible HTTP API exposed by **grok-auth-proxy**. Clients authenticate with **proxy API keys** (`sk-gap-…`). The proxy injects a Grok/xAI session token from `auth.json` when calling upstream and never returns that token to clients.

| Item | Value |
|------|--------|
| Default listen address | `http://localhost:8080` |
| Production example | `https://grok-proxy.example.com` (your ingress host) |
| OpenAI-compatible base URL (for SDKs / Roo Code / Cline) | `{origin}/v1` |
| Upstream (default) | `https://api.x.ai/v1` |

Request and response **bodies** for `/v1/*` match the [xAI OpenAI-compatible API](https://docs.x.ai). The proxy is a transparent reverse proxy for those paths (plus local auth, rate limits, and token refresh).

---

## Table of contents

1. [Authentication](#authentication)
2. [Common headers](#common-headers)
3. [Error model](#error-model)
4. [Health and ops](#health-and-ops)
5. [OpenAI-compatible API (`/v1`)](#openai-compatible-api-v1)
6. [Admin API (`/admin`)](#admin-api-admin)
7. [Client integration](#client-integration)
8. [Quick reference](#quick-reference)

---

## Authentication

There are two independent credential types.

### Client API key (for `/v1/*`)

| Property | Detail |
|----------|--------|
| Format | `sk-gap-` + hex secret |
| Header | `Authorization: Bearer sk-gap-…` |
| Created via | `POST /admin/keys` |
| Storage | bcrypt hash + SHA-256 lookup; plaintext is **never** stored |
| Plaintext visibility | **Only once**, in the create response field `key` |

Revoked or disabled keys are rejected with `401`.

### Admin key (for `/admin/*`)

| Property | Detail |
|----------|--------|
| Source | `GAP_SERVER_ADMIN_KEY` (or Helm secret) |
| Header | `Authorization: Bearer <admin_key>` **or** `X-Admin-Key: <admin_key>` |

The admin key is **not** a valid client API key. Using it on `/v1/*` returns `401 invalid API key`.

### Unauthenticated routes

`GET /health`, `GET /ready`, `GET /metrics` (when metrics are enabled) do not require a key.

---

## Common headers

### Request

| Header | Used by | Description |
|--------|---------|-------------|
| `Authorization` | `/v1/*`, `/admin/*` | `Bearer <token>` |
| `X-Admin-Key` | `/admin/*` | Alternative to admin Bearer |
| `Content-Type` | POST bodies | `application/json` |
| `X-Request-ID` | optional | Propagated if set; otherwise generated |

### Response

| Header | Description |
|--------|-------------|
| `X-Request-ID` | Request id (also in access logs) |
| `Access-Control-*` | CORS (default allow origin `*`) |

Upstream response headers are mostly forwarded (hop-by-hop and `Set-Cookie` stripped). xAI rate-limit and trace headers may appear on successful proxied calls.

---

## Error model

Proxy-generated errors (auth, rate limit, upstream unavailability) typically look like:

```json
{
  "error": {
    "message": "missing API key",
    "type": "invalid_request_error"
  }
}
```

Admin errors often use a flatter shape:

```json
{ "error": "unauthorized" }
```

Upstream (xAI) errors are forwarded as-is (status code and body), for example:

```json
{ "code": "invalid-argument", "error": "Model not found: gpt-4o" }
```

### Status codes

| Code | Typical cause |
|------|----------------|
| `200` / `201` | Success |
| `204` | CORS preflight `OPTIONS` |
| `400` | Bad client JSON (admin) or upstream validation (e.g. unknown model) |
| `401` | Missing/invalid API key or admin key |
| `404` | Unknown path (e.g. `/v1/v1/chat/completions`) or unknown key id |
| `429` | Per-key rate limit exceeded |
| `500` | Internal (DB, reload failure, …) |
| `502` | Upstream request failed / unauthorized after refresh |
| `503` | Not ready (`/ready`) or upstream auth unavailable |

---

## Health and ops

### `GET /health`

Liveness probe. Process is up.

**Auth:** none

```bash
curl -sS http://localhost:8080/health
```

```json
{ "status": "ok" }
```

### `GET /ready`

Readiness: non-empty access token loaded and database reachable.

**Auth:** none

```bash
curl -sS http://localhost:8080/ready
```

**Ready**

```json
{
  "status": "ready",
  "expires_at": "2026-07-19T07:46:29.996909668Z"
}
```

**Not ready** — `503`

```json
{ "status": "not_ready", "reason": "auth" }
```

```json
{ "status": "not_ready", "reason": "db" }
```

`expires_at` is the current in-memory Grok access token expiry. Token refresh is **lazy** (on demand when a `/v1` request needs a valid token), not on a background timer.

### `GET /metrics`

Prometheus metrics (if `GAP_METRICS_ENABLED=true`). Default path `/metrics`.

**Auth:** none

```bash
curl -sS http://localhost:8080/metrics | head
```

---

## OpenAI-compatible API (`/v1`)

All routes under `/v1` require a client API key and are subject to rate limiting.

**Registered routes** (no catch-all):

| Method | Path | Upstream |
|--------|------|----------|
| `POST` | `/v1/chat/completions` | yes |
| `GET` | `/v1/models` | yes |
| `POST` | `/v1/completions` | yes |
| `POST` | `/v1/embeddings` | yes |
| `POST` | `/v1/responses` | yes |

Other paths under `/v1` return Gin’s plain `404 page not found`.

### Behaviour notes

1. Client `Authorization` is **stripped** and replaced with the Grok access token.
2. On upstream `401`, the proxy force-refreshes the session token and **retries once**.
3. Streaming responses (SSE) are flushed; do not enable buffering on reverse proxies for long chat streams.
4. Request path and query are forwarded. Default upstream base ends with `/v1`, matching client paths like `/v1/chat/completions`.

### `GET /v1/models`

List models from xAI.

```bash
export GAP_API_KEY='sk-gap-…'

curl -sS http://localhost:8080/v1/models \
  -H "Authorization: Bearer $GAP_API_KEY" | jq .
```

**401 without key**

```json
{
  "error": {
    "message": "missing API key",
    "type": "invalid_request_error"
  }
}
```

**Success (shape from upstream, abbreviated)**

```json
{
  "object": "list",
  "data": [
    {
      "id": "grok-4.5",
      "object": "model",
      "owned_by": "xai",
      "created": 1782691200
    }
  ]
}
```

Use model **ids** from this list (or xAI docs). OpenAI names such as `gpt-4o` are rejected by upstream.

### `POST /v1/chat/completions`

Chat completions (OpenAI-compatible). Supports `"stream": true` (SSE).

#### Non-streaming

```bash
curl -sS http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $GAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "grok-4.5",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "Say hello in one sentence."}
    ],
    "max_tokens": 128,
    "temperature": 0.7
  }' | jq .
```

**Example success (fields may vary with model)**

```json
{
  "id": "…",
  "object": "chat.completion",
  "created": 1784432998,
  "model": "grok-4.5",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Hello! How can I help you today?"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 20,
    "completion_tokens": 10,
    "total_tokens": 30
  }
}
```

#### Streaming (SSE)

```bash
curl -N http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $GAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "grok-4.5",
    "stream": true,
    "messages": [{"role": "user", "content": "Count to three."}]
  }'
```

Typical stream lines:

```text
data: {"id":"…","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"One"},"finish_reason":null}]}

data: [DONE]
```

#### Invalid model (upstream)

```bash
curl -sS http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $GAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
```

```json
{ "code": "invalid-argument", "error": "Model not found: gpt-4o" }
```

Status: `400` (from upstream).

### `POST /v1/completions`

Legacy text completions. Proxied to upstream if supported.

```bash
curl -sS http://localhost:8080/v1/completions \
  -H "Authorization: Bearer $GAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "grok-4.5",
    "prompt": "Once upon a time",
    "max_tokens": 32
  }'
```

### `POST /v1/embeddings`

Embeddings, if supported by the selected model / upstream.

```bash
curl -sS http://localhost:8080/v1/embeddings \
  -H "Authorization: Bearer $GAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "YOUR_EMBEDDING_MODEL",
    "input": "hello world"
  }'
```

### `POST /v1/responses`

OpenAI-style Responses API path, proxied when upstream supports it.

```bash
curl -sS http://localhost:8080/v1/responses \
  -H "Authorization: Bearer $GAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "grok-4.5",
    "input": "Hello"
  }'
```

Prefer `/v1/chat/completions` for broadest client compatibility (Roo Code, many SDKs).

### Rate limiting

Per API key token bucket. Defaults: `GAP_RATE_LIMIT_RPS` / `GAP_RATE_LIMIT_BURST` (e.g. 10 / 20). Optional per-key override via `rate_limit_rps` on create.

```json
{
  "error": {
    "message": "rate limit exceeded",
    "type": "rate_limit_error"
  }
}
```

Status: `429`.

### Double `/v1` mistake

Many clients append `/chat/completions` to the **base URL**. If the base already ends with `/v1` and the client also adds `/v1`, the path becomes `/v1/v1/chat/completions` → **404**.

| Client base URL | Resulting path | OK? |
|-----------------|----------------|-----|
| `https://host/v1` | `/v1/chat/completions` | yes |
| `https://host` (if client adds `/v1/...`) | depends on client | often yes |
| `https://host/v1/v1` or double join | `/v1/v1/...` | no |

---

## Admin API (`/admin`)

All admin routes require the admin key.

```bash
export ADMIN_KEY='your-admin-secret'
# either:
#   -H "Authorization: Bearer $ADMIN_KEY"
# or:
#   -H "X-Admin-Key: $ADMIN_KEY"
```

### `POST /admin/keys`

Create a new client API key.

**Request body** (JSON, all fields optional; empty body allowed):

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human label (e.g. `roocode`, `ci`) |
| `rate_limit_rps` | number | Optional per-key RPS override |

```bash
curl -sS -X POST http://localhost:8080/admin/keys \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"roocode","rate_limit_rps":20}' | jq .
```

**201 Created**

```json
{
  "id": "a1b2c3d4e5f6789012345678abcdef01",
  "name": "roocode",
  "key_prefix": "sk-gap-0123456789ab…",
  "key": "sk-gap-0123456789ab…full-secret-only-here…",
  "rate_limit_rps": 20,
  "created_at": "2026-07-19T03:49:54Z",
  "enabled": true
}
```

| Field | Notes |
|-------|--------|
| `key` | **Full secret. Store immediately.** Never returned again. |
| `key_prefix` | Safe to log / list later |
| `id` | Use for revoke |

Malformed JSON with a non-empty body → `400` `{"error":"invalid JSON body"}`.

### `GET /admin/keys`

List keys (no secrets).

```bash
curl -sS http://localhost:8080/admin/keys \
  -H "Authorization: Bearer $ADMIN_KEY" | jq .
```

**200 OK**

```json
{
  "keys": [
    {
      "id": "a1b2c3d4e5f6789012345678abcdef01",
      "name": "roocode",
      "key_prefix": "sk-gap-0123456789ab…",
      "rate_limit_rps": 20,
      "enabled": true,
      "created_at": "2026-07-19T03:49:54Z",
      "last_used_at": "2026-07-19T04:00:00Z",
      "revoked_at": null
    }
  ]
}
```

### `DELETE /admin/keys/:id`

Soft-revoke: sets `enabled=false` and `revoked_at`.

```bash
curl -sS -X DELETE "http://localhost:8080/admin/keys/a1b2c3d4e5f6789012345678abcdef01" \
  -H "Authorization: Bearer $ADMIN_KEY" | jq .
```

**200**

```json
{ "status": "revoked", "id": "a1b2c3d4e5f6789012345678abcdef01" }
```

**404** if id unknown or already revoked with no matching row:

```json
{ "error": "key not found" }
```

### `POST /admin/reload-auth`

Re-read `auth.json` from disk into memory. Does **not** perform OIDC token refresh by itself (refresh happens on demand via `GetAccessToken` / force-refresh after upstream 401).

On startup the process prefers an `auth_states` row in the database (if present) over the bootstrap file, so restarts without PVC keep the last refreshed token.

```bash
curl -sS -X POST http://localhost:8080/admin/reload-auth \
  -H "Authorization: Bearer $ADMIN_KEY" | jq .
```

**200**

```json
{
  "status": "reloaded",
  "expires_at": "2026-07-19T07:46:29.996909668Z"
}
```

**500** if the file is missing, unreadable, or invalid JSON:

```json
{
  "error": "reload failed",
  "detail": "parse auth file: unexpected end of JSON input"
}
```

### `GET /admin/audit`

List proxied request/response audit entries (newest first). Requires admin auth.

**Query parameters**

| Param | Description |
|-------|-------------|
| `limit` | Page size (default 50, max 500) |
| `offset` | Offset |
| `api_key_id` | Filter by client API key id |
| `path` | Exact path, e.g. `/v1/chat/completions` |
| `model` | Exact model id from request body |
| `status_min` / `status_max` | HTTP status range |
| `from` / `to` | RFC3339 timestamps |

```bash
curl -sS "http://localhost:8080/admin/audit?limit=20&path=/v1/chat/completions" \
  -H "Authorization: Bearer $ADMIN_KEY" | jq .
```

**200**

```json
{
  "total": 1,
  "limit": 20,
  "offset": 0,
  "items": [
    {
      "id": "…",
      "created_at": "2026-07-19T04:00:00Z",
      "request_id": "…",
      "api_key_id": "…",
      "api_key_name": "roocode",
      "method": "POST",
      "path": "/v1/chat/completions",
      "status_code": 200,
      "latency_ms": 842,
      "model": "grok-4.5",
      "stream": false,
      "request_body": "{\"model\":\"grok-4.5\",…}",
      "response_body": "{\"id\":\"…\",…}",
      "request_truncated": false,
      "response_truncated": false
    }
  ]
}
```

Bodies are truncated at `GAP_AUDIT_MAX_BODY_BYTES` (default 64 KiB) per side. Streaming responses store the first N bytes only.

Disable with `GAP_AUDIT_ENABLED=false`.

### `GET /admin/audit/:id`

Fetch a single audit row (full stored bodies).

```bash
curl -sS "http://localhost:8080/admin/audit/$ID" \
  -H "Authorization: Bearer $ADMIN_KEY" | jq .
```

**404** if unknown id.

### Admin unauthorized

```bash
curl -sS http://localhost:8080/admin/keys
```

```json
{ "error": "unauthorized" }
```

Status: `401`.

---

## Client integration

### OpenAI Python SDK

```python
from openai import OpenAI

client = OpenAI(
    api_key="sk-gap-…",
    base_url="https://grok-proxy.example.com/v1",
)

r = client.chat.completions.create(
    model="grok-4.5",
    messages=[{"role": "user", "content": "Hello"}],
)
print(r.choices[0].message.content)
```

### curl checklist (production)

```bash
BASE=https://grok-proxy.example.com
export GAP_API_KEY='sk-gap-…'

# Health (no key)
curl -sS "$BASE/ready" | jq .

# Models
curl -sS "$BASE/v1/models" -H "Authorization: Bearer $GAP_API_KEY" | jq '.data[].id'

# Chat
curl -sS "$BASE/v1/chat/completions" \
  -H "Authorization: Bearer $GAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"grok-4.5","messages":[{"role":"user","content":"ping"}],"max_tokens":16}' | jq .
```

### Roo Code / Cline / OpenAI Compatible extensions

| Setting | Value |
|---------|--------|
| Provider | OpenAI Compatible |
| Base URL | `https://<host>/v1` |
| API Key | `sk-gap-…` from `POST /admin/keys` |
| Model ID | e.g. `grok-4.5`, `grok-4.3`, `grok-code-fast-1` |

Do **not** use the admin key, Grok CLI JWT, or OpenAI model names.

### CORS

Default allowed origins: `*` (configurable via `cors.allowed_origins`).  
`OPTIONS` returns `204` with allow headers including `Authorization` and `Content-Type`.

---

## Quick reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | — | Liveness |
| `GET` | `/ready` | — | Readiness + token `expires_at` |
| `GET` | `/metrics` | — | Prometheus |
| `GET` | `/v1/models` | API key | List models (upstream) |
| `POST` | `/v1/chat/completions` | API key | Chat (stream optional) |
| `POST` | `/v1/completions` | API key | Legacy completions |
| `POST` | `/v1/embeddings` | API key | Embeddings |
| `POST` | `/v1/responses` | API key | Responses API |
| `POST` | `/admin/keys` | Admin | Create key (plaintext once) |
| `GET` | `/admin/keys` | Admin | List keys |
| `DELETE` | `/admin/keys/:id` | Admin | Revoke key |
| `POST` | `/admin/reload-auth` | Admin | Reload `auth.json` from disk |
| `GET` | `/admin/audit` | Admin | List request/response audit logs |
| `GET` | `/admin/audit/:id` | Admin | Get one audit entry |

---

## Security notes

- Prefer HTTPS in production; terminate TLS at ingress/load balancer.
- Rotate client keys with create + revoke; treat `key` from create as a password.
- Protect `GAP_SERVER_ADMIN_KEY` and the bootstrap `auth.json` / data PVC.
- Grok access and refresh tokens must not be given to end clients; only `sk-gap-…` keys.
- With SQLite + local `auth.json` write-back, run a **single replica**.

For configuration, deployment, and architecture, see the root [README](../README.md).
