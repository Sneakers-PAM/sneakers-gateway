# Configuration

The gateway reads its settings from environment variables at start. An unset or empty variable
takes the default shown. Defaults suit a local run; anything marked "dev default" must be set in
a real deployment.

## HTTP and mode

| Variable | Default | Meaning |
|---|---|---|
| `HTTP_PORT` | `9100` | The port for every HTTP route (GraphQL, auth, setup, health). |
| `AUTH_MODE` | `noauth` | `noauth`: local development; the caller is the user id in the `X-Dev-User` header (or the `x-dev-user` field of a WebSocket `connection_init`), and no login, Redis or session is used. `real`: the BFF login, Redis-backed sessions and CSRF. Any value other than `real` behaves as `noauth`. |
| `COOKIE_SECURE` | on | The `Secure` flag on the session cookies. See [cookies.md](cookies.md). A value that isn't a boolean stops the gateway at start. |
| `CORS_ALLOWED_ORIGINS` | (none) | The browser origins allowed to call the gateway with credentials: a comma-separated list of `scheme://host[:port]`, for example `https://sneakers.example.org`. Set it to the web app's origin. Only an exact match gets CORS headers; any other origin gets none, and its preflight answers 403. An entry that isn't a plain http or https origin, or `*`, stops the gateway at start. Unset with `AUTH_MODE=real` allows no cross-origin caller (serve the UI from the gateway's origin). Unset with `AUTH_MODE=noauth` echoes any origin, for local development only. |
| `SETUP_TOKEN` | (none) | Guards `/setup/bootstrap` and `/setup/seed`. Unset disables both (they answer 503). Surrounding whitespace (such as the newline a Secret made from a file ends in) is trimmed, and a blank value counts as unset. The gateway never logs the value; read it from the Secret or environment that sets it. Clear it once the first admin exists. |

## Backend services

Every address is a gRPC `host:port`, dialled in plaintext. Connections are lazy: the gateway starts
without the services, and a call fails until its service answers. Every call carries the gateway's
workload identity (see [api.md](api.md), "Service-to-service authentication").

| Variable | Default | Service |
|---|---|---|
| `VAULT_ADDR` | `localhost:9091` | vault |
| `IDENTITY_ADDR` | `localhost:9092` | identity |
| `WORKFLOW_ADDR` | `localhost:9093` | workflow |
| `AUDIT_ADDR` | `localhost:9194` | audit |
| `NOTIFY_ADDR` | `localhost:9195` | notify |
| `SSHBROKER_ADDR` | `localhost:9096` | SSH broker |

| Variable | Default | Meaning |
|---|---|---|
| `WORKLOAD_TOKEN_FILE` | (none) | The gateway's projected service-account token (audience `sneakers`), for example `/var/run/secrets/sneakers/token`. It's sent to every backend as `authorization: Bearer <token>` gRPC metadata and read again on every call, so a rotated token is picked up. A set path that can't be read stops the gateway at start. Required with `AUTH_MODE=real`; unset (noauth only) sends no token, which only backends running with `WORKLOAD_AUTH=disabled` accept. |

## Sessions (`AUTH_MODE=real`)

| Variable | Default | Meaning |
|---|---|---|
| `REDIS_URL` | `redis://localhost:26379/0` | Redis for sessions, pending logins and the OAuth store. `rediss://` enables TLS. The gateway won't start in `real` mode if Redis doesn't answer. |
| `MFA_ENFORCED` | `true` | `false` or `0` makes the second factor optional (the client shows a setup banner); anything else enforces it, so a user without a verified factor can reach only the enrollment endpoints. |
| `MFA_MAX_AGE` | `5m` | How recent a second factor must be to add or remove a factor (a Go duration from `1m` to `1h`; anything else stops the gateway at boot). Set it to the same value as the vault and the workflow. |
| `MFA_PENDING_TTL` | `5m` | How long a login waits for its second factor after the password step (a Go duration). |

The session lifetime isn't an environment variable: it's the vault security setting
`session_ttl_seconds`, clamped to 15 to 60 minutes (30 when unset), re-read every 60 seconds.

## Password backend (`AUTH_MODE=real`)

Sign-in uses Ory: Ory Kratos for accounts and the password step, Ory Polis for SAML SSO (below)
and Ory Hydra for machine OAuth (below).

| Variable | Default | Meaning |
|---|---|---|
| `KRATOS_PUBLIC_URL` | `http://sneakers-kratos:4433` | Ory Kratos public API. |
| `KRATOS_ADMIN_URL` | `http://sneakers-kratos:4434` | Ory Kratos admin API, for password reset. |
| `JWT_LEEWAY_SECONDS` | `30` | Clock leeway for Ory Hydra token times. |

## Single sign-on (Ory Polis)

SSO is off unless `POLIS_PUBLIC_URL` is set. Setup's SSO provisioning is off unless
`POLIS_ADMIN_URL` is set.

| Variable | Default | Meaning |
|---|---|---|
| `POLIS_PUBLIC_URL` | (none) | The Polis URL the browser is sent to. Enables `/auth/sso/*`. |
| `POLIS_ISSUER_URL` | `http://sneakers-polis:5225` | The Polis URL the gateway calls for the code exchange and user info. |
| `POLIS_PRODUCT` | `sneakers` | The Polis product. |
| `POLIS_TENANT` | `example.org` | The Polis tenant, usually your email domain: set it. |
| `POLIS_CLIENT_SECRET` | (none) | The client secret for the SSO code exchange: the `CLIENT_SECRET_VERIFIER` Polis runs with. Read it from a Secret; surrounding whitespace is trimmed. With `AUTH_MODE=real` and `POLIS_PUBLIC_URL` set, an unset value or the development value `dummy` stops the gateway at start. |
| `POLIS_ADMIN_URL` | (none) | The Polis admin API, used by setup to create the SAML connection. |
| `POLIS_API_KEY` | (none) | The Polis admin API key. |
| `POLIS_SAML_METADATA_URL` | (none) | The identity provider's SAML metadata URL for that connection. |
| `SSO_REDIRECT_BASE` | (none) | The gateway's public base URL; the callback is `<base>/auth/sso/callback`. |
| `SSO_APP_BASE` | `/` | Where the browser goes after an SSO login (or a rejection, with `?sso_error=<reason>`). |

## Native-client login (OAuth)

| Variable | Default | Meaning |
|---|---|---|
| `OAUTH_PUBLIC_URL` | (none) | The public URL of the UI. When set (and `AUTH_MODE=real`), the gateway serves the OAuth authorization server for native clients under `/oauth2/` and `/.well-known/oauth-authorization-server`. The machine API also uses it to build links. |

## Machine OIDC (Ory Hydra)

The machine API accepts Hydra client-credentials JWTs only when `HYDRA_ENABLED` is true. With it
off, the gateway makes no Hydra calls, and a JWT-shaped bearer is refused.

| Variable | Default | Meaning |
|---|---|---|
| `HYDRA_ENABLED` | off | `true` or `1` (any case, spaces trimmed) turns the OIDC leg on. Anything else is off. |
| `HYDRA_ISSUER` | (none) | The expected `iss`. Required when enabled: the gateway refuses to start without it. Also the issuer admins link service accounts to, even while disabled. |
| `HYDRA_JWKS_URL` | `http://sneakers-hydra:4444/.well-known/jwks.json` | Hydra's signing keys. |
| `HYDRA_AUDIENCE` | `sneakers-mcp` | The expected `aud`. |

## Telemetry and logging

| Variable | Default | Meaning |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317` | The OTLP collector for traces and metrics. |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn` or `error` (go-log). |
| `LOG_FORMAT` | `json` | `json`, or `console` for local reading (go-log). |

See [logging.md](logging.md) for what is logged.
