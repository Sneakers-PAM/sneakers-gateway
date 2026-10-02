# Runbook

## Before you deploy

- **Never run `AUTH_MODE=noauth` where anyone else can reach it.** In that mode the caller is
  whoever the `X-Dev-User` header names, with no password. Use `AUTH_MODE=real` everywhere but a
  developer's own machine.
- **The backends trust the gateway.** Identity, vault, workflow, audit, notify and the SSH broker
  act on the actor context the gateway sends, and the gateway talks to them over plaintext gRPC.
  Let only the gateway reach their gRPC ports (for example with a network policy), and keep those
  hops on a private network or behind a service mesh with mTLS.
- **Point it at Ory.** Set `KRATOS_PUBLIC_URL` and `KRATOS_ADMIN_URL` for Ory Kratos, and
  `POLIS_TENANT` and the other `POLIS_*` values if you use Ory Polis SSO.
- **`SETUP_TOKEN` is logged at start** so the first admin can be created. Set it for the first
  run only, then remove it: with it unset, `/setup/bootstrap` and `/setup/seed` answer 503.
- **Serve it over HTTPS** behind a reverse proxy that passes the original `Host` (or
  `X-Forwarded-Host`): the subscription socket's `Origin` must match it.
- **Set `CORS_ALLOWED_ORIGINS`** to the web app's origin (for example
  `https://sneakers.example.org`) when the UI is served from another origin. Without it, a real
  deployment allows no cross-origin browser caller.
- **Redis holds live sessions** (the tokens behind each session id). Give the gateway its own
  Redis database, require a password, and use `rediss://` when the hop isn't private.

## Start up

At start the gateway:

1. reads its configuration from the environment ([configuration.md](configuration.md));
2. checks the Hydra settings: `HYDRA_ENABLED` with no `HYDRA_ISSUER` stops it;
3. starts OpenTelemetry export to `OTEL_EXPORTER_OTLP_ENDPOINT`;
4. sets up the gRPC clients for the six backends; they connect lazily, on the first call;
5. checks `COOKIE_SECURE`: a value that isn't a boolean stops it;
6. in `real` mode, reads the session lifetime from the vault (falling back to 30 minutes if the
   vault doesn't answer) and connects to Redis: if Redis doesn't answer, it stops;
7. serves HTTP on `HTTP_PORT`.

A stop is a fatal log line and a non-zero exit. The start-up line `gateway starting (/graphql)`
lists the port, the mode and every backend address. Another line says whether the machine OIDC
leg is active, and in `real` mode one more names the password backend.

## Health

`GET /health` answers `200 {"status":"ok","mode":"real"}` while the process serves HTTP. It
doesn't check Redis or the backends; a backend that's down shows up as GraphQL errors with
`code = Unavailable` in the `graphql error` log lines.

## Sessions

- A session lives in Redis for the configured lifetime (15 to 60 minutes, set in the vault's
  security settings), and every authenticated request slides it forward. A change to the setting
  takes effect within 60 seconds, with no restart.
- Losing Redis signs everyone out and makes logins fail until it's back.
- With `MFA_ENFORCED` on (the default), a user who has no verified second factor gets a
  half-session that can only enroll one. Admins can remove a user's TOTP factor with
  `/auth/mfa/admin/remove-totp` when a device is lost; the user's sessions end.
- A login waits `MFA_PENDING_TTL` (5 minutes) for its second factor, then has to start again.

## Single sign-on

SSO needs Polis reachable from both the browser (`POLIS_PUBLIC_URL`) and the gateway
(`POLIS_ISSUER_URL`). SSO never creates users: the email from the identity provider has to match
an existing, enabled user, or the browser lands on `SSO_APP_BASE` with `?sso_error=no_user`. The
`sso login rejected` warning carries the reason and, for backend failures, an error code from
[error-codes.md](error-codes.md).

## Machine callers

- Personal tokens and service-account API tokens are checked against identity on every request;
  revoking one takes effect at once.
- Hydra client-credentials JWTs are accepted only with `HYDRA_ENABLED`, and are verified locally
  against `HYDRA_JWKS_URL` (keys cached for 10 minutes), `HYDRA_ISSUER` and `HYDRA_AUDIENCE`.
  Admins link a service account to a Hydra client with the `linkOidcClient` mutation first.

## Logs and errors

- One JSON line per HTTP request (`http`), and one per GraphQL error (`graphql error`): client
  mistakes and refusals at `warn`, everything else at `error`. See [logging.md](logging.md).
  Variables, arguments, response data and tokens are never logged.
- Login-backend failures carry a four-digit code in the log line; [error-codes.md](error-codes.md)
  lists them. Wrong passwords and bad codes are plain 401 or 400 answers, not coded errors.

## Common problems

| Symptom | Likely cause |
|---|---|
| Login works, then every request is 401 | The browser drops the `Secure` cookie on plain http: serve HTTPS, or set `COOKIE_SECURE=false` for a test stack. |
| Subscriptions never connect | The socket's `Origin` doesn't match the host the gateway sees: check the proxy passes `Host` or `X-Forwarded-Host`. |
| Every GraphQL call fails with `Unavailable` | A backend address is wrong or the service is down; the start-up line lists the addresses. |
| The gateway exits at start in `real` mode | Redis is unreachable, or `COOKIE_SECURE` isn't a boolean, or `HYDRA_ENABLED` is on without `HYDRA_ISSUER`. |
| `/setup/bootstrap` answers 503 | `SETUP_TOKEN` is unset (expected once setup is done). |
