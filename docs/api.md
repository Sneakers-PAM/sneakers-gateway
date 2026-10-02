# API

Everything is served over HTTP on `HTTP_PORT` (9100 by default). The two GraphQL schemas in
`graphql/` are the reference for every field; this page covers the routes, how each one
authenticates, and where to read more.

## GraphQL

| Route | Schema | Callers | Authentication |
|---|---|---|---|
| `POST /graphql` | `graphql/schema.graphqls` | the web and mobile apps | `AUTH_MODE=real`: the `sneakers_sid` session cookie plus the `X-CSRF-Token` header. `noauth`: the `X-Dev-User` header. |
| `GET /graphql` (WebSocket upgrade) | the same | the apps, for the `secretStats` subscription | `real`: the session cookie, checked at `connection_init`, and the `Origin` must match the host. `noauth`: `x-dev-user` in the `connection_init` payload. |
| `POST /machine/graphql` | `graphql/machine.graphqls` | the MCP server, scripts, service accounts | `Authorization: Bearer <token>`: a personal token, a service-account API token, or (with `HYDRA_ENABLED`) a Hydra client-credentials JWT. No cookie, CSRF or second factor. |

- In `real` mode a session without a verified second factor (when MFA is enforced) gets 403 on
  `/graphql` and can reach only the enrollment endpoints.
- Introspection is on for `/graphql`.
- Every call runs as the caller: the gateway passes an actor context (user id, roles, groups, and
  for machine callers the principal kind and token id) to the backend service, and the service
  makes the authorization decision and writes the audit record.
- Errors carry the backend's gRPC status text, for example
  `rpc error: code = PermissionDenied desc = ...`. There is no `extensions.code` yet, so match on
  the gRPC code in that text, never on the description after `desc =`.

The human schema has about 45 queries (users and groups, folders, secrets and their rulesets,
access requests and approvals, audit, notifications, tokens), about 70 mutations, and one
subscription. The machine schema is a smaller, principal-scoped surface:
[machine-graphql.md](machine-graphql.md) and [machine-automation.md](machine-automation.md)
describe it.

## Login and sessions (`AUTH_MODE=real`)

All are JSON over `POST` unless noted. Endpoints that act for a signed-in user need the session
cookie and the CSRF header.

| Route | Purpose |
|---|---|
| `/auth/login` | Password step. Returns a session, or a pending id and the factors to choose from. |
| `/auth/verify-otp` | Second-factor step at login (TOTP or email code). |
| `/auth/mfa/otp/send`, `/auth/mfa/email/send` | Email a one-time code. |
| `/auth/mfa/webauthn/begin` | Passkey assertion at login. |
| `/auth/mfa/enroll`, `/auth/mfa/confirm` | Enroll TOTP for the signed-in user. |
| `/auth/mfa/webauthn/register/begin`, `/auth/mfa/webauthn/register/finish` | Enroll a passkey. |
| `/auth/mfa/email/verify` | Prove the email factor. |
| `/auth/mfa/remove` | Remove your own TOTP factor. |
| `/auth/mfa/admin/remove-totp`, `/auth/mfa/admin/status` | Admin: remove another user's TOTP, read their MFA status. |
| `/auth/session` (`GET`) | The current session: whether signed in, the CSRF token, MFA posture. |
| `/auth/logout` | End the session. |
| `/auth/reset/request`, `/auth/reset/confirm` | Self-service password reset (unauthenticated). |
| `/auth/verify/request`, `/auth/verify/confirm` | Email verification (unauthenticated). |
| `/auth/sso/login` (`GET`), `/auth/sso/callback` (`GET`) | SAML single sign-on through Polis, when configured. |

The cookies are described in [cookies.md](cookies.md).

## OAuth for native clients

With `OAUTH_PUBLIC_URL` set, the gateway is an OAuth 2.0 authorization server for native clients
(loopback redirect URIs, PKCE `S256`), which is how the MCP server gets a personal token:

| Route | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | Server metadata. |
| `POST /oauth2/register` | Dynamic client registration (loopback redirect URIs only). |
| `GET /oauth2/authorize` | Start the flow; the user signs in and consents in the UI. |
| `GET /oauth2/consent/{id}`, `POST /oauth2/consent/{id}` | Read and answer the consent request (signed-in user). |
| `POST /oauth2/consent/{id}/email-code`, `POST /oauth2/consent/{id}/passkey/begin` | Step-up second factor for the consent. |
| `POST /oauth2/token` | Exchange the code for a personal token. |

## First-run setup

| Route | Purpose |
|---|---|
| `GET /setup/state` | `{"needsSetup": true}` until the first admin exists. |
| `POST /setup/bootstrap` | Create the first admin. Needs `setupToken` in the body to equal `SETUP_TOKEN`. |
| `POST /setup/seed` | Install the vault's built-in types and baseline, after bootstrap. Same token. |

These are outside the session gate, like `/health`.

## Health

`GET /health` answers `{"status":"ok","mode":"<AUTH_MODE>"}`. It doesn't check Redis or the
backends.

## CORS

Every route echoes the request `Origin` with credentials allowed, and answers `OPTIONS` preflights
for `Content-Type`, `X-Dev-User`, `X-CSRF-Token` and `Authorization`. Put the gateway behind a
reverse proxy that serves only your UI's origin.
