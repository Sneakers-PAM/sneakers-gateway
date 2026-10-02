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

### Targets and SSH host keys

`Target.sshHostKeys` (human schema) and `MachineTarget.sshHostKeys` (machine schema) list the SSH
host keys the broker accepts for the target, one OpenSSH public key per entry in authorized_keys
form (`ssh-ed25519 AAAA... comment`). An empty list means the target isn't pinned.

- `saveTarget(input: TargetInput)` and `saveTargetForPrincipal(input: MachineTargetInput)` take
  `sshHostKeys` as the whole list. Leave it out on an edit to keep the current pins (the gateway
  reads them from the vault and sends them back, since the vault replaces the list on every save);
  send `[]` to clear them. The vault checks every key and lets only a human site admin change the
  pins, so a token can save a target only with the pins it already has. The vault's rules are in
  [sneakers-vault docs/api.md](https://github.com/Sneakers-PAM/sneakers-vault/blob/main/docs/api.md).
- `openSshSession(secretId)` sends the target's pins to the broker with the session. The ticket
  comes back either way; for an unpinned target, or a host that presents another key, the broker
  refuses the connection and closes the WebSocket with code 1008 and the reason
  (`host key not pinned for this target` or `host key mismatch`), which the client can show.

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
| `/auth/sso/login` (`GET`), `/auth/sso/callback` (`GET`) | SAML single sign-on through Ory Polis, when configured. |

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
| `POST /setup/bootstrap` | Create the first admin. Needs `setupToken` in the body to equal `SETUP_TOKEN` (both trimmed of surrounding whitespace). |
| `POST /setup/seed` | Install the vault's built-in types and baseline, after bootstrap. Same token. |

These are outside the session gate, like `/health`.

## Health

`GET /health` answers `{"status":"ok","mode":"<AUTH_MODE>"}`. It doesn't check Redis or the
backends.

## CORS

Only the origins in `CORS_ALLOWED_ORIGINS` (see [configuration.md](configuration.md)) get CORS
headers: the exact `Origin` is echoed with credentials allowed, and their `OPTIONS` preflights are
answered for `Content-Type`, `X-Dev-User`, `X-CSRF-Token` and `Authorization`. Any other origin
gets no CORS headers, so the browser keeps the response from it, and its preflight answers 403.
With `AUTH_MODE=noauth` and no list set, any origin is echoed, for local development.

## Calling other services

The gateway never imports another service's Go module. It generates its own client stubs from each
callee's protos, pinned by commit:

- `proto-refs.env` pins each callee: `SNEAKERS_AUDIT_REF=<commit>` for
  `Sneakers-PAM/sneakers-audit`, `SNEAKERS_IDENTITY_REF=<commit>` for
  `Sneakers-PAM/sneakers-identity`, `SNEAKERS_NOTIFY_REF=<commit>` for
  `Sneakers-PAM/sneakers-notify`, `SNEAKERS_SSHBROKER_REF=<commit>` for
  `Sneakers-PAM/sneakers-sshbroker` and `SNEAKERS_VAULT_REF=<commit>` for
  `Sneakers-PAM/sneakers-vault`.
- `scripts/proto-generate.sh` downloads only the callee's `proto/` at that commit into `.protos/`
  (git-ignored) and runs `buf generate`. The stubs land in `gen/go/thirdparty/audit/v1`,
  `gen/go/thirdparty/identity/v1`, `gen/go/thirdparty/notify/v1`, `gen/go/thirdparty/sshbroker/v1`,
  `gen/go/thirdparty/vault/v1` and `gen/go/thirdparty/workflow/v1`, inside this module, so they
  can't collide with the owner's Go packages. The stubs are committed, so a build needs no network;
  the protos never are.
- To try an unmerged proto change, point `SNEAKERS_AUDIT_PROTO_DIR`, `SNEAKERS_IDENTITY_PROTO_DIR`,
  `SNEAKERS_NOTIFY_PROTO_DIR`, `SNEAKERS_SSHBROKER_PROTO_DIR` and `SNEAKERS_VAULT_PROTO_DIR` at a
  local `proto/` directory and run the script.
- To move to a newer callee, change its ref, run the script and commit `proto-refs.env` and `gen/`
  together. Build & Test fails when `gen/` doesn't match the pins.
- The `proto-sync` check (from `Sneakers-PAM/.github`) fails a PR whose pin isn't on the owner's
  `main` or that the owner's `main` breaks, and warns when `main` has moved on. On a schedule it
  opens a PR that bumps stale pins.
