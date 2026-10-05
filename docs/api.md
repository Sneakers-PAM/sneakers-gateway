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
  makes the authorization decision and writes the audit record. For a signed-in person the vault
  and workflow actors also carry `mfa_verified_at_unix`, when the session last proved a second
  factor (see "Step-up" below); the workflow actor carries the admin flags and groups too, for the
  vault's access check on check-out. Both carry the user's directory group ids next to the names,
  which group rules match on; so do a personal token's and a service account's actor on the
  machine API. `simulateFolder` and `simulateSecret` resolve the same for the previewed user
  (`sim_group_names` and `sim_group_ids`), so the preview matches a GROUP rule the same way the
  real access check does.
- Identity's admin calls (users, groups, roles, factors, service accounts and tokens) name the
  signed-in user as `acting_user_id`, so the audit event identity records has an actor. A password
  Kratos rejects at `/auth/login` never reaches identity, so the gateway records it itself:
  `auth.signin` with `step: password`, `outcome: rejected` and the typed `identifier` (cut to 254
  characters), never the password. That write is best effort and never changes the 401.
- Errors from a backend carry its gRPC status text as the message, for example
  `rpc error: code = PermissionDenied desc = ...`, and stable `extensions` on both endpoints:
  - `code`: the canonical gRPC code name, such as `PERMISSION_DENIED` or `FAILED_PRECONDITION`;
  - `reason`: present when the service gave a stable reason for the refusal, such as
    `CHECKOUT_LEASE_HELD` (see "Refusal reasons" below);
  - `metadata`: present when the reason carries details, such as `holder_user_id`;
  - `domain`: the reason's domain, such as `sneakers.workflow`, beside `reason`;
  - `traceId`: the request's trace id, on every error (backend or not) while tracing is on, so a
    report can be matched to the logs.

  Match on `code` and `reason`, never on the message text after `desc =`.

### Refusal reasons

The backends attach a `google.rpc.ErrorInfo` (domain `sneakers.vault` or `sneakers.workflow`) to
the refusals a client should explain; the gateway passes its reason and metadata through
unchanged, and drops details from any other domain. The check-out and check-in reasons are:

| Mutation | `code` | `reason` | `metadata` | Meaning |
|---|---|---|---|---|
| `checkoutSecret` | `PERMISSION_DENIED` | `CHECKOUT_NO_ACCESS` | | The caller can't read the secret. |
| `checkoutSecret` | `FAILED_PRECONDITION` | `CHECKOUT_TYPE_DISABLED` | | The secret's type doesn't allow check-out. |
| `checkoutSecret` | `FAILED_PRECONDITION` | `CHECKOUT_LEASE_HELD` | `holder_user_id` | Someone already holds a lease on the secret. |
| `checkinSecret` | `PERMISSION_DENIED` | `CHECKIN_NOT_HOLDER` | | Only the lease holder can check in. |
| `restoreSecretVersion` | `FAILED_PRECONDITION` | `CHECKOUT_LEASE_HELD` | `holder_user_id` | Someone holds a lease on the secret. The gateway checks this, since the vault can't see leases. |
| `rotateSecret` | `FAILED_PRECONDITION` | `CHECKOUT_LEASE_HELD` | `holder_user_id` | Someone holds a lease on the secret; a manual rotation would replace their credential. |
| `restoreSecretVersion` | `FAILED_PRECONDITION` | `ROTATION_IN_PROGRESS` | | The vault is rotating the secret. |

`revealSecretVersionField` and `restoreSecretVersion` without the recovery role answer
`PERMISSION_DENIED` with reason `RECOVERY_ROLE_REQUIRED`. A reveal or check-out that needs a
fresher second factor answers `FAILED_PRECONDITION` with
reason `STEP_UP_REQUIRED` (domain `sneakers.vault`): the client runs a step-up and retries. A new
group rule in `setFolderRuleset` or `setSecretRuleset` without `subjectId` is refused with
`GROUP_ID_REQUIRED`.

Other vault reasons a client may see (domain `sneakers.vault`):

| `code` | `reason` | Meaning |
|---|---|---|
| `PERMISSION_DENIED` | `NO_ACCESS` | The user can't read the secret: a reveal, copy, version reveal or `secretFields`. |
| `FAILED_PRECONDITION` | `RETIRED` | The secret is retired, so it can't be revealed or copied. |
| `PERMISSION_DENIED` | `NOT_SITE_ADMIN` | The call needs a site admin: settings, password policies, secret types, connections, key rotation. |
| `PERMISSION_DENIED` | `NOT_FOLDER_OWNER` | The call needs the folder's owner or a site admin: folder rules, renaming or reordering. |
| `PERMISSION_DENIED` | `API_SENSITIVE_DISABLED` | A token may not reveal super-sensitive fields while `allowApiForSensitive` is off. |
| `FAILED_PRECONDITION` | `ROTATION_NOT_SUPPORTED` | The secret's type can't rotate. |
| `FAILED_PRECONDITION` | `ROTATION_OPTED_OUT` | The secret is opted out of rotation. |

A secret the user can't see at all (an explicit deny, or someone else's personal folder) is left
out of `secretsInFolder`, and `secret` returns null for it, with no reason given.

`Secret.canRead` is set by `secretsInFolder` and `secret`, the two queries that show a user secrets
they may not be able to read, so the client can show those locked and offer an access request. It's
null on every other query.

The workflow service owns the check-out and check-in reasons; a refusal without one still has its
`code`. For `restoreSecretVersion` and `rotateSecret` the gateway looks up the lease itself, and if
that lookup fails the change doesn't run: the client gets the workflow's code (`UNAVAILABLE` when it
can't be reached).

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
- `openSshSession` sends the broker the caller's actor context with its principal kind (the same
  values as the vault's). The broker refuses every kind but a person, and passes the actor
  through to the vault when it reveals the key.

### Step-up

The session remembers when it last proved a second factor: at sign-in, at enrollment, or through
`POST /auth/mfa/step-up`. The gateway sends that time to the vault and the workflow as
`mfa_verified_at_unix` on every call; the vault owns the freshness window and decides when a
reveal or check-out needs a step-up. Where a reveal needs one is set globally by
`SecuritySettings.requireMfaForReveal` and per folder by `setFolderRevealStepUp(folderId, mode)`
(`inherit`, `require` or `off`, shown as `Folder.revealStepUp`; inherited down the tree; site
admins only). Machine callers never carry the time.

### Recovery

A secret's prior values are a separate recovery surface. `secretVersions` lists the versions and
their field keys to any reader, never a value. `revealSecretVersionField` and
`restoreSecretVersion(secretId, versionNo)`, which makes a prior version's fields the current ones
as a new version, need the identity role `recovery` and a fresh second factor. The gateway sends
the role as `is_recovery` on the vault actor, read from identity on every request, and the vault
decides: `RECOVERY_ROLE_REQUIRED` without the role, `STEP_UP_REQUIRED` without a fresh MFA, and a
refusal while the secret is rotating (`ROTATION_IN_PROGRESS`). The vault can't see check-out
leases, so the gateway asks the workflow first and refuses a restore while someone holds a lease
(`CHECKOUT_LEASE_HELD` with `holder_user_id`); if that lookup fails, the restore doesn't run. Only a site admin or root can grant or
revoke the role (identity enforces it). Machine callers never get the recovery surface.

### Diagnostics

`diagnostics` takes no arguments and answers any signed-in user with the facts a support report
needs: `generatedAt`, this read's `traceId`, the caller (`actor`: id, username and roles, read
from identity), the origin of `OAUTH_PUBLIC_URL` (`publicUrl`), the appliance version
(`appliance`, from `SNEAKERS_APPLIANCE_VERSION`, null off the appliance), and a `ComponentVersion`
(name, version, commit and status) for the gateway, each service and each third-party service:

- **Services** (`services`): identity, vault, workflow, audit, notify, sshbroker and connector,
  read from the response headers of each one's standard gRPC health check (`sneakers-version`,
  `sneakers-commit`); mcp from its `GET /health`. A service that answers without the headers (an
  older build) shows version `unknown`.
- **Third party** (`thirdParty`): kratos (`/admin/version`), hydra (`/version`), polis
  (`/api/health`), valkey (`INFO server` on the session store), kubernetes (the API server's
  `GET /version`, with the pod's ServiceAccount token), and postgres and rabbitmq as the services
  report them in `sneakers-dep-postgres` and `sneakers-dep-rabbitmq` (one entry per distinct
  version, so services that disagree all show).

`status` is `OK`, `UNAVAILABLE` (configured, but it didn't answer within its timeout, or a service
answered that it isn't ready) or `NOT_CONFIGURED` (not part of this deployment, such as Kratos in
noauth mode, or RabbitMQ while no service uses a broker). A component that doesn't answer never
fails the query.

`dependencies` is a component's readiness by dependency: for each service, what its health check
reports in its `sneakers-health` header; for the gateway, its own readiness (see "Health" below).
Each entry has `name`, `state` (`OK`, `DEGRADED` or `DOWN`), `required`, `error` (a class:
`timeout`, `refused`, `unavailable`, `unauthenticated` or `error`, never the error text) and
`version` when known. It's null for a component that reports none (an older build, or a
third-party service). Entries with a name or state outside those tokens are dropped.

The component part is cached for 30 seconds. Only names, versions, commits and statuses leave the
gateway: never an address, URL, credential, error text or response body, and a version that isn't
a plain version string (letters, digits, `.`, `_`, `+` and `-`, at most 64 characters) is shown as
`unknown`.

## Login and sessions (`AUTH_MODE=real`)

All are JSON over `POST` unless noted. Endpoints that act for a signed-in user need the session
cookie and the CSRF header.

| Route | Purpose |
|---|---|
| `/auth/login` | Password step. Returns a session, or a pending id and the factors to choose from. |
| `/auth/verify-otp` | Second-factor step at login (TOTP or email code). |
| `/auth/mfa/otp/send`, `/auth/mfa/email/send` | Email a one-time code. |
| `/auth/mfa/webauthn/begin` | Passkey assertion at login. |
| `/auth/mfa/factors` (`GET`) | The signed-in user's own factors (see [Managing your factors](#managing-your-factors)). |
| `/auth/mfa/enroll`, `/auth/mfa/confirm` | Enroll TOTP for the signed-in user. `enroll` needs a fresh second factor once the user has one. |
| `/auth/mfa/webauthn/register/begin`, `/auth/mfa/webauthn/register/finish` | Enroll a passkey. `register/begin` needs a fresh second factor once the user has one. |
| `/auth/mfa/email/verify` | Prove the email factor. |
| `/auth/mfa/step-up` | Step-up: prove a factor again (`{kind: totp\|email, code}` or `{kind: passkey, credentialJson, webauthnSessionId}`) so the vault sees a fresh second factor. Answers `{mfaVerifiedAt}` (Unix seconds); a wrong proof is 401 `invalid_code`, and after 5 wrong proofs the session is revoked (401 `session_revoked`). |
| `/auth/mfa/step-up/email/send`, `/auth/mfa/step-up/passkey/begin` | Email a step-up code; start a passkey assertion (returns `options` and `webauthnSessionId`). |
| `/auth/mfa/remove` | Remove your own TOTP factor, then sign out (`{ok: true, signedOut: true}`). Needs a fresh second factor; refuses to remove the last one when MFA is enforced. |
| `/auth/mfa/admin/remove-totp`, `/auth/mfa/admin/status` | Admin: remove another user's TOTP, read their MFA status. |
| `/auth/session` (`GET`) | The current session: whether signed in, the CSRF token, MFA posture, and `mfaVerifiedAt` (Unix seconds) once a factor has been proved. |
| `/auth/logout` | End the session. |
| `/auth/reset/request`, `/auth/reset/confirm` | Self-service password reset (unauthenticated). |
| `/auth/verify/request`, `/auth/verify/confirm` | Email verification (unauthenticated). |
| `/auth/sso/login` (`GET`), `/auth/sso/callback` (`GET`) | SAML single sign-on through Ory Polis, when configured. |

The cookies are described in [cookies.md](cookies.md).

### Managing your factors

`GET /auth/mfa/factors` needs the session cookie and the CSRF header, and lists only the caller's
own factors:

```json
{"factors": [
  {"kind": "totp", "id": "totp", "label": "Authenticator app", "createdAt": "2026-01-02T03:04:05Z", "lastUsedAt": null},
  {"kind": "passkey", "id": "<credential id>", "label": "Laptop", "createdAt": "2026-02-01T00:00:00Z", "lastUsedAt": "2026-03-01T00:00:00Z"},
  {"kind": "email", "id": "email", "label": "Email", "createdAt": null, "lastUsedAt": null}
]}
```

- `kind` is `totp`, `passkey` or `email`. TOTP and email come from identity's `ListUserFactors`;
  each passkey is its own entry from `ListWebauthnCredentials`, with the passkey's credential id
  and label (`Passkey` when it has none).
- Times are RFC 3339 or `null`. Identity doesn't record when TOTP was last used, so its
  `lastUsedAt` is always `null`. The email factor is implicit (every user with an address has it),
  so its `createdAt` and `lastUsedAt` are `null`.
- No entry carries a secret, public key, transport list or other credential material.
- A user with no factor gets `{"factors": []}`. Identity unreachable is 502 `identity_unreachable`.

Changing factors needs a recent second factor, using `MFA_MAX_AGE` (the same setting and parsing as
the vault and the workflow; see [configuration.md](configuration.md)):

| Route | Refusal |
|---|---|
| `POST /auth/mfa/remove` | 403 `{"error":"step_up_required"}` when the session's last MFA is older than `MFA_MAX_AGE`, or the session never proved one. |
| `POST /auth/mfa/enroll`, `POST /auth/mfa/webauthn/register/begin` | 403 `{"error":"step_up_required"}` as above, but only when the user already has a TOTP or passkey factor (identity's `GetMfaStatus`). A user with none has nothing to step up with, so the first enrolment stays open. |
| `POST /auth/mfa/remove` | 409 `{"error":"last_factor"}` when `MFA_ENFORCED` is on and removing TOTP would leave no TOTP or passkey factor. The implicit email factor doesn't count, matching how a login decides whether a second factor is owed. |

The client answers `step_up_required` with `POST /auth/mfa/step-up` and retries. Refusals change
nothing and keep the session. Factor enrolment (`mfa.enroll`, on TOTP confirm and passkey
registration) and removal (`mfa.remove`) are already written to the audit service by identity,
which owns the factors, with the actor and subject user ids, the factor kind and, for a passkey,
its credential id; the gateway doesn't write a second copy.

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
| `POST /setup/seed` | Install the vault's built-in types and baseline, after bootstrap. Same token, plus the `userId` bootstrap returned: the seed acts as that admin and creates their personal folder. Without it, 400. |

These are outside the session gate, like `/health`.

## Health

Three unauthenticated endpoints:

- `GET /livez`: liveness. Always `200 {"status":"ok"}` while the process answers; it checks no
  dependency, so an outage never restarts the gateway.
- `GET /readyz`: readiness. `200` while every required dependency is up, `503` while one is down.
  The body lists each dependency:
  `{"status":"ok|degraded|down","dependencies":[{"name":"valkey","state":"ok","required":true,"checkedAt":"2026-10-05T12:00:00Z"}]}`,
  with `error` (one of the classes above) on a failing one. Required: Valkey and Kratos in
  `AUTH_MODE=real`, and identity in every mode. Vault, workflow, audit, notify, the SSH broker,
  Hydra (when enabled) and Polis (when configured) are optional: one failing makes the status
  `degraded`, still `200`. Each dependency is checked with a 1-second timeout and the results are
  cached for 5 seconds, so probes don't load the dependencies.
- `GET /health`: `{"status":"ok","mode":"<AUTH_MODE>"}`, unchanged; it checks nothing.

The running build is in the `diagnostics` query; the image build stamps it from its
`VERSION` and `COMMIT` build arguments
(`docker build --build-arg VERSION=v0.1.0 --build-arg COMMIT="$(git rev-parse HEAD)" .`).

## CORS

Only the origins in `CORS_ALLOWED_ORIGINS` (see [configuration.md](configuration.md)) get CORS
headers: the exact `Origin` is echoed with credentials allowed, and their `OPTIONS` preflights are
answered for `Content-Type`, `X-Dev-User`, `X-CSRF-Token` and `Authorization`. Any other origin
gets no CORS headers, so the browser keeps the response from it, and its preflight answers 403.
With `AUTH_MODE=noauth` and no list set, any origin is echoed, for local development.

## Service-to-service authentication

Every gRPC call to vault, workflow, identity, audit, notify and the SSH broker carries the
gateway's Kubernetes workload identity: the projected service-account token named by
`WORKLOAD_TOKEN_FILE`, sent as `authorization: Bearer <token>` and read again on every call. Each
backend verifies it and maps the service account `<namespace>/sneakers-gateway` to the caller
`gateway`. The backends' allow-lists (sneakers-vault's `docs/api.md`) list the gateway as
**on behalf** for every vault method except the connector pull-API and for every workflow method:
it's the caller that passes the signed-in user's actor context.

The client side is `internal/workloadauth`, a byte-for-byte copy of the canonical package in
sneakers-vault at `SNEAKERS_VAULT_REF`. CI runs `scripts/workloadauth-check.sh` to compare them;
to take a new version, bump the ref and copy the vault's `internal/workloadauth/` in the same
change.

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
