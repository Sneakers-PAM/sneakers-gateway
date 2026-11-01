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

The gateway checks the break-glass MFA code itself, before the vault is called, so that refusal
comes from domain `sneakers.gateway`:

| Mutation | `code` | `reason` | Meaning |
|---|---|---|---|
| `breakGlassSecret`, `openBreakGlassSession` | `UNAUTHENTICATED` | `BREAK_GLASS_CODE_INVALID` | The TOTP code is wrong, missing or expired. Identity doesn't say which, so neither does the reason. Ask for a fresh code. |
| `breakGlassSecret` and the break-glass browse operations | `PERMISSION_DENIED` | `BREAK_GLASS_WEB_ONLY` | Not a person's own signed-in web session: a personal (MCP or agent) token, a service account, an OAuth client, or no session. Checked before the code, and audited as `break_glass.denied`. |
| The break-glass browse operations | `PERMISSION_DENIED` | `BREAK_GLASS_NOT_ADMIN` | The caller isn't a site admin or root. |
| `scanTargetHostKey`, `pinTargetHostKey` | `PERMISSION_DENIED` | `HOST_KEY_PIN_NOT_ADMIN` | The caller isn't a person who is a site admin or root. |
| `scanTargetHostKey`, `pinTargetHostKey` | `FAILED_PRECONDITION` | `TARGET_NO_SSH_CONNECTION` | The target has no SSH connection to scan. |
| `pinTargetHostKey` | `FAILED_PRECONDITION` | `HOST_KEY_CHANGED` | The target now offers a key with another fingerprint than the one confirmed. Nothing was pinned; scan again and show the new fingerprint. |
| `pinTargetHostKey` | `INVALID_ARGUMENT` | `HOST_KEY_FINGERPRINT_REQUIRED` | No fingerprint was sent. |

Other vault reasons a client may see (domain `sneakers.vault`):

| `code` | `reason` | Meaning |
|---|---|---|
| `PERMISSION_DENIED` | `NO_ACCESS` | The user can't read the secret: a reveal, copy, version reveal or `secretFields`. |
| `FAILED_PRECONDITION` | `RETIRED` | The secret is retired, so it can't be revealed or copied. |
| `PERMISSION_DENIED` | `NOT_SITE_ADMIN` | The call needs a site admin: settings, password policies, secret types, connections, key rotation. On `/machine/graphql`, `importExtension` needs a personal token whose owner is one. |
| `PERMISSION_DENIED` | `TOP_LEVEL_FOLDERS_RESTRICTED` | `restrictTopLevelFolders` is on, and the caller of a top-level `createFolder`, or the owner of the token calling a top-level `createFolderForPrincipal`, isn't a site admin or root. |
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

### Changing a secret's type

`changeSecretType` changes a secret's type as a new version, and `previewSecretTypeChange` says what
the same inputs would do without writing anything. Both take `id`, `newTypeId`, `fieldMapping`
(`[{from, to}]`, old key to new key), `fields` (`[{key, value}]`, values for fields the mapping
leaves empty) and `unmappedFields`. Both need Author on the secret or ownership of its folder, and
the vault refuses anyone but a signed-in person. A repeated `from` or `key` is refused with
`INVALID_ARGUMENT` before the vault is called.

`unmappedFields` says what happens to a value with no field under the new type: `notes`, the
default, moves it to the notes field, and `refuse` fails the change naming the keys. Nothing is
dropped under either.

```graphql
query Preview($id: ID!, $newTypeId: ID!, $fieldMapping: [FieldMappingInput!], $fields: [KeyValueInput!], $unmappedFields: UnmappedFieldPolicy) {
  previewSecretTypeChange(id: $id, newTypeId: $newTypeId, fieldMapping: $fieldMapping, fields: $fields, unmappedFields: $unmappedFields) {
    allowed refusalReason refusalMessage
    fieldChanges { fromKey toKey outcome reason }
    missingRequiredKeys notesFieldKey fieldKeys changeLabel
    rotation heartbeat target fromTargetId targetId
  }
}

mutation Change($id: ID!, $newTypeId: ID!, $fieldMapping: [FieldMappingInput!], $fields: [KeyValueInput!], $unmappedFields: UnmappedFieldPolicy) {
  changeSecretType(id: $id, newTypeId: $newTypeId, fieldMapping: $fieldMapping, fields: $fields, unmappedFields: $unmappedFields) {
    secret { id typeId targetIds rotationOptOut }
    fieldKeys movedToNotesKeys notesFieldKey changeLabel
  }
}
```

The preview returns keys, never values. `outcome` is `carried`, `renamed`, `movedToNotes` or
`blocked`, with `reason` set when it's blocked. A change the rules refuse is a normal answer with
`allowed` false and `refusalReason` and `refusalMessage` set to what `changeSecretType` would refuse
with. No access, a retired secret, a missing secret or type and the type the secret already has are
GraphQL errors, as they are for the change. `rotation` is `none` or `off`, `heartbeat` is `none`,
`scheduled`, `no_target` or `opted_out`, and `target` is `none`, `kept` or `detached`.

Because the preview is a query it keeps working during maintenance; `changeSecretType` is refused
like any other mutation.

`changeSecretType` passes these vault refusals through unchanged (domain `sneakers.vault`).
`metadata.fields` lists the keys involved, joined by commas, unless the table says otherwise:

| `code` | `reason` | Meaning |
|---|---|---|
| `FAILED_PRECONDITION` | `TYPE_CHANGE_UNMAPPED_FIELDS` | A value has no field, under `refuse` or because the new type has no notes field. |
| `FAILED_PRECONDITION` | `TYPE_CHANGE_LOWERS_PROTECTION` | A value would land in a less protected field, the notes field included. |
| `FAILED_PRECONDITION` | `TYPE_CHANGE_NOTES_TOO_LONG` | Moving values to notes would pass its max length. |
| `INVALID_ARGUMENT` | `TYPE_CHANGE_INVALID_FIELD` | A mapping or value doesn't fit the new type. A key pair that doesn't match names no fields. |
| `INVALID_ARGUMENT` | `TYPE_CHANGE_CERTIFICATE_INVALID` | The material doesn't validate as a certificate, or a stored value differs from the one derived from it. |
| `INVALID_ARGUMENT` | `FIELD_VALUE_REQUIRED` | The new type requires a field nothing fills. Metadata `field`. |
| `INVALID_ARGUMENT` | `FIELD_VALUE_NOT_ALLOWED` | A select value isn't one of the options. Metadata `field` and `allowed`. |
| `FAILED_PRECONDITION` | `ROTATION_IN_PROGRESS` | A rotation of the secret is claimed; retry once it finishes. No metadata. |
| `FAILED_PRECONDITION` | `RETIRED` | The secret is retired. No metadata. |

### Secret order

`Secret.position` is the secret's manual place in its folder, 1-based among the folder's active
secrets, and 0 for a retired one. `secretsInFolder` returns secrets in that order, retired ones
last. The vault keeps positions dense: a new, moved-in or restored secret goes last, and retire,
delete and move-out close the gap.

`reorderSecrets(folderId, orderedIds)` sets the whole order through the vault's `ReorderSecrets`
and returns the folder's secrets in the new order, with `canRead`. `orderedIds` must name every
active secret in the folder exactly once, and the caller needs RACI Author on the folder or must
own it; the vault refuses anything else (`INVALID_ARGUMENT` or `PERMISSION_DENIED`) and changes
nothing.

### Heartbeat readiness

`Secret.heartbeatBlockedReason` (human schema) names what's missing before a heartbeat-capable
secret's heartbeat can be switched on: `"no target"`, `"no connection"` or, for an SSH Key secret,
`"no pinned host key"` on the target. It's null once heartbeat is already running, when it's opted
out on purpose (`heartbeatOptOut`), or when the type has no heartbeat at all. The gateway derives
it from `secretTypes` and `targets` (the vault's `GetSecret`/`secretsInFolder` don't compute it;
only the machine schema's `*ForPrincipal` responses do, as `SecretSummary.heartbeatBlockedReason`).
`setSecretAutomation` still refuses an explicit switch-on before then, naming the same reason.

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
- `openSshSession` is bounded at 15 seconds in all: the vault reads and the broker's
  `CreateSession`. When that runs out it fails with `DEADLINE_EXCEEDED` and names the service
  that didn't answer (`the vault didn't answer within 15s while opening the session`, or the same
  for `the SSH broker`). The broker bounds each step of the connect itself and closes the
  WebSocket with the step and the reason when one fails (see the broker's docs/api.md).

Trust on first use (human schema only) lets a site admin pin the key a target offers without
copying it by hand:

- `scanTargetHostKey(targetId)` asks the broker's `ScanHostKey` for the key the target's SSH
  connection offers (its default connection when that is SSH, otherwise its first SSH one). The
  broker reads the key during the handshake and never authenticates. The answer is a
  `TargetHostKeyScan`: `keyType`, `publicKey` (authorized_keys form), `fingerprint`
  (`SHA256:<base64>`, as `ssh-keygen -l` prints it) and `pinned` (whether the target already pins
  it). A scan pins nothing. The broker rate-limits scans per user (`RESOURCE_EXHAUSTED` past the
  limit) and audits each as `hostkey.scan`.
- `pinTargetHostKey(targetId, fingerprint)` pins only the key the person confirmed: the gateway
  scans again and adds the offered key to the target's pins only when its fingerprint is exactly
  `fingerprint`; a different key is refused with `HOST_KEY_CHANGED` and nothing is pinned. A key
  the target already pins is left as it is. The target's other pins and fields are kept. The
  decision is audited as `target.host_key.pin` (outcome `pinned` or `mismatch`, with the
  fingerprints, never the key), and the vault audits the pin list change as
  `target.host_keys.change`.
- Both are for a person who is a site admin or root, the same people the vault lets change a
  target's pins. The gateway refuses anyone else (`HOST_KEY_PIN_NOT_ADMIN`) before it calls the
  broker, so the broker can't be used to probe hosts on someone else's behalf.

### Top-level folders

A folder with no parent is open to anyone by default: a signed-in person through `createFolder`, or
a personal token through `createFolderForPrincipal` on `/machine/graphql`, whose `parentId` is
optional. The folder is a shared top-level folder owned by that user. With no parent, the gateway
sends the vault an empty parent and the vault decides; the gateway has no folder rule of its own.

The "Restrict top-level folders to admins" setting, `SecuritySettings.restrictTopLevelFolders`,
limits both paths to a site admin or root, or a token whose owner is one. Anyone else gets
`PERMISSION_DENIED`, reason `TOP_LEVEL_FOLDERS_RESTRICTED`, domain `sneakers.vault`, as the vault
sent it. A service account is refused with `INVALID_ARGUMENT` either way, since it has no user to
own the folder.

The gateway tells the vault about a token's owner in `ActorContext.token_owner_is_site_admin`. It
sets that from the roles and root flag identity returns when it verifies the token, on every
request, and never from anything the client sends. No other kind of actor can carry it, and it
gives the token no admin authority: `is_site_admin` and `is_root` stay false. The vault reads it
for one other thing, `importExtension` on `/machine/graphql`.

`ActorContext.token_client_kind` carries the kind identity recorded for the token (`mcp` for an MCP
agent token) the same way. It grants nothing; the vault uses it for the `source` of an extension
activation in the audit log.

`restrictTopLevelFolders` is off by default, and is read and written through `securitySettings` and
`updateSecuritySettings` on `/graphql`. Writing it needs a site admin; the vault enforces that and
audits each change.

### Target connections

`Target.connections` (`[TargetConnection!]!`, each a `connectionId` plus `isDefault`) lists a
target's connections in order, one connector protocol apiece, with exactly one default.
`Target.connectionId` stays as an alias for the default entry, for a caller that hasn't moved to
the list. `TargetInput.connectionId` is now optional: set `connections` instead to save more than
one, or leave it as the sole field to keep saving a single connection the old way. The vault
validates the list (every id must resolve to a connection, no two sharing a protocol, exactly one
default) and normalizes a legacy single-`connectionId` save, same as it always has — see
[sneakers-vault docs/api.md](https://github.com/Sneakers-PAM/sneakers-vault/blob/main/docs/api.md).

`openSshSession(secretId, connectionId)` starts on the bound target's default connection unless
`connectionId` names one of that target's own connections; naming any other id, or one that isn't
`ssh`, is refused the same way an unresolvable target or connection already is.

### One secret, many targets

`Secret.targetIds` (`[String!]!`) lists every target a secret is attached to, in attach order;
`Secret.targetId` stays the first/primary entry, kept in sync, for a caller that hasn't moved to
the list. `updateSecret`'s `targetId` keeps its existing meaning: replace the whole list with just
this one.

- `attachSecretTarget(secretId, targetId)` and `detachSecretTarget(secretId, targetId)` add or
  remove ONE target without touching the others, and are idempotent: attaching an
  already-attached target, or detaching one that isn't attached, is a no-op, not an error.
- Host-key pins (`Target.sshHostKeys`) stay per target, unaffected.
- `openSshSession(secretId, connectionId, targetId)`: `targetId` picks which of the secret's
  attached targets to open a session on. It's required when `targetIds` has more than one entry
  (refused otherwise, with no target chosen), defaults to the only one when there's exactly one,
  and is refused if it names a target that isn't attached to the secret at all. The gateway also
  forwards the secret's full attached-target list to sshbroker (`CreateSession.secretTargetIds`),
  which independently checks the chosen target is actually one of them before any auth is sent —
  the gateway's own check is for a clear error; the broker's is the real gate.
- `secretsByTarget(targetId): [Secret!]!` lists every secret attached to a target, for the
  target's own page ("every secret attached to this target"), with the same `canRead` visibility
  as `secretsInFolder`.
- See [sneakers-vault docs/api.md](https://github.com/Sneakers-PAM/sneakers-vault/blob/main/docs/api.md)
  for how heartbeat and rotation run per target.

### Contribute, own reveal

`RaciGrant` gains `own`, valid only on the `C` (read) cell. Combined with `R: allow` it is a grant
for a machine principal: create and update anywhere `R` allows in the folder, but reveal only a
secret whose `creatorPrincipalId` is its own — never a blanket folder read. Saving `own` on any
cell but `C` is refused, same as any other vault validation error. `Secret.creatorPrincipalId` is
the secret's creator (set once, at creation); null on a secret created before this field existed.
The vault's full rules (every read path this closes, the refusal and audit shape) are in
[sneakers-vault docs/api.md](https://github.com/Sneakers-PAM/sneakers-vault/blob/main/docs/api.md).

### Audit subject

`AuditRecord.subjectKind`, `subjectId` and `subjectName` resolve the raw `subject` string (which
stays, unchanged, for compatibility) to a record the web can link to: `subjectKind` is one of
`secret`, `folder`, `target`, `user`, `service_account` or `unknown`, read off the id's prefix;
`subjectId` is the same id with any `#field` suffix (a field-level action's subject, e.g.
`secret-1#password`) stripped; `subjectName` is the resolved display name, or `null` when the
caller can't read the subject, it's deleted, or its kind is `unknown`. Resolution is batched once
per page of `auditRecords` — one call per kind present, not per record — through the same
actor-scoped calls the rest of the schema uses (`GetSecret`, `ListFolders`, `ListTargets`,
`ListServiceAccounts`, `ResolveUserLabels`), so access and visibility follow the caller exactly as
they do everywhere else.

### Your tokens

`myTokens` lists the caller's personal tokens, and `revokeMyToken(id: ID!): UserToken!` revokes one.
`deleteMyToken(id: ID!): Boolean!` then removes a revoked token from the list for good, and answers
`true`. Both mutations take the user id from the session, so neither can reach another user's
token, and both exist only on `/graphql`, behind its session, CSRF and second-factor checks.

| `code` | Message after `desc =` | Meaning |
|---|---|---|
| `FAILED_PRECONDITION` | `token is not revoked` | The token hasn't been revoked, even if it has expired; revoke it first. |
| `NOT_FOUND` | `token not found` | No such token among the caller's own, including one that belongs to someone else. |

### Step-up

The session remembers when it last proved a second factor: at sign-in, at enrollment, or through
`POST /auth/mfa/step-up`. The gateway sends that time to the vault and the workflow as
`mfa_verified_at_unix` on every call; the vault owns the freshness window and decides when a
reveal or check-out needs a step-up. Where a reveal needs one is set globally by
`SecuritySettings.requireMfaForReveal` and per folder by `setFolderRevealStepUp(folderId, mode)`
(`inherit`, `require` or `off`, shown as `Folder.revealStepUp`; inherited down the tree; site
admins only). Machine callers never carry the time.

`SecuritySettings.mfaMaxAgeSeconds` reports the window this gateway enforces, read from its own
`MFA_MAX_AGE` at start: `1800` (30 minutes) when unset, `0` when every sensitive action asks. It's
read-only; set `MFA_MAX_AGE` where the services run (the chart's `global.mfaMaxAge` sets it on the
vault, the workflow and the gateway together).

### Pending secret uses, approvals and runs

The vault decides who needs an approval (see the vault's docs/api.md, "Approval levels"): a secret
is normal, approval-required (owners exempt, a non-owner needs one owner) or always-approve
(everyone needs another owner or a designated approver, RACI A). The levels apply to a person in
the web and to a personal token alike, and the requester never approves their own use. When
nobody else can decide (a single-user install, or an always-approve secret whose only approver
is the requester), the requester confirms the task once instead. Break-glass is unchanged.

The gateway sends the vault the people identity reports as active (not disabled, with a login
subject), listed once and kept for 30 seconds, so the vault can tell whether anyone else could
decide. When identity can't list them the gateway sends nothing, and the vault never treats the
install as single-user.

A personal token asks with the machine `prepareSecretUse`; a person whose `revealSecretField` or
`copySecret` answers `APPROVAL_REQUIRED` asks with `prepareSecretReveal(secretId, fieldKey,
runId)`, and collects the value with `redeemSecretReveal(id)` once it's approved, still under the
step-up window. A use that needs a decision waits, `PENDING`. One task's uses share a run id
(`prepareSecretUse(runId, purpose)`, see [machine-graphql.md](machine-graphql.md#secret-uses)), so
they're decided or confirmed on one page with one factor, and a confirmed run covers its later
uses. Service accounts have no pending uses.

- `pendingSecretUses` lists all the caller's own pending uses; `secretUseRun(runId)` lists the
  ones of one run, with `mfaFreshUntilUnix`, the time the session's second factor stops covering
  an approval (`0` when it doesn't now; the window is `MFA_MAX_AGE`), so the page can hide the
  factor input while it's open. The run lists only the signed-in person's own uses.
- `secretUsesToDecide` lists the other people's pending uses the caller may decide, with
  `requestedBy` set to each requester's display name. It never lists the caller's own.
- `SecretUse` carries `runId` (null without one), `purpose` (the agent's own words, empty without
  them; show them as plain text, never as product copy), `requester` (the token's name from
  identity, or the use's client label when identity can't say), `requestedBy` and `confirm` (true
  when the requester confirms it instead of an approver).
- `decideSecretUse(id, approve, factor)` decides one use. Approving needs the session's factor
  within `MFA_MAX_AGE` or `factor`.
- `decideSecretUses(ids, decision, factor)` decides 1 to 20 distinct ids (a repeated id is decided
  once) and returns one `SecretUseOutcome` per id, in request order: `decided` with the `use`, or
  a `reason`. `APPROVE` needs the session's second factor within `MFA_MAX_AGE` (prove it with
  `POST /auth/mfa/step-up`, which also opens the window for a follow-up batch) or a `factor` here,
  checked once for the batch and opening no window. `DENY` needs neither. Every id still goes
  through the vault's single-use `DecideSecretUse`, one at a time in request order, with its own
  checks and audit event; a refused item never stops the others.
- `confirmSecretUses(ids, factor)` is the requester's one-time confirmation of their own uses
  marked `confirm`, with the same batch shape, factor rule and outcomes, through the vault's
  `ConfirmSecretUse`.
- `setSecretTokenApproval(secretId, required, always)` sets the level: `required` alone is
  approval-required, with `always` it's always-approve. `Secret.alwaysRequireApproval` shows it.

A refused item's `reason`:

| `reason` | Meaning |
|---|---|
| `EXPIRED` | The use expired before it was decided. |
| `ALREADY_DECIDED` | The use was already approved, denied or redeemed. |
| `NOT_FOUND` | No such use. |
| `NOT_PERMITTED` | The use isn't the caller's to decide. |
| `UNAVAILABLE` | The vault couldn't decide it now; try again. |
| `SELF_APPROVAL` | The caller asked for this use; another owner or approver decides it. |
| `OTHER_APPROVER` | Someone else can decide this use, so its requester can't confirm it. |
| `NO_APPROVER` | Nobody can approve this use. |

The whole batch fails, deciding nothing, only for these (domain `sneakers.gateway`), or for a
caller who isn't signed in:

| `code` | `reason` | Meaning |
|---|---|---|
| `INVALID_ARGUMENT` | `BATCH_SIZE_INVALID` | No ids, or more than 20 distinct ones. Checked before the factor. |
| `FAILED_PRECONDITION` | `STEP_UP_REQUIRED` | `APPROVE` without a `factor` and outside the session's window: step up and retry. |
| `UNAUTHENTICATED` | `FACTOR_NOT_ACCEPTED` | The `factor` given was wrong. |

### Break-glass is people only

Break-glass is the emergency backup for an admin who needs a password outside the planned access
paths, when no grant, check-out or approval covers it. It is for people only: the MCP, AI agents
and any API token (personal, service account or OAuth) can't use it, by design. The gateway
refuses every break-glass call, including a plain `breakGlassSecret` with no browse session, that
doesn't come from a person's own signed-in web session (`BREAK_GLASS_WEB_ONLY`), before the TOTP
code is even checked, and audits the refusal as `break_glass.denied` naming the caller kind
(`user_token`, `service_account` or `no_web_session`). `/machine/graphql`, the only endpoint
tokens reach, has no break-glass field at all.

### Break-glass browse

A site admin or root can open a short-lived break-glass session from the web app to find and
reveal any secret, other users' personal ones included. It grants no edit or manage rights.

- `openBreakGlassSession(reason, code)` checks the TOTP `code` exactly as `breakGlassSecret` does,
  then asks the vault to open the session, passing the code's time as the actor's MFA time and an
  opaque reference to the web session (a hash of the session id, never the id). The vault binds the
  session to that person and web session, keeps it for 15 minutes, and ends any session the caller
  still has open (`replaced`). A blank reason or a reason over 500 characters is
  `INVALID_ARGUMENT`; a stale factor is `STEP_UP_REQUIRED` from the vault.
- `breakGlassSession` is the caller's open session for this web session, or null. Anyone who
  can't break glass gets null without a vault call, so the web can check it on every page.
- `breakGlassBrowse(sessionId, folderId)` lists every folder and every live secret, with the same
  `Folder` and `Secret` types as `folders` and `secretsInFolder`; `folderId` narrows the secrets.
  Folders always come back with `canManage` false.
- `breakGlassSecret(secretId, reason, code, sessionId)` reveals inside the session: the vault
  records the session id with the reveal, alerts the owner and queues the rotation as for any
  break-glass reveal. An empty `reason` takes the session's.
- `closeBreakGlassSession(id)` ends the session (`exit`). It stays open in read-only maintenance.
- `breakGlassSessions(limit)` lists sessions newest first for the audit log: `openedAt` is the
  entered event, `endedAt` and `endReason` (`exit`, `expired` or `replaced`) the left one, and
  `reveals` every secret revealed in the session (who saw what). `actorName` comes from identity.
  `limit` defaults to 50, at most 200.

A call naming a session that has ended or expired, or that belongs to someone else or another web
session, is refused by the vault with `FAILED_PRECONDITION` and `BREAK_GLASS_SESSION_CLOSED`. Only
the human schema has these operations; `/machine/graphql` has none of them.

### Recovery

A secret's prior values are a separate recovery surface. `secretVersions` lists the versions and
their field keys to any reader, never a value. `SecretVersion.changeLabel` is set only on a version
a type change produced ("Type changed: Password -> Password Account (SSH); added host; fields
carried over: username, password"), naming any field added, renamed or dropped by the mapping; it's
null on every other version, which renders from `changedFieldKeys` as before ("Changed:
`<field>`, `<field>`"). `revealSecretVersionField` and
`restoreSecretVersion(secretId, versionNo)`, which makes a prior version's fields the current ones
as a new version, need the identity role `recovery` and a fresh second factor. The gateway sends
the role as `is_recovery` on the vault actor, read from identity on every request, and the vault
decides: `RECOVERY_ROLE_REQUIRED` without the role, `STEP_UP_REQUIRED` without a fresh MFA, and a
refusal while the secret is rotating (`ROTATION_IN_PROGRESS`). The vault can't see check-out
leases, so the gateway asks the workflow first and refuses a restore while someone holds a lease
(`CHECKOUT_LEASE_HELD` with `holder_user_id`); if that lookup fails, the restore doesn't run. Only a site admin or root can grant or
revoke the role (identity enforces it). Machine callers never get the recovery surface.

`secretMoves(secretId)` lists a secret's folder moves, newest first, with who moved it, when, and
the source and destination folder ids. It's read from the audit trail (`secret.move` and
`secret.move.principal`; a move waiting on an approval isn't listed), behind the same vault check
as `secretVersions`, which runs first. The folder ids are empty for a move recorded before the
vault kept them.

### Maintenance

`maintenance` answers any signed-in user with `readOnly` and, when the appliance gave one, a
`reason`, so the web apps can show a banner. While `readOnly` is true, both `/graphql` and
`/machine/graphql` refuse every mutation, before any backend is called, with code
`FAILED_PRECONDITION` and reason `MAINTENANCE_READONLY` (domain `sneakers.gateway`). These stay
open: `revealSecretField`, `revealSecretVersionField`, `exportCertificate`, `sendMfaEmailCode`,
`beginMfaPasskey`, `markNotificationRead`, `markAllNotificationsRead` and `closeBreakGlassSession`
on `/graphql`, and
`revealSecretFieldForPrincipal` on `/machine/graphql`. Queries, sign-in and the factor routes
under `/auth` keep working. The backends hold their own read-only mode too, so a write that gets
past the gateway is still refused. The mode comes from `MAINTENANCE_READONLY` or the appliance
ConfigMap (see [configuration.md](configuration.md), "Maintenance and the appliance").

### Appliance

`appliance` answers any signed-in user with the appliance's state from its `sneakers-appliance`
ConfigMap, for the web banners: `present`, `version`, `productState` (`starting`, `ok`,
`degraded`, `down`, `maintenance` or `stopped`), `mcp` (`on`, `off` or `degraded`),
`mcpRevokePending`, `machineApi` (`on` or `off`), `tlsMode` (`self-signed`, `upload`, `csr` or
`acme`), `tlsNotAfter` (RFC 3339), `maintenance` and `maintenanceReason`. On a plain Kubernetes
install `present` is false and every other field is null or false. See
[appliance.md](appliance.md) for the keys.

### Diagnostics

`diagnostics` takes no arguments and answers any signed-in user with the facts a support report
needs: `generatedAt`, this read's `traceId`, the caller (`actor`: id, username and roles, read
from identity), the origin of `OAUTH_PUBLIC_URL` (`publicUrl`), the product release the install
runs (`productVersion`, from `SNEAKERS_PRODUCT_VERSION`, null when unset), the appliance's Base OS
version (`appliance`, from `SNEAKERS_APPLIANCE_VERSION`, null off the appliance), the box itself
(`box`: `baseOS`, `baseWeb` and `fqdn`, from `SNEAKERS_APPLIANCE_VERSION`,
`SNEAKERS_APPLIANCE_WEB_VERSION` and `SNEAKERS_APPLIANCE_FQDN`; null off the appliance, and a value
the box didn't give, still the bundle's `.invalid` placeholder, is `unknown`), and a `ComponentVersion`
(name, version, commit, status and, for a connector, `lastContactAt`) for the gateway, each service
and each third-party service:

- **Services** (`services`): identity, vault, workflow, audit, notify and sshbroker, read from the
  response headers of each one's standard gRPC health check (`sneakers-version`,
  `sneakers-commit`); mcp from `MCP_HEALTH_URL`, its `GET /livez` (the `Sneakers-Version` and
  `Sneakers-Commit` response headers, or `version` and `commit` in the body where an older build
  has them). A service that answers without the headers (an older build) shows version `unknown`.
  One `connector` entry per connector worker vault has heard from, read through vault's
  `ListConnectors` (the gateway never dials a connector: it's a pull-based worker). Its
  `lastContactAt` is the last verified pull-API call; `version`/`commit` are `unknown` for a worker
  that has never sent one. No connectors at all means no `connector` entries, not a single
  `NOT_CONFIGURED` placeholder.
- **Third party** (`thirdParty`): kratos (`/admin/version`), hydra (`/version`), polis
  (`/api/health`), valkey (`INFO server` on the session store), kubernetes (the API server's
  `GET /version`, with the pod's ServiceAccount token; the version keeps the distribution's build
  metadata, such as `v1.36.4+k0s`), and postgres and rabbitmq as the services
  report them in `sneakers-dep-postgres` and `sneakers-dep-rabbitmq` (one entry per distinct
  version, so services that disagree all show; a service reporting `unknown` counts as not
  reporting).

`status` is `OK`, `UNAVAILABLE` (configured, but it didn't answer within its timeout, or a service
answered that it isn't ready) or `NOT_CONFIGURED` (not part of this deployment, such as Kratos in
noauth mode, or RabbitMQ while no service uses a broker). A component that doesn't answer never
fails the query.

`dependencies` is a component's readiness by dependency: for each service, what its health check
reports in its `sneakers-health` header; for the gateway, its own readiness (see "Health" below).
Each entry has `name`, `state` (`OK`, `DEGRADED` or `DOWN`), `required`, `error` (a class:
`timeout`, `refused`, `unavailable`, `unauthenticated` or `error`, or go-buildinfo's
`connection-refused`, `dns`, `network`, `canceled` or `panic`; never the error text) and
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
(loopback redirect URIs, PKCE `S256`), which is how the MCP server and the CLIs (`sneakers-put
login`, `sneakers-run login`) get a personal token:

| Route | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | Server metadata. |
| `POST /oauth2/register` | Dynamic client registration (loopback redirect URIs only). A CLI sends `"software_id": "sneakers-cli"`. |
| `GET /oauth2/authorize` | Start the flow; the user signs in and consents in the UI. |
| `GET /oauth2/consent/{id}`, `POST /oauth2/consent/{id}` | Read and answer the consent request (signed-in user). |
| `POST /oauth2/consent/{id}/email-code`, `POST /oauth2/consent/{id}/passkey/begin` | Step-up second factor for the consent. |
| `POST /oauth2/token` | Exchange the code for a personal token. |

Consent follows the same second-factor rule as approving pending secret uses: `GET
/oauth2/consent/{id}` returns `factorRequired`, which is `false` while the session's second factor
is within `MFA_MAX_AGE`. Then `POST /oauth2/consent/{id}` with `approve: true` and no `factor` is
accepted, so a cold `/login` costs one MFA prompt (the sign-in) and a warm one costs none at
consent. Once the session's factor is older than `MFA_MAX_AGE` (or the session never proved one, as
after SSO), an approval with no `factor` answers 403 `{"error":"step_up_required"}` and the request
stays pending for a retry with a factor. A `factor` that is given is always verified; a wrong one is
401 `{"error":"invalid_code"}`. Denying needs no factor.

A client says it's a Sneakers CLI by registering with the RFC 7591 `software_id` `sneakers-cli`;
the registration answer echoes it. The token minted for that client is recorded by identity with
`client_kind: cli`, like one minted on the tokens page. Every other client is an MCP client, and its
token is recorded with `client_kind: mcp`. Together with Hydra client-credentials JWTs (audience
`sneakers-mcp`), the `mcp` tokens are the MCP agent tokens. A client keeps the kind it registered
with; a client registered before the kinds existed is an MCP client.

**MCP off** (`MCP_ENABLED=false`): the metadata stays up and CLI clients sign in as usual. For an
MCP client, every route above (registration, authorize, the consent routes and the token
exchange), and every MCP agent token on `/machine/graphql`, answers `403` with
`{"error":"MCP_DISABLED","message":"MCP is turned off on this appliance (setting mcp.enabled)"}`,
before identity or Hydra is called for a JWT, so no new agent token can be minted or used. This
includes an MCP client registered, or a consent started, while the MCP was still on. Personal
tokens with `client_kind: cli` and service-account API tokens keep working, and turning the MCP
off revokes only `mcp` tokens. With `OAUTH_PUBLIC_URL` unset there is no authorization server, so
while the MCP is off the routes answer `MCP_DISABLED` to everyone.

**Machine API off** (`MACHINE_API_ENABLED=false`): `/machine/graphql` answers `403` with
`{"error":"MACHINE_API_DISABLED","message":"The machine API is turned off on this install (setting MACHINE_API_ENABLED)"}`
for `cli` personal tokens and service-account API tokens (those are refused before identity is
called). MCP agent tokens are left to the MCP switch.

## First-run setup

| Route | Purpose |
|---|---|
| `GET /setup/state` | `{"needsSetup": true}` until the first admin exists. |
| `POST /setup/bootstrap` | Create the first admin. Needs `setupToken` in the body to equal `SETUP_TOKEN` (both trimmed of surrounding whitespace). |
| `POST /setup/seed` | Install the vault's built-in types and baseline, after bootstrap. Same token, plus the `userId` bootstrap returned: the seed acts as that admin and creates their personal folder. Without it, 400. |

These are outside the session gate, like `/livez` and `/readyz`.

## Health

Two unauthenticated endpoints served by go-buildinfo, plus the smoke and telemetry status routes below (`github.com/Bugs5382/go-buildinfo`):

- `GET /livez`: liveness. Always `200 {"status":"ok"}` while the process answers; it checks no
  dependency, so an outage never restarts the gateway.
- `GET /readyz`: readiness. `200` while every required dependency is up, `503` while one is down.
  The body carries the build and lists each dependency:
  `{"status":"ok|degraded|down","ready":true,"build":{"version":"v0.1.0","commit":"...","goVersion":"...","modified":false},"dependencies":[{"name":"valkey","state":"ok","required":true,"checkedAt":"2026-10-05T12:00:00Z"}]}`,
  with `error` (one of the classes above) on a failing one. Required: Valkey and Kratos in
  `AUTH_MODE=real`, and identity in every mode. Vault, workflow, audit, notify, the SSH broker,
  Hydra (when enabled), Polis (when configured) and `otlp` (when a collector is configured) are
  optional: one failing makes the status `degraded`, still `200`. The gateway checks every dependency in the background, every 5 seconds
  with a 1-second timeout, and `/readyz` only reads the last results: it answers at once however
  slow a dependency is, so a hanging one shows as `timeout` instead of failing the probe that asked.
  Until the first pass finishes, each dependency reads `pending` (a required one makes the gateway
  not ready).
Both carry the build in the `Sneakers-Version` and `Sneakers-Commit` headers, and `/readyz` adds
`Sneakers-Depstate-<name>` (`ok`, `degraded` or `down`) for each dependency. There is no plain
`/health` route.

`GET /smoke` is the appliance's post-upgrade check: unauthenticated, outside the product routes
like `/readyz`, and never cached. It makes a real read through identity (`GetSetupState`) and
vault (`GetSecuritySettings`), each of which reads its database, checks that workflow and audit
are serving, and pings the session store in `AUTH_MODE=real`. It answers `200` when every check
passes and `503` otherwise:
`{"ok":false,"checks":[{"name":"identity","ok":true},{"name":"vault","ok":false,"error":"unavailable"}]}`.
A failure carries its class only, never the error text; each check has 3 seconds. Nothing in it
writes.

`GET /telemetry-status` says which workloads are exporting telemetry, for the box's telemetry card:
unauthenticated and outside the product routes like `/smoke`. It always answers `200`, in a fixed
order:
`{"services":[{"name":"identity","state":"sending","checkedAt":"2026-10-05T12:00:00Z"},{"name":"vault","state":"issue","checkedAt":"2026-10-05T12:00:00Z"}]}`.
The workloads are identity, vault, workflow, audit, notify, connector, sshbroker, gateway and mcp,
and `checkedAt` is the last check, missing until the first one. The states:

| State | Meaning |
|---|---|
| `sending` | The workload's `otlp` dependency reads `ok`. |
| `issue` | Its `otlp` dependency reads `degraded` or `down`: its last export of a signal failed. |
| `off` | No `otlp` dependency in its report, so no collector is set, or the build is too old to have one. mcp is also `off` with `MCP_HEALTH_URL` unset. |
| `unknown` | The gateway couldn't read the workload's report. |

The services are read from their gRPC health check's `sneakers-depstate-otlp` header, mcp from the
`Sneakers-Depstate-otlp` header of `/readyz` on the host in `MCP_HEALTH_URL`, and the gateway from
its own checker. The connector is read at `CONNECTOR_ADDR`; it answers `unknown` while that's unset
or the connector refuses the gateway. `sending` means no failed export is outstanding, which is also
true just after start, before the first export. Like `/readyz`, the gateway checks in the background, every 5
seconds with a 1-second timeout, and the route only reads the last results, so a peer that's down
or hanging never holds it. A check's error text is never in the answer.

The running build is also in the `diagnostics` query; the image build stamps it from its
`VERSION` and `COMMIT` build arguments into go-buildinfo's `Version` and `Commit`
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

The client side is the owner's helper package
[`github.com/Bugs5382/go-workload-identity`](https://github.com/Bugs5382/go-workload-identity)
(v1.0.0), the same release the backends verify with; it replaced the old private copy. A new
version arrives as a `go.mod` bump.

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
