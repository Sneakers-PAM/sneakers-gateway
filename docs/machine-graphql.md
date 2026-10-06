# Machine GraphQL

`/machine/graphql` serves personal tokens and service accounts (bearer auth). The schema is `graphql/machine.graphqls`. Every call runs as the calling principal; vault does the RACI checks and the audit.

## Organize

| Mutation | Needs | Returns |
|---|---|---|
| `renameSecretForPrincipal(id, name)` | Author on the secret | `SecretSummary` |
| `updateSecretFieldsForPrincipal(id, fields)` | Author on the secret | `UpdatedSecretFields { secret, changedFieldKeys }` |
| `createFolderForPrincipal(parentId, name)` | Author on the parent | `PrincipalFolder` |
| `renameFolderForPrincipal(id, name)` | Author on the folder | `PrincipalFolder` |

- `updateSecretFieldsForPrincipal` changes only the listed keys. An empty value clears an optional field. A repeated key is rejected before vault is called. The result names the changed keys (sorted), never values; a call that changes nothing returns `[]`. On types vault manages (rotation, heartbeat, checkout, certificate) only `notes` and `description` may change.
- There is no machine delete, and a machine cannot create a top-level folder or a folder inside a personal folder.
- `PrincipalFolder.canAuthor` comes from vault. It is true on the results of both folder mutations, since each needs Author.
- `PrincipalFolder` on those results is the folder's entry from `foldersForPrincipal`, so `path` is the full path the principal can see (`Infrastructure/AD`). The gateway reads it with a second vault call, the principal folder listing, which vault audits as `folder.list.principal`. If that listing fails or does not include the folder, `path` falls back to the folder's own name.
- The listing is a separate read after the mutation, so a change made in between (such as another rename) shows in the result.

## Targets

`targetsForPrincipal(query, connectionId)` lists the targets the caller can see, each with `sshHostKeys` (the pinned SSH host keys; `[]` when not pinned). `saveTargetForPrincipal(input)` creates or updates one; `sshHostKeys` in the input is the whole pin list, left out to keep the current pins. Changing the pins needs a human site admin, so a token gets `PermissionDenied` if it sends a different list. See [api.md](api.md#targets-and-ssh-host-keys).

## Secret uses

Personal tokens only. `prepareSecretUse(secretId, fieldKey, argv, clientLabel, reveal, runId, purpose)` asks to use one field for the exact command in `argv` (or, with `reveal: true`, for the value itself); `secretUse(id)` polls it and `redeemSecretUse(id)` collects the value once, after approval. A use is approved at once unless the secret's approval level needs a decision (see [api.md](api.md#pending-secret-uses-approvals-and-runs)): then it waits for an owner or approver, or, when `confirm` is true, for the token's own person to confirm the task once in the web. There is no second factor on this path: after `/login`, a token needs no MFA.

- `runId` (optional, `[A-Za-z0-9_-]{1,64}`) groups the uses one agent run raises so the owner decides them on one page; pass the same one on every request of one task. It groups for display only and grants nothing.
- `purpose` (optional, at most 200 characters of plain text, no control characters) is the agent's own words for its task, shown to the owner.
- Vault checks both. A bad `argv`, `runId` or `purpose` is `INVALID_ARGUMENT` with reason `SECRET_USE_REQUEST_INVALID` (domain `sneakers.gateway`) and vault's message, which names the field.
- `secretUseRun(runId)` lists this token's own pending uses in that run, so an agent can show what is still waiting.
- `SecretUse.runId` is the use's run, null without one. `approvalUrl` is `<OAUTH_PUBLIC_URL>/approvals`, or `<OAUTH_PUBLIC_URL>/approvals/run/<runId>` for a use with a run id while `APPROVAL_RUN_LINKS` is on (see [configuration.md](configuration.md)).

## Change type

`changeSecretTypeForPrincipal(id, newTypeId, fieldMapping, fields)` needs Author on the secret and returns `TypeChangedSecret { secret, fieldKeys, movedToNotesKeys, automation }`. `movedToNotesKeys` lists the old field keys (never values) whose values had no field in the new type and were appended to its notes field. Vault applies the value rules: nothing is dropped, sensitive values only move into sensitive fields, and the prior values stay in version history. Any type may be converted into or out of any other, including rotation/heartbeat types (AD, Windows, database accounts) and the certificate type. Dropping checkout from a plain checkout type is still refused.

`automation` is derived from the new type and the returned secret. The gateway reads the type catalog for it, only when it is selected.

| Field | Values |
|---|---|
| `rotation` | `NONE` (type never rotates), `OFF` (opted out; always the case right after a change into a rotation type), `ON` |
| `heartbeat` | `NONE` (type has none), `OFF` (opted out), `NO_TARGET` (none until a target is attached), `ON` (runs once the target has a connection) |
| `target` | `ATTACHED`, `NONE` (type takes a target, the secret has none), `NOT_SUPPORTED` (type takes no target, so any target was detached) |

Turn rotation on with `setSecretAutomationForPrincipal(secretId, disableRotation: false, ...)`. A type change is refused while a rotation of the secret is in flight. The vault's rules are in [sneakers-vault docs/type-change.md](https://github.com/Sneakers-PAM/sneakers-vault/blob/main/docs/type-change.md).
