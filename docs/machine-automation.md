# Machine GraphQL: rotation and heartbeat opt-outs

On `/machine/graphql` (schema `graphql/machine.graphqls`) a principal with RACI-Author on a secret can opt it out of scheduled rotation and heartbeat checks, for example a break-glass account password that must never change.

- `setSecretAutomationForPrincipal(secretId, disableRotation, disableHeartbeat): SecretSummary!` sets both flags on every call: `true` opts out, `false` opts back in. Vault audits each flag that changes; a call that changes nothing is a no-op.
- `createSecretForPrincipal` and `generateSecretForPrincipal` take optional `disableRotation` and `disableHeartbeat` (default `false`) to opt a new secret out at creation.
- `SecretSummary.rotationOptOut` and `SecretSummary.heartbeatOptOut` show the current state on every mutation and query that returns a summary.

Needs a vault that serves `SetSecretAutomationForPrincipal`.

## Change signals

So an agent knows when a value it holds may have gone stale:

- `SecretSummary.valueVersion` goes up each time the secret's stored values change (create, edit, type change, restore, committed rotation) and never goes down. `valueChangedAt` is the RFC3339 time of that change, null when none is recorded. Renames, moves and target or automation changes don't count. A secret whose values haven't changed since the vault started counting reads 0.
- `rotationEnabled` means the vault will rotate the secret (a rotation type, not opted out, a target with a connection). `rotatesOnCheckin` means checking it in after a check-out rotates the value, so a value read during the check-out stops working. `heartbeatEnabled` means heartbeat checks run. The vault works these out on every read.
- `lastRotationResult`, `rotatedAt`, `nextRotationAt` and `lastHeartbeatResult` are the stored rotation and heartbeat history, null when unset.
- `findSecretsForPrincipal(changedSince: "<RFC3339>")` keeps only secrets whose value changed at or after that time. The vault refuses a time that isn't RFC3339.
- `secretForPrincipal(id)` returns one secret's summary (RACI read; the vault audits it as `secret.get.principal`).

None of these carry a value. They need a vault that serves `GetSecretForPrincipal` (the pin in `proto-refs.env`).
