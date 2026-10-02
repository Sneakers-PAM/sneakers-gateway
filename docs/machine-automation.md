# Machine GraphQL: rotation and heartbeat opt-outs

On `/machine/graphql` (schema `graphql/machine.graphqls`) a principal with RACI-Author on a secret can opt it out of scheduled rotation and heartbeat checks, for example a break-glass account password that must never change.

- `setSecretAutomationForPrincipal(secretId, disableRotation, disableHeartbeat): SecretSummary!` sets both flags on every call: `true` opts out, `false` opts back in. Vault audits each flag that changes; a call that changes nothing is a no-op.
- `createSecretForPrincipal` and `generateSecretForPrincipal` take optional `disableRotation` and `disableHeartbeat` (default `false`) to opt a new secret out at creation.
- `SecretSummary.rotationOptOut` and `SecretSummary.heartbeatOptOut` show the current state on every mutation and query that returns a summary.

Needs a vault that serves `SetSecretAutomationForPrincipal`.
