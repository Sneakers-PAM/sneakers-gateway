# AGENTS.md - sneakers-gateway

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

Sneakers gateway: the GraphQL and machine API for the web, mobile and MCP clients. A leaf HTTP
service: two gqlgen GraphQL endpoints (`/graphql` for people, `/machine/graphql` for tokens and
service accounts), a backend-for-frontend login layer with Redis sessions, and gRPC clients for
identity, vault, workflow, audit, notify and the SSH broker. Before changing it, know the rules it
keeps: every backend call carries the caller's actor context and the backend decides access (the
gateway never grants anything itself); `/graphql` fails closed without a valid session, CSRF token
and, when enforced, a verified second factor; tokens and secret values are never logged; and the
human and machine schemas share no generated code or resolver.

## Layout

- `cmd/gateway/` - the entrypoint: environment, the backend clients, the routes and the auth
  modes.
- `graphql/` - the two schemas, `schema.graphqls` (human) and `machine.graphqls` (machine).
- `internal/resolvers/` - the human schema's resolvers; `generated.go` and `models_gen.go` are
  gqlgen output.
- `internal/machineresolvers/` - the machine schema's resolvers, generated separately.
- `internal/bff/` - login, sessions (memory and Redis stores), CSRF, MFA, SSO (Polis), the OAuth
  server for native clients, and the machine bearer-token gate.
- `internal/setup/` - the first-run `/setup/*` handlers.
- `internal/gqllog/` - one log line per GraphQL error.
- `internal/apperr/` - the gateway's error-code table (the 2xxx range); the coded-error helpers
  come from `github.com/Bugs5382/go-apperr`.
- `internal/safeconv/` - bounds-checked integer conversions.
- `internal/maintenance/` - read-only maintenance: the mode and the gqlgen guard that refuses
  mutations with `MAINTENANCE_READONLY`; its allow-lists name the mutations that stay open.
- `internal/appliance/` - reads the appliance's `sneakers-appliance` ConfigMap from the
  Kubernetes API on a timer.
- `internal/workloadauth/` - service-to-service workload authentication, copied byte for byte
  from sneakers-vault (`scripts/workloadauth-check.sh` compares it); never edit it here.
- `docs/` - configuration, API, runbook and the topic pages.

## Build, test, lint

- Build: `task build`
- Test: `task test`; the backends, Redis and the login backends are faked in process, so nothing
  else is needed.
- Lint: `task lint`.
- Generated code: `go tool gqlgen generate --config gqlgen.yml` and
  `go tool gqlgen generate --config gqlgen-machine.yml` after a schema change, and
  `scripts/proto-generate.sh` (buf, with the plugin versions pinned in
  `.github/workflows/job-go-lang-ci.yaml`) after a pin change; CI checks both are current.
- License headers: `task license` (golic, the Apache-2.0 SPDX header in `.golic.yaml`).

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- Environments: local dev `trace` with `LOG_FORMAT=console` (never JSON), dev cluster `debug`,
  qa/staging `info`, production `error`. Every cluster environment logs JSON. Set levels through
  `LOG_LEVEL` and `LOG_FORMAT`, never in code; local settings live in the run target or
  `.env.example`.
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- Every commit carries a DCO sign-off (`git commit -s`); the `checks / scrub` job fails without it.
- No real identifiers anywhere: fixtures use example.org, 192.0.2.0/24, 2001:db8::/32 and invented
  names.
- The service client stubs in `gen/go/thirdparty/` (identity, vault, workflow, audit, notify and
  sshbroker) are generated from the commits pinned in `proto-refs.env` (see docs/api.md, "Calling
  other services"); never import another service's Go module.
- Request-scoped logging goes through a go-log `Logger` passed in (`Log` fields, `Ctx(ctx)` for
  trace ids); never the deprecated package-level `log.Ctx`.
- Never edit `generated.go` or `models_gen.go` by hand; gqlgen keeps resolver bodies in
  `*.resolvers.go` across regeneration.
- `go.mod` holds tagged releases only: no `replace` directive, and no pseudo-version (`@main`,
  `@<sha>`) of a `github.com/Bugs5382/*` or `github.com/Sneakers-PAM/*` module; the
  `proto-sync / check` job fails on either. To compile and test against a local package checkout,
  use a git-ignored `go.work` beside `go.mod` (`go work init . ../go-<pkg>`, which writes
  `use . ../go-<pkg>`); `go.work` and `go.work.sum` are in `.gitignore`. For local callee protos,
  point `SNEAKERS_AUDIT_PROTO_DIR`, `SNEAKERS_IDENTITY_PROTO_DIR`, `SNEAKERS_NOTIFY_PROTO_DIR`,
  `SNEAKERS_SSHBROKER_PROTO_DIR` and `SNEAKERS_VAULT_PROTO_DIR` at a local `proto/` directory when
  running `scripts/proto-generate.sh`, rather than editing a pin in `proto-refs.env`.
