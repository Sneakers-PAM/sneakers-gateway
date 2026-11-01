# Logging

The gateway logs JSON through go-log (`LOG_FORMAT=console` for local reading). The level comes from `LOG_LEVEL`.

Every HTTP request except WebSocket upgrades writes one `http` line with `method`, `path`, `status` and `dur` (milliseconds), plus `trace_id` and `span_id` when the request is traced.

## GraphQL errors

Every GraphQL response that carries errors, on `/graphql` and `/machine/graphql`, writes one `graphql error` line per error:

| Field | Meaning |
|---|---|
| `operation` | The GraphQL operation name, empty when the query failed validation |
| `path` | The field the error belongs to, e.g. `revealSecretFieldForPrincipal` |
| `code` | The gRPC code from the backing service (`PermissionDenied`, `Unavailable`, ...), `Unknown` for a plain error, or the GraphQL code such as `GRAPHQL_VALIDATION_FAILED` |
| `actor` | The caller's id: the signed-in user, a personal token's user, or a service account id. Never a token. |
| `duration` | How long the operation ran |

- Client-side codes log at `warn`: InvalidArgument, NotFound, AlreadyExists, PermissionDenied, FailedPrecondition, ResourceExhausted, Unauthenticated, OutOfRange, Canceled and GraphQL validation errors.
- Everything else logs at `error`: Internal, Unavailable, Unknown, DeadlineExceeded and the rest.
- Variables, arguments and response data are never logged.

## Diagnostics

Each fresh read of the component versions for the `diagnostics` query writes one `debug` line, `diagnostics: collected`, with `ms` (how long the probes took) and `unavailable` (the names of configured components that didn't answer). A read served from the 30-second cache writes a `trace` line with its `age_ms`. Addresses, URLs, tokens and error text are never logged.

## Readiness

A dependency that starts failing writes one `warn` line, `dependency check failing`, with `dependency`, `required`, `from`, `to` (`down` or `degraded`) and `error_class`; one that recovers writes an `info` line, `dependency recovered`. Nothing is logged while a state holds, and never the address or the error text.

## Telemetry export errors

OpenTelemetry's own errors go through the logger rather than stderr: one `warn` line, `telemetry export failed`, with the gRPC `code`, at most once a minute. The endpoint, headers and error text are never logged.

## Log export

With `OTLP_LOGS_ENABLED=true`, logs also go to the OTLP collector. Stdout doesn't change, and neither does the level it writes at. Export reads the JSON lines, so `LOG_FORMAT=console` exports nothing, and it stays off while `OTLP_INSECURE_SKIP_VERIFY=true`.

Export is default-deny. A record carries its time, level, `service`, `message`, trace and span ids, and only the fields on the list in `internal/telemetry/telemetry.go`. A new log field exports nothing until it's added there. Debug and trace lines never leave, whatever `LOG_LEVEL` says. Strings that remain go through go-otel's redactor, which also removes `snk_` tokens.

The list holds ids, counts, durations, classes, states and short enums:

| Kind | Fields |
|---|---|
| Ids | `actor`, `actor_user_id`, `caller`, `client_id`, `connection_id`, `run_id`, `secret_id`, `session_id`, `target_id`, `token_id`, `use_id`, `user_id` |
| Counts | `confirmed`, `count`, `decided`, `folders`, `host_keys`, `refused`, `secrets` |
| Durations | `age_ms`, `current`, `dur`, `duration`, `duration_ms`, `fallback`, `ms`, `session_ttl` |
| Classes, states, enums | `action`, `auth_mode`, `check`, `class`, `client_kind`, `code`, `decision`, `dependency`, `error_class`, `from`, `ok`, `required`, `route`, `rule`, `sso_reason`, `state`, `status`, `step`, `to`, `workload` |
| Switches | `appliance_configmap`, `approval_run_links`, `cookie_secure`, `hydra_enabled`, `machine_api_enabled`, `maintenance_readonly`, `mcp_clients`, `mcp_enabled` |

Free text, addresses and names stay off it, so these never leave: `error`, `reason`, `host`, `port`, `path`, `target`, `operation` and `method` (a client chooses both), `outcome` (a library can put error text in it), `issuer`, `oauth_public_url`, `allowed_origins`, the backend address fields, `folder`, `requested_folder`, `matched`, `identity`, the fingerprints and the time fields.

## SSH sessions

`openSshSession` writes an `info` line, `ssh session requested`, with `actor_user_id`, `secret_id` and `connection_id`, and once the broker has issued the ticket an `info` line, `ssh session ticket issued`, with `target_id`, `host`, `port`, `session_id` and `duration_ms`. A `debug` line, `ssh session target resolved`, adds the number of pinned host keys. A request that fails writes a `warn` line, `ssh session ticket failed`, with the `step` that failed (`secret`, `target`, `username` or `broker`), the `error` and `duration_ms`; past the 15-second bound the error names the service that didn't answer. The ticket and key material are never logged. The broker logs each step of the connect itself (see the broker's runbook).

## Secret-use batches

`decideSecretUses` writes one `info` line, `secret uses: batch decided`, with `user_id`, `decision`, `count`, `decided` and `refused`, and a `debug` line per item (`secret uses: decided` with `use_id` and `run_id`, or `secret uses: refused` with `use_id` and `reason`). A batch refused before any decision (step-up needed, wrong factor) writes a `warn` line. A vault refusal the gateway can't map writes an `error` line with `use_id` and the gRPC `code`, and the item comes back `UNAVAILABLE`. When identity can't name the tokens, a `warn` line `secret uses: token names unavailable, showing client labels` is written. `secretUseRun` writes a `debug` line with `run_id` and `count`. `confirmSecretUses` writes one `info` line, `secret uses: confirmed`, with `confirmed` and `refused`, a `debug` line per refused item and a `warn` line when the batch is refused before any use. `prepareSecretReveal` and `secretUsesToDecide` write a `debug` line each. When identity can't list the active people, a `warn` line `active users unavailable; approvals treat the install as multi-user` is written. Values and factors are never logged.
