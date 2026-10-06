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

## Secret-use batches

`decideSecretUses` writes one `info` line, `secret uses: batch decided`, with `user_id`, `decision`, `count`, `decided` and `refused`, and a `debug` line per item (`secret uses: decided` with `use_id` and `run_id`, or `secret uses: refused` with `use_id` and `reason`). A batch refused before any decision (step-up needed, wrong factor) writes a `warn` line. A vault refusal the gateway can't map writes an `error` line with `use_id` and the gRPC `code`, and the item comes back `UNAVAILABLE`. When identity can't name the tokens, a `warn` line `secret uses: token names unavailable, showing client labels` is written. `secretUseRun` writes a `debug` line with `run_id` and `count`. `confirmSecretUses` writes one `info` line, `secret uses: confirmed`, with `confirmed` and `refused`, a `debug` line per refused item and a `warn` line when the batch is refused before any use. `prepareSecretReveal` and `secretUsesToDecide` write a `debug` line each. When identity can't list the active people, a `warn` line `active users unavailable; approvals treat the install as multi-user` is written. Values and factors are never logged.
