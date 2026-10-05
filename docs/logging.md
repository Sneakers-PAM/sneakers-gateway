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
