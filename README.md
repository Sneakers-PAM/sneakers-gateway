# Gateway Service 🚪

> 🧭 The GraphQL and machine API for the web, mobile and MCP clients: one front door to every Sneakers service.

The gateway is the only service the clients talk to. It serves two GraphQL endpoints built with
gqlgen, handles login and sessions as a backend-for-frontend (BFF), and calls the identity, vault,
workflow, audit, notify and SSH broker services over gRPC, passing each call the caller's actor
context.

## ✨ Highlights

- 🧩 **Human GraphQL:** `/graphql` (queries, mutations and a WebSocket subscription) for the web and mobile apps, behind a session cookie and a CSRF token.
- 🤖 **Machine GraphQL:** `/machine/graphql` for personal tokens, service-account API tokens and, when enabled, OIDC client-credentials tokens: no cookie, no CSRF.
- 🔑 **Login:** Keycloak or Ory Kratos as the password backend, a second factor (TOTP, email code or passkey), SAML single sign-on through Polis, and an OAuth authorization server for native clients such as the MCP server.
- 🍪 **Server-side sessions:** session and pending-login records live in Redis; the browser only holds an opaque, `HttpOnly` session id.
- 🛠️ **First-run setup:** `/setup/*` creates the first admin and seeds the vault's built-in types, guarded by `SETUP_TOKEN`.
- 📈 **Observable:** OpenTelemetry traces and metrics, and one JSON log line per request and per GraphQL error.

## ⚠️ Before production

The services behind the gateway trust the actor context it sends, and the gateway talks to them
over plaintext gRPC. Keep those hops on a private network or behind a service mesh with mTLS, and
read [docs/runbook.md](docs/runbook.md) before you deploy it.

## 🚀 Run it

```bash
go run ./cmd/gateway
```

HTTP listens on port 9100. The default `AUTH_MODE=noauth` is for local development only: the caller
is whoever the `X-Dev-User` header names, and Redis and the login backends aren't needed. The
backend services are dialled lazily, so the gateway starts without them; calls that need one fail
until it's up. [docs/configuration.md](docs/configuration.md) lists every setting.

Run the tests (the backends are faked in process, so nothing else is needed):

```bash
go test ./...
```

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # tests, gofmt check, golangci-lint and yamllint
task license  # check the Apache-2.0 headers (golic)
```

After changing a schema in `graphql/`, regenerate the resolvers' generated code:

```bash
go tool gqlgen generate --config gqlgen.yml
go tool gqlgen generate --config gqlgen-machine.yml
```

## 📚 Where to look

- [docs/configuration.md](docs/configuration.md): environment variables.
- [docs/api.md](docs/api.md): the HTTP routes and the two GraphQL schemas.
- [docs/runbook.md](docs/runbook.md): operating the service.
- [docs/machine-graphql.md](docs/machine-graphql.md) and [docs/machine-automation.md](docs/machine-automation.md): the machine API in detail.
- [docs/cookies.md](docs/cookies.md), [docs/logging.md](docs/logging.md) and [docs/error-codes.md](docs/error-codes.md).

## ⚖️ License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
