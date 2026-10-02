# Contributing to sneakers-gateway

This repository follows the Sneakers-PAM workflow in the org
[CONTRIBUTING.md](https://github.com/Sneakers-PAM/.github/blob/main/.github/CONTRIBUTING.md):
issues from a template, a branch per issue, Conventional Commits, squash-merged PRs, and a
[DCO](DCO) sign-off (`git commit -s`) on every commit.

## Working on this repo

- Build and test: see [README.md](README.md). The backend services, Redis and the login backends
  are faked inside the tests, so `go test ./...` needs nothing else running.
- Changing the API: edit `graphql/schema.graphqls` or `graphql/machine.graphqls`, then run
  `go tool gqlgen generate --config gqlgen.yml` (or `gqlgen-machine.yml`) and commit the result.
  Resolver bodies in the `*.resolvers.go` files survive regeneration; never edit `generated.go`
  or `models_gen.go` by hand. CI fails if the generated code is stale.
- Every `.go` file starts with the Apache-2.0 header, except the six files gqlgen rewrites
  (listed in `.licignore`):
  ```
  // Copyright 2026 The Sneakers-PAM Authors
  // SPDX-License-Identifier: Apache-2.0
  ```
- No real names, hosts, addresses or other identifiers in code, tests, fixtures or docs. Use
  example.org, 192.0.2.0/24, 2001:db8::/32 and invented names.
- Never log tokens, passwords, one-time codes or secret values, not even at `trace`; log an opaque
  id instead.
