# Gateway error codes

Human-readable mirror of `internal/apperr/codes.go`'s `Registry`. Keep both in sync.

| Code | Meaning |
|---|---|
| 2000 | Default/unclassified internal error |
| 2001 | Sample coded error (apperr package tests) |
| 2210 | Kratos login-flow init failed (`GET self-service/login/api`) |
| 2211 | Kratos password verify failed, non-credential (`POST self-service/login`) |
| 2212 | Kratos unreachable (transport-level failure) |
| 2213 | Kratos whoami/session-refresh failed (`GET sessions/whoami`) |
| 2214 | Kratos logout failed (`POST self-service/logout/api`) — best-effort |
| 2215 | Polis SSO flow state invalid (missing/mismatched state or redirect build failure) |
| 2216 | Polis code-exchange failed (`POST /api/oauth/token`) |
| 2217 | Polis userinfo failed (`GET /api/oauth/userinfo`) or userinfo carried no email |
| 2218 | SSO login rejected — no platform user for federated email (no-JIT) |
| 2221 | Kratos admin identity lookup failed (`GET admin/identities`) |
| 2222 | Kratos admin recovery-code creation failed (`POST admin/recovery/code`) |
| 2223 | Kratos self-service recovery flow failed, non-credential |
| 2224 | Kratos self-service settings flow failed, non-credential |
