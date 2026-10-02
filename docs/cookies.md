# Cookies

The BFF (`AUTH_MODE=real`) sets two cookies:

| Cookie | Path | SameSite | Purpose |
|---|---|---|---|
| `sneakers_sid` | `/` | Strict | The session id |
| `sneakers_sso_state` | `/auth/sso` | Lax | The single-use SSO state, 5 minutes |

Both are `HttpOnly`. Setting and clearing them use the same attributes.

## `COOKIE_SECURE`

The `Secure` flag is on by default. It is off only when:

- `AUTH_MODE=noauth` (plain-http dev), whatever `COOKIE_SECURE` says, or
- `COOKIE_SECURE` is explicitly false.

| `AUTH_MODE` | `COOKIE_SECURE` | Secure |
|---|---|---|
| `real` | unset | on |
| `real` | `true`, `1`, `t` | on |
| `real` | `false`, `0`, `f` | off |
| `noauth` | unset or any boolean | off |
| any | anything else (`yes`, `on`, ...) | the gateway refuses to start |

Values are parsed with Go's `strconv.ParseBool`: `1`, `t`, `T`, `true`, `True`, `TRUE` and `0`, `f`, `F`, `false`, `False`, `FALSE`. Surrounding spaces are trimmed. The gateway logs the effective setting at startup:

```json
{"level":"info","auth_mode":"real","cookie_secure":true,"message":"cookie config"}
```

An `AUTH_MODE=real` stack served over plain http on a host other than `localhost` needs `COOKIE_SECURE=false`, or the browser drops the session cookie.
