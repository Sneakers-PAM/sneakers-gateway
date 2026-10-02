// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	auditv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	notifyv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/notify/v1"
	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/sshbroker/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	workflowv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/bff"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqllog"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/machineresolvers"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/setup"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const serviceName = "gateway"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envTrue reports whether env var k is a true-ish value: "true" or "1" after
// trimming surrounding whitespace and comparing case-insensitively, so
// "True", "TRUE", " true" etc are all ON. Unset or any other value
// (including "false"/"0"/""/junk) is false — an explicit opt-IN flag,
// mirrored by newHydraVerifier so activation never happens by accident.
func envTrue(k string) bool {
	v := strings.TrimSpace(env(k, ""))
	return v == "1" || strings.EqualFold(v, "true")
}

// newHydraVerifier builds the machine bearer-auth path's OIDC leg from env,
// gated on HYDRA_ENABLED (default OFF), an explicit activation flag, so
// inertness holds by construction: while HYDRA_ENABLED is unset/false this
// returns a nil verifier and performs NO network I/O whatsoever
// (bff.NewVerifier's JWKS cache is lazy — it never fetches until something
// calls Verify, and nothing does when the verifier is nil). hydraIssuer is
// returned unconditionally — even when disabled — since the human admin
// surface's LinkOidcClient mutation still needs the configured issuer to link
// accounts ahead of activation.
//
// HYDRA_ENABLED=true with an empty HYDRA_ISSUER is refused at boot (Fatal),
// not silently tolerated: jwt.WithIssuer is only added to the parser options
// when the issuer is non-empty (jwks.go), so that combination would accept a
// token from ANY issuer whose signature merely verifies against whatever
// HYDRA_JWKS_URL happens to serve — activating the OIDC leg with issuer
// validation quietly disabled. logger is used only for this fatal
// misconfiguration check and the activation-state log line below.
func newHydraVerifier(logger zerolog.Logger) (*bff.Verifier, string) {
	hydraIssuer := env("HYDRA_ISSUER", "")
	enabled := envTrue("HYDRA_ENABLED")
	if enabled && hydraIssuer == "" {
		logger.Fatal().Msg("HYDRA_ENABLED=true but HYDRA_ISSUER is empty — refusing to start with JWT issuer validation disabled")
	}
	if !enabled {
		logger.Info().Msg("machine OIDC leg: inactive (HYDRA_ENABLED not set to a true-ish value)")
		return nil, hydraIssuer
	}
	hydraLeeway := 30 * time.Second
	if n, err := strconv.Atoi(env("JWT_LEEWAY_SECONDS", "")); err == nil {
		hydraLeeway = time.Duration(n) * time.Second
	}
	verifier := bff.NewVerifier(
		env("HYDRA_JWKS_URL", "http://sneakers-hydra:4444/.well-known/jwks.json"),
		hydraIssuer,
		env("HYDRA_AUDIENCE", "sneakers-mcp"),
		"", 10*time.Minute, hydraLeeway)
	logger.Info().Str("issuer", hydraIssuer).Msg("machine OIDC leg: active")
	return verifier, hydraIssuer
}

// Session lifetime bounds. The effective session timeout is the admin-editable
// vault SecuritySettings.session_ttl_seconds, clamped to [15m, 60m]; it drives
// both the session-store expiry and the sliding renewal, so a mis-set value can
// neither expire sessions mid-use nor keep them alive indefinitely. An unset
// (zero) value resolves to the 30m default.
const (
	sessionTTLDefault = 30 * time.Minute
	sessionTTLMin     = 15 * time.Minute
	sessionTTLMax     = 60 * time.Minute
	// sessionTTLRefresh is how often the gateway re-reads the configured session
	// timeout from vault so an admin change takes effect without a redeploy and
	// without a vault round-trip on every authenticated request.
	sessionTTLRefresh = 60 * time.Second
)

// clampSessionTTL constrains d to the supported [15m, 60m] window; a zero/unset
// value resolves to the 30m default.
func clampSessionTTL(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return sessionTTLDefault
	case d < sessionTTLMin:
		return sessionTTLMin
	case d > sessionTTLMax:
		return sessionTTLMax
	default:
		return d
	}
}

// sessionTTLProvider caches the admin-configured session lifetime read from the
// vault SecuritySettings singleton. Reads (get) are lock-free; a background
// loop refreshes the cache on sessionTTLRefresh. When vault is briefly
// unreachable the last known good value is retained — seeded to the 30m default
// — so authentication keeps working.
type sessionTTLProvider struct {
	vault vaultv1.VaultServiceClient
	cur   atomic.Int64 // current TTL, nanoseconds
}

// newSessionTTLProvider seeds the cache with the clamped default (30m) so a
// caller always gets a sane value even before the first vault read.
func newSessionTTLProvider(vault vaultv1.VaultServiceClient) *sessionTTLProvider {
	p := &sessionTTLProvider{vault: vault}
	p.cur.Store(int64(sessionTTLDefault))
	return p
}

// get returns the current cached session lifetime.
func (p *sessionTTLProvider) get() time.Duration { return time.Duration(p.cur.Load()) }

// refresh reads SecuritySettings from vault, clamps session_ttl_seconds to the
// supported window, and updates the cache. On error the previous cached value is
// retained and returned alongside the error.
func (p *sessionTTLProvider) refresh(ctx context.Context) (time.Duration, error) {
	resp, err := p.vault.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{})
	if err != nil {
		return p.get(), err
	}
	ttl := clampSessionTTL(time.Duration(resp.GetSettings().GetSessionTtlSeconds()) * time.Second)
	p.cur.Store(int64(ttl))
	return ttl, nil
}

// checkAuthBackend refuses any AUTH_BACKEND other than kratos (or unset), so a
// leftover setting fails at start instead of being ignored.
func checkAuthBackend(v string) error {
	switch v {
	case "", "kratos":
		return nil
	case "keycloak":
		return errors.New("AUTH_BACKEND=keycloak: Keycloak is not supported; Sneakers signs in with Ory Kratos (set AUTH_BACKEND=kratos or leave it unset)")
	default:
		return fmt.Errorf("AUTH_BACKEND=%q is not a known backend; the only backend is kratos", v)
	}
}

// newRealAuthHandler builds the AUTH_MODE=real BFF: the Ory Kratos password
// backend, Redis-backed sessions, the optional Ory Polis SSO leg, and the
// identity client used to adopt/provision the user at login and resolve the
// per-request ActorContext (roles + group names). ttlFn returns the current,
// already-clamped session lifetime (admin-configured via vault SecuritySettings)
// and is evaluated on every session write and cookie refresh, so the store
// expiry and the sliding renewal always track the live setting.
func newRealAuthHandler(ctx context.Context, identity identityv1.IdentityServiceClient, ttlFn func() time.Duration, secure bool) (*bff.Handler, error) {
	rc, err := bff.ParseRedisURL(ctx, env("REDIS_URL", "redis://localhost:26379/0"))
	if err != nil {
		return nil, err
	}
	// pendingTTL bounds the 2-step login window: after a successful password
	// step the session token is parked for at most this long awaiting the second
	// factor, then the record expires (Redis TTL) and the user restarts login.
	pendingTTL := 5 * time.Minute
	if d, derr := time.ParseDuration(env("MFA_PENDING_TTL", "")); derr == nil {
		pendingTTL = d
	}
	h := &bff.Handler{
		Store:      bff.NewRedisStore(rc, ttlFn),
		Identity:   identity,
		Pending:    bff.NewRedisPendingStore(rc, pendingTTL),
		OAuthStore: bff.NewRedisOAuthStore(rc),
		TTLFn:      ttlFn,
		Secure:     secure,
		// MFA enforced by default: an un-enrolled user gets a half-session that can
		// only reach the enrollment endpoints. Set MFA_ENFORCED=0/false to make MFA
		// optional (login proceeds; the client shows a setup-recommended banner).
		MfaEnforced: env("MFA_ENFORCED", "true") != "false" && env("MFA_ENFORCED", "true") != "0",
		Auth:        bff.NewKratosClient(env("KRATOS_PUBLIC_URL", "http://sneakers-kratos:4433"), env("KRATOS_ADMIN_URL", "http://sneakers-kratos:4434")),
	}
	if pub := env("POLIS_PUBLIC_URL", ""); pub != "" {
		h.Polis = bff.NewPolisClient(
			pub,
			env("POLIS_ISSUER_URL", "http://sneakers-polis:5225"),
			env("POLIS_PRODUCT", "sneakers"),
			env("POLIS_TENANT", "example.org"),
		)
		h.SSORedirectBase = env("SSO_REDIRECT_BASE", "")
		h.SSOAppBase = env("SSO_APP_BASE", "/")
	}
	return h, nil
}

//nolint:gocognit,gocyclo // wires every client, route and auth mode in one place
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(serviceName)
	if err := checkAuthBackend(os.Getenv("AUTH_BACKEND")); err != nil {
		logger.Fatal().Err(err).Msg("auth backend")
	}
	// reqLog is the neutral logger for request-scoped lines: its Ctx method
	// adds the active span's trace and span ids.
	reqLog := log.NewLogger(serviceName)
	vaultAddr := env("VAULT_ADDR", "localhost:9091")
	identityAddr := env("IDENTITY_ADDR", "localhost:9092")
	workflowAddr := env("WORKFLOW_ADDR", "localhost:9093")
	auditAddr := env("AUDIT_ADDR", "localhost:9194")
	notifyAddr := env("NOTIFY_ADDR", "localhost:9195")
	sshbrokerAddr := env("SSHBROKER_ADDR", "localhost:9096")
	httpPort := env("HTTP_PORT", "9100")
	otlp := env("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	// hydraVerifier/hydraIssuer: the machine path's OIDC leg.
	// hydraIssuer is also used as the human admin surface's default OIDC
	// issuer (LinkOidcClient). See newHydraVerifier: the OIDC leg is active
	// only when HYDRA_ENABLED is true.
	hydraVerifier, hydraIssuer := newHydraVerifier(logger)

	// Observability from day one: traces + metrics via go-otel, structured logs
	// via go-log (trace-correlated through the logger's Ctx method).
	otelShutdown, err := otel.Init(ctx, serviceName, otlp)
	if err != nil {
		logger.Fatal().Err(err).Msg("otel init")
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn().Err(err).Msg("otel shutdown")
		}
	}()

	// gRPC client spans to the vault (otel stats handler).
	conn, err := grpc.NewClient(vaultAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStatsHandler(otel.GRPCClientStatsHandler()))
	if err != nil {
		logger.Fatal().Err(err).Str("vault", vaultAddr).Msg("dial vault")
	}
	defer func() { _ = conn.Close() }()
	vaultClient := vaultv1.NewVaultServiceClient(conn)

	idConn, err := grpc.NewClient(identityAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStatsHandler(otel.GRPCClientStatsHandler()))
	if err != nil {
		logger.Fatal().Err(err).Str("identity", identityAddr).Msg("dial identity")
	}
	defer func() { _ = idConn.Close() }()
	identityClient := identityv1.NewIdentityServiceClient(idConn)

	wfConn, err := grpc.NewClient(workflowAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStatsHandler(otel.GRPCClientStatsHandler()))
	if err != nil {
		logger.Fatal().Err(err).Str("workflow", workflowAddr).Msg("dial workflow")
	}
	defer func() { _ = wfConn.Close() }()
	workflowClient := workflowv1.NewWorkflowServiceClient(wfConn)

	auditConn, err := grpc.NewClient(auditAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStatsHandler(otel.GRPCClientStatsHandler()))
	if err != nil {
		logger.Fatal().Err(err).Str("audit", auditAddr).Msg("dial audit")
	}
	defer func() { _ = auditConn.Close() }()
	auditClient := auditv1.NewAuditServiceClient(auditConn)

	nConn, err := grpc.NewClient(notifyAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStatsHandler(otel.GRPCClientStatsHandler()))
	if err != nil {
		logger.Fatal().Err(err).Str("notify", notifyAddr).Msg("dial notify")
	}
	defer func() { _ = nConn.Close() }()
	notifyClient := notifyv1.NewNotifyServiceClient(nConn)

	sshbrokerConn, err := grpc.NewClient(sshbrokerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStatsHandler(otel.GRPCClientStatsHandler()))
	if err != nil {
		logger.Fatal().Err(err).Str("sshbroker", sshbrokerAddr).Msg("dial sshbroker")
	}
	defer func() { _ = sshbrokerConn.Close() }()
	sshbrokerClient := sshbrokerv1.NewSSHBrokerServiceClient(sshbrokerConn)

	gql := handler.New(resolvers.NewExecutableSchema(resolvers.Config{Resolvers: &resolvers.Resolver{Vault: vaultClient, Identity: identityClient, Workflow: workflowClient, Audit: auditClient, Notify: notifyClient, SSHBroker: sshbrokerClient, HydraIssuer: hydraIssuer}}))
	gql.AddTransport(transport.Options{})
	gql.AddTransport(transport.POST{})
	gql.Use(extension.Introspection{})
	gql.Use(gqllog.ErrorLog{Log: reqLog, Actor: resolvers.CallerID})

	// Same-origin-only WebSocket upgrader for GraphQL subscriptions. A WS upgrade
	// can't carry the CSRF double-submit header, so cross-origin sockets are
	// blocked here by the Origin check; the per-socket authentication then happens
	// in the transport InitFunc (below).
	wsUpgrader := websocket.Upgrader{CheckOrigin: sameOriginWS}

	// AUTH_MODE selects how the acting user is established:
	//   noauth (DEFAULT): the X-Dev-User header (dev personas).
	//   real: Ory Kratos login via the BFF; the acting user comes from the
	//         authenticated session cookie, and /graphql fails closed (401) with
	//         no valid session — never a silent fallback.
	authMode := env("AUTH_MODE", "noauth")
	secureCookies, err := cookieSecure(authMode, os.Getenv("COOKIE_SECURE"))
	if err != nil {
		logger.Fatal().Err(err).Msg("cookie config")
	}
	logger.Info().Str("auth_mode", authMode).Bool("cookie_secure", secureCookies).Msg("cookie config")
	mux := http.NewServeMux()
	if authMode == "real" {
		// Session timeout is admin-configured (vault SecuritySettings), not an env
		// var: seed the cache from vault at startup and refresh it in the background
		// so a change takes effect without a redeploy. A vault read failure falls
		// back to the clamped 30m default already seeded in the provider.
		ttlProvider := newSessionTTLProvider(vaultClient)
		if ttl, rerr := ttlProvider.refresh(ctx); rerr != nil {
			logger.Warn().Err(rerr).Dur("fallback", ttlProvider.get()).
				Msg("session timeout: initial security-settings read failed; using default")
		} else {
			logger.Info().Dur("session_ttl", ttl).Msg("session timeout loaded from security settings")
		}
		go func() {
			t := time.NewTicker(sessionTTLRefresh)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if _, rerr := ttlProvider.refresh(ctx); rerr != nil {
						logger.Warn().Err(rerr).Dur("current", ttlProvider.get()).
							Msg("session timeout refresh failed; retaining cached value")
					}
				}
			}
		}()
		bffH, err := newRealAuthHandler(ctx, identityClient, ttlProvider.get, secureCookies)
		if err != nil {
			logger.Fatal().Err(err).Msg("auth setup")
		}
		bffH.Log = reqLog
		// MCP /login: the OAuth native-app authorization server that issues
		// personal tokens. Mounted only when the env's public UI URL is set.
		if pub := env("OAUTH_PUBLIC_URL", ""); pub != "" {
			o := (&bff.OAuth{Handler: bffH, Store: bffH.OAuthStore, PublicURL: pub}).Routes()
			mux.Handle("/oauth2/", o)
			mux.Handle("/.well-known/oauth-authorization-server", o)
		}
		mux.Handle("/auth/login", cors(http.HandlerFunc(bffH.Login)))
		mux.Handle("/auth/logout", cors(http.HandlerFunc(bffH.Logout)))
		mux.Handle("/auth/session", cors(http.HandlerFunc(bffH.Session)))
		// Self-service password reset — public, unauthenticated.
		mux.Handle("/auth/reset/request", cors(http.HandlerFunc(bffH.ResetRequest)))
		mux.Handle("/auth/reset/confirm", cors(http.HandlerFunc(bffH.ResetConfirm)))
		// Email verification: public, unauthenticated (like reset). Serves
		// the /setup and post-account-creation verify flows that have no session.
		mux.Handle("/auth/verify/request", cors(http.HandlerFunc(bffH.VerifyRequest)))
		mux.Handle("/auth/verify/confirm", cors(http.HandlerFunc(bffH.VerifyConfirm)))
		// 2-step MFA: verify the second factor at login (kind-dispatched:
		// totp|email); /auth/mfa/otp/send emails a login-purpose code. Enroll TOTP
		// or prove the email factor for the authed user (all enroll/confirm/verify
		// endpoints enforce the session cookie + CSRF).
		mux.Handle("/auth/verify-otp", cors(http.HandlerFunc(bffH.VerifyOtp)))
		mux.Handle("/auth/mfa/otp/send", cors(http.HandlerFunc(bffH.MfaOtpSend)))
		mux.Handle("/auth/mfa/enroll", cors(http.HandlerFunc(bffH.MfaEnroll)))
		mux.Handle("/auth/mfa/confirm", cors(http.HandlerFunc(bffH.MfaConfirm)))
		// Passkey/WebAuthn: login assert (pending) + authed enroll.
		mux.Handle("/auth/mfa/webauthn/begin", cors(http.HandlerFunc(bffH.MfaWebauthnBegin)))
		mux.Handle("/auth/mfa/webauthn/register/begin", cors(http.HandlerFunc(bffH.EnrollWebauthnBegin)))
		mux.Handle("/auth/mfa/webauthn/register/finish", cors(http.HandlerFunc(bffH.EnrollWebauthnFinish)))
		mux.Handle("/auth/mfa/email/send", cors(http.HandlerFunc(bffH.MfaEmailSend)))
		mux.Handle("/auth/mfa/email/verify", cors(http.HandlerFunc(bffH.MfaEmailVerify)))
		// TOTP self/admin removal: the authed user resets their own factor (lost
		// device); a site-admin/root removes another user's factor as account
		// recovery. Both call identity's generalized RemoveFactor(kind=totp).
		mux.Handle("/auth/mfa/remove", cors(http.HandlerFunc(bffH.MfaRemove)))
		mux.Handle("/auth/mfa/admin/remove-totp", cors(http.HandlerFunc(bffH.MfaAdminRemoveTotp)))
		mux.Handle("/auth/mfa/admin/status", cors(http.HandlerFunc(bffH.MfaAdminStatus)))
		mux.Handle("/auth/sso/login", cors(http.HandlerFunc(bffH.SSOLogin)))
		mux.Handle("/auth/sso/callback", cors(http.HandlerFunc(bffH.SSOCallback)))
		// Subscriptions (WS): authenticate the socket from the SESSION COOKIE at
		// connection_init, mirroring the HTTP SessionActor gate through the shared
		// resolveSessionActor core. Fail closed — no valid session rejects the
		// socket. The resolved ActorContext rides the connection context so the
		// subscription resolver's actorOf(ctx) is RACI-scoped identically to POST.
		gql.AddTransport(transport.Websocket{
			KeepAlivePingInterval: 10 * time.Second,
			Upgrader:              wsUpgrader,
			InitFunc: func(connCtx context.Context, _ transport.InitPayload) (context.Context, *transport.InitPayload, error) {
				r := wsRequestFrom(connCtx)
				if r == nil {
					return connCtx, nil, errors.New("no_request")
				}
				actorCtx, aerr := bffH.AuthenticateWS(connCtx, r)
				if aerr != nil {
					return connCtx, nil, aerr
				}
				return actorCtx, nil, nil
			},
		})
		mux.Handle("/graphql", cors(graphqlWithWS(gql, bffH.SessionActor(gql))))
		logger.Info().Str("auth_backend", "kratos").Msg("auth mode: real (BFF, Redis sessions, 2-step MFA: totp+email+passkey; WS subscriptions cookie-authed)")
	} else {
		// Subscriptions (WS) in no-auth dev: a browser can't set the X-Dev-User
		// header on a WS upgrade, so the persona rides the connection_init payload
		// instead; enrich it exactly like the HTTP no-auth path.
		gql.AddTransport(transport.Websocket{
			KeepAlivePingInterval: 10 * time.Second,
			Upgrader:              wsUpgrader,
			InitFunc: func(connCtx context.Context, initPayload transport.InitPayload) (context.Context, *transport.InitPayload, error) {
				user := initPayload.GetString("x-dev-user")
				actorCtx := resolvers.WithActor(connCtx, user)
				actorCtx = enrichActor(actorCtx, identityClient, user)
				return actorCtx, nil, nil
			},
		})
		mux.Handle("/graphql", withCORSActor(identityClient, gql))
	}

	// Machine bearer-auth path (with a pluggable OIDC leg): a SEPARATE GraphQL
	// endpoint for non-human callers, gated by bff.MachineActor instead of the human SessionActor/no-auth gates above —
	// no cookie, no CSRF, no MFA. Mounted unconditionally (independent of
	// AUTH_MODE): the bearer token is verified against identity regardless of
	// whether the human login surface is real or noauth-dev. machineGQL is its
	// own executable schema (internal/machineresolvers, graphql/machine.graphqls)
	// so the human /graphql surface above is never touched by this mount.
	// hydraVerifier/hydraIssuer are computed once, above, by newHydraVerifier.
	machineH := &bff.Handler{Identity: identityClient, MachineOidcVerifier: hydraVerifier, MachineOidcIssuer: hydraIssuer}
	machineGQL := handler.New(machineresolvers.NewExecutableSchema(machineresolvers.Config{
		Resolvers: &machineresolvers.Resolver{Vault: vaultClient, PublicURL: env("OAUTH_PUBLIC_URL", "")},
	}))
	machineGQL.AddTransport(transport.POST{})
	machineGQL.Use(gqllog.ErrorLog{Log: reqLog, Actor: resolvers.CallerID})
	mux.Handle("/machine/graphql", cors(machineH.MachineActor(machineGQL)))

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","mode":"` + authMode + `"}`))
	})

	// First-run admin bootstrap (/setup). Mounted OUTSIDE the auth/session
	// middleware (alongside /health) — the whole point is to create the first
	// admin before anyone can log in. The write is guarded by SETUP_TOKEN here and
	// the no-root invariant in identity. Wrapped in cors so the UI /setup
	// page can call it cross-origin in dev.
	setupToken := env("SETUP_TOKEN", "")
	var ssoProv *bff.JacksonProvisioner
	if admin := env("POLIS_ADMIN_URL", ""); admin != "" {
		ssoProv = bff.NewJacksonProvisioner(
			admin,
			env("POLIS_API_KEY", ""),
			env("POLIS_PRODUCT", "sneakers"),
			env("POLIS_TENANT", "example.org"),
			env("SSO_REDIRECT_BASE", ""),
			env("POLIS_SAML_METADATA_URL", ""),
		)
	}
	setupH := setup.New(identityClient, vaultClient, setupToken, ssoProv)
	setupH.Log = reqLog
	mux.Handle("/setup/state", cors(setupH.StateHandler()))
	mux.Handle("/setup/bootstrap", cors(setupH.BootstrapHandler()))
	// After the first admin is created, the wizard POSTs here to install the
	// built-in baseline into the fresh vault (idempotent, SETUP_TOKEN-gated).
	mux.Handle("/setup/seed", cors(setupH.SeedHandler()))
	if setupToken != "" {
		// Dev convenience: echo the setup token prominently so an operator can
		// bootstrap the first admin without digging through the deployment
		// config. Never rely on this in prod.
		logger.Info().Str("setup_token", setupToken).Msg("SETUP_TOKEN configured — POST /setup/bootstrap with this token to create the first admin")
	} else {
		logger.Warn().Msg("SETUP_TOKEN not set — /setup/bootstrap disabled (returns 503)")
	}

	// otelhttp (server spans) → request logging → HTTP metrics → mux.
	instrumented := otelhttp.NewHandler(withLogging(reqLog, otel.Metrics(mux)), "gateway")
	// WebSocket upgrades (GraphQL subscriptions) need a ResponseWriter that
	// implements http.Hijacker. The otel/logging/metrics wrappers wrap the writer
	// without forwarding Hijack (gorilla then fails the upgrade with 500), so route
	// upgrades straight to the mux with the raw writer; everything else stays fully
	// instrumented. A long-lived subscription socket isn't meaningfully captured by
	// per-request spans/metrics anyway.
	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketUpgrade(r) {
			mux.ServeHTTP(w, r)
			return
		}
		instrumented.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: ":" + httpPort, Handler: rootHandler, ReadHeaderTimeout: 10 * time.Second}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	logger.Info().Str("http", httpPort).Str("auth_mode", authMode).Str("vault", vaultAddr).Str("identity", identityAddr).Str("workflow", workflowAddr).Str("audit", auditAddr).Str("notify", notifyAddr).Str("sshbroker", sshbrokerAddr).Str("otlp", otlp).Msg("gateway starting (/graphql)")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal().Err(err).Msg("http server exited")
	}
}

// cors applies dev CORS (credentialed — echoes the request Origin, never "*",
// so cookie-bearing requests are allowed) and short-circuits preflight.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Vary", "Origin")
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			// Authorization is allowed for the machine bearer-auth path
			// (/machine/graphql) — a preflighted cross-origin
			// machine client sends its API token in this header.
			h.Set("Access-Control-Allow-Headers", "Content-Type,X-Dev-User,X-CSRF-Token,Authorization")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// wsReqCtxKey carries the raw *http.Request through the request context so the
// WebSocket transport's InitFunc (which only receives the connection context)
// can read the session cookie for authentication.
type wsReqCtxKey struct{}

func withWSRequest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, wsReqCtxKey{}, r)
}

func wsRequestFrom(ctx context.Context) *http.Request {
	r, _ := ctx.Value(wsReqCtxKey{}).(*http.Request)
	return r
}

// isWebSocketUpgrade reports whether the request is a GraphQL-over-WS upgrade
// (subscriptions) rather than a normal POST query/mutation.
func isWebSocketUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// sameOriginWS is the WebSocket upgrade Origin guard: the socket's Origin host
// must equal the request host (behind a reverse proxy the original host arrives
// as X-Forwarded-Host). Cross-origin sockets are rejected — this stands in for the
// CSRF double-submit that a WS upgrade cannot carry. A missing Origin (non-browser
// client) is also rejected.
func sameOriginWS(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := r.Host
	if xf := r.Header.Get("X-Forwarded-Host"); xf != "" {
		host = xf
	}
	return strings.EqualFold(u.Host, host)
}

// graphqlWithWS serves the single /graphql endpoint for BOTH shapes in real-auth
// mode: a WS upgrade (GET) goes straight to the gqlgen handler with the request
// stashed for the InitFunc to authenticate from the cookie (the HTTP SessionActor
// gate is bypassed — it would 403 a GET upgrade that carries no CSRF header),
// while everything else (POST queries/mutations) passes through the SessionActor
// gate unchanged.
func graphqlWithWS(gql http.Handler, httpGate http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketUpgrade(r) {
			gql.ServeHTTP(w, r.WithContext(withWSRequest(r.Context(), r)))
			return
		}
		httpGate.ServeHTTP(w, r)
	})
}

// withCORSActor is the no-auth path: CORS + the dev persona identity
// (X-Dev-User) injected into the resolver context, enriched with the user's
// site-admin/root/groups from the identity service (for firewall-RACI).
func withCORSActor(identity identityv1.IdentityServiceClient, next http.Handler) http.Handler {
	return cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := resolvers.WithActor(r.Context(), r.Header.Get("X-Dev-User"))
		ctx = enrichActor(ctx, identity, r.Header.Get("X-Dev-User"))
		next.ServeHTTP(w, r.WithContext(ctx))
	}))
}

// enrichActor resolves the acting user's authz attributes from identity. Best
// effort: if identity is unavailable the actor stays unenriched (no admin/groups).
func enrichActor(ctx context.Context, identity identityv1.IdentityServiceClient, userID string) context.Context {
	if userID == "" || identity == nil {
		return ctx
	}
	resp, err := identity.GetUser(ctx, &identityv1.GetUserRequest{Id: userID})
	if err != nil {
		return ctx
	}
	u := resp.GetUser()
	siteAdmin := false
	for _, role := range u.GetRoles() {
		if role == "site-admin" {
			siteAdmin = true
			break
		}
	}
	// GroupNames stay nil (identity has no membership model yet), so
	// group-subject RACI rules don't match; user/everyone/owner/site-admin
	// rules do.
	return resolvers.WithActorInfo(ctx, siteAdmin, u.GetIsRoot(), nil)
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) {
	s.code = c
	s.ResponseWriter.WriteHeader(c)
}

// withLogging logs one trace-correlated line per request (l.Ctx picks up the
// active span's trace/span ids from otelhttp).
func withLogging(l log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)
		l.Ctx(r.Context()).Info("http",
			log.F("method", r.Method), log.F("path", r.URL.Path),
			log.F("status", rec.code), log.F("dur", float64(time.Since(start))/float64(time.Millisecond)))
	})
}
