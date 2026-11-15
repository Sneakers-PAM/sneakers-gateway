// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"regexp"
	"strings"
	"time"
	"unicode"

	log "github.com/Bugs5382/go-log"
	auditv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/audit/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// What the phone apps report about themselves, as audit events. The gateway
// takes the app's word for the client kind, the device and the event, and says
// so by recording them as client-reported; who and which secret it checks.

const (
	maxDeviceLen = 80
	maxScreenLen = 64
)

var (
	clientKindPattern = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	screenPattern     = regexp.MustCompile(`^[A-Za-z0-9._ -]{1,64}$`)
)

func errClientEventInvalid(msg string) error {
	return gatewayError(codes.InvalidArgument, msg, "CLIENT_EVENT_INVALID")
}

func errSecretNotFound() error {
	return gatewayError(codes.NotFound, "secret not found", "SECRET_NOT_FOUND")
}

// clientEventActor is the person reporting: a signed-in human, never a token
// or a service account.
func clientEventActor(ctx context.Context) (*vaultv1.ActorContext, error) {
	notPerson := gatewayError(codes.PermissionDenied, "a signed-in person is needed to report a client event", "CLIENT_EVENT_NOT_PERSON")
	if _, machine := machineActorFrom(ctx); machine {
		return nil, notPerson
	}
	a := actorOf(ctx)
	if uid := a.GetUserId(); uid == "" || uid == "system" || a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, notPerson
	}
	return a, nil
}

// clientEventAttrs checks what the app says about itself, and returns the
// audit attributes for it.
func clientEventAttrs(clientKind string, device *string) (map[string]string, error) {
	if !clientKindPattern.MatchString(clientKind) {
		return nil, errClientEventInvalid("clientKind must be a short lowercase token such as ios or android")
	}
	attrs := map[string]string{"client_kind": clientKind, "reported_by": "client"}
	if device != nil && strings.TrimSpace(*device) != "" {
		d := strings.TrimSpace(*device)
		if len([]rune(d)) > maxDeviceLen || strings.IndexFunc(d, unicode.IsControl) >= 0 {
			return nil, errClientEventInvalid("device must be a plain name of at most 80 characters")
		}
		attrs["device"] = d
	}
	return attrs, nil
}

// visibleSecret checks the caller can see the secret. An unknown secret and
// one the caller may not see answer the same, so a refusal says nothing about
// whether it exists.
func (r *Resolver) visibleSecret(ctx context.Context, actor *vaultv1.ActorContext, id string) error {
	_, err := r.Vault.GetSecret(ctx, &vaultv1.GetSecretRequest{Actor: actor, Id: id})
	switch status.Code(err) {
	case codes.OK:
		return nil
	case codes.NotFound, codes.PermissionDenied:
		r.logger(ctx).Info("client event refused: the secret is unknown or not visible to the caller", log.F("user_id", actor.GetUserId()))
		return errSecretNotFound()
	}
	return err
}

// recordClientEvent writes the event. A failed write is an error, so the app
// can retry: recording is the call's whole job.
func (r *Resolver) recordClientEvent(ctx context.Context, tier auditv1.Tier, action, userID, subject string, attrs map[string]string) error {
	if r.Audit == nil {
		return gatewayError(codes.Unavailable, "the audit log is unavailable", "AUDIT_UNAVAILABLE")
	}
	_, err := r.Audit.RecordEvent(ctx, &auditv1.RecordEventRequest{
		Tier: tier, Action: action, ActorUserId: userID, Subject: subject, Attributes: attrs,
		OccurredAt: r.now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		r.logger(ctx).Error(err, "client event audit failed", log.F("action", action), log.F("user_id", userID))
		return gatewayError(codes.Unavailable, "the audit log is unavailable", "AUDIT_UNAVAILABLE")
	}
	r.logger(ctx).Info("client event recorded", log.F("action", action), log.F("user_id", userID))
	return nil
}

func (r *Resolver) reportScreenCapture(ctx context.Context, in ScreenCaptureInput) (bool, error) {
	actor, err := clientEventActor(ctx)
	if err != nil {
		return false, err
	}
	attrs, err := clientEventAttrs(in.ClientKind, in.Device)
	if err != nil {
		return false, err
	}
	hasSecret, hasScreen := in.SecretID != nil && *in.SecretID != "", in.Screen != nil && *in.Screen != ""
	if hasSecret == hasScreen {
		return false, errClientEventInvalid("give the secret or the screen the capture was taken on, not both and not neither")
	}
	subject := ""
	if hasScreen {
		if !screenPattern.MatchString(*in.Screen) || len(*in.Screen) > maxScreenLen {
			return false, errClientEventInvalid("screen must be a plain name of at most 64 characters")
		}
		attrs["screen"] = *in.Screen
	} else {
		subject = *in.SecretID
		if err := r.visibleSecret(ctx, actor, subject); err != nil {
			return false, err
		}
	}
	action := "client.screenshot"
	if in.Kind == ScreenCaptureKindScreenRecording {
		action = "client.screen_recording"
	}
	if err := r.recordClientEvent(ctx, auditv1.Tier_TIER_AUDIT, action, actor.GetUserId(), subject, attrs); err != nil {
		return false, err
	}
	return true, nil
}

func (r *Resolver) recordSecretScan(ctx context.Context, in SecretScanInput) (bool, error) {
	actor, err := clientEventActor(ctx)
	if err != nil {
		return false, err
	}
	attrs, err := clientEventAttrs(in.ClientKind, in.Device)
	if err != nil {
		return false, err
	}
	if err := r.visibleSecret(ctx, actor, in.SecretID); err != nil {
		return false, err
	}
	if err := r.recordClientEvent(ctx, auditv1.Tier_TIER_ACTIVITY, "secret.qr_scan", actor.GetUserId(), in.SecretID, attrs); err != nil {
		return false, err
	}
	return true, nil
}
