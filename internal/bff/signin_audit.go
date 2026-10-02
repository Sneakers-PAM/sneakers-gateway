// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"

	log "github.com/Bugs5382/go-log"
	auditv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/audit/v1"
	"google.golang.org/grpc"
)

// AuditRecorder is the part of the audit service the BFF writes to.
type AuditRecorder interface {
	RecordEvent(ctx context.Context, in *auditv1.RecordEventRequest, opts ...grpc.CallOption) (*auditv1.RecordEventResponse, error)
}

// maxAuditIdentifier caps the typed sign-in identifier kept on a rejected
// sign-in, so an anonymous caller can't write arbitrary amounts to the chain.
const maxAuditIdentifier = 254

// recordRejectedSignIn writes auth.signin with outcome rejected for a password
// Kratos refused. Identity records every accepted sign-in, but a rejected
// password never reaches it. Best effort: a failed write is logged and the
// caller still gets its 401. The password is never recorded.
func (h *Handler) recordRejectedSignIn(ctx context.Context, identifier string) {
	if h.Audit == nil {
		return
	}
	if len(identifier) > maxAuditIdentifier {
		identifier = identifier[:maxAuditIdentifier]
	}
	_, err := h.Audit.RecordEvent(ctx, &auditv1.RecordEventRequest{
		Tier:       auditv1.Tier_TIER_AUDIT,
		Action:     "auth.signin",
		Attributes: map[string]string{"step": "password", "outcome": "rejected", "identifier": identifier},
	})
	if err != nil {
		h.logger().Ctx(ctx).Error(err, "sign-in audit: recording a rejected password failed")
		return
	}
	h.logger().Ctx(ctx).Info("sign-in audit: rejected password recorded", log.F("action", "auth.signin"))
}
