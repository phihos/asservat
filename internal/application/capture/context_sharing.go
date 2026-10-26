package capture

import (
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// previewSharing checks what a preview can check about a capture-time sharing
// instruction (ADR-235) without another permission read: a human requester
// with the evidence:share scope, recipients of the requester's own issuer and
// an explicit end within the seven-day share maximum. Evidence-owner
// authority is checked by admission against the same projection it locks.
func previewSharing(s *value.ContextSharing, i identity.Identity, now time.Time) error {
	if s == nil {
		return nil
	}
	if i.Principal.Kind != identity.Human || !slices.Contains(i.Scopes, authorization.ShareScope) {
		return value.ErrSharingDenied
	}
	if !s.Valid() || s.Recipients[0].Issuer != i.Principal.Issuer || !s.NotAfter.IsZero() && (!s.NotAfter.After(now) || s.NotAfter.After(now.Add(authorization.ShareMaxLifetime))) {
		return value.ErrInvalid
	}
	return nil
}

// CaptureShareReader reports whether a capture-time share was materialized.
// It is the share ledger's read, not authority: the share is evaluated at
// every recipient read.
type CaptureShareReader interface {
	CaptureShareExists(ctx context.Context, shareID string) (bool, error)
}

// sharingStatus derives get_capture's separate sharing projection (ADR-235):
// Shared once the share exists, Pending while the capture can still publish,
// SharingUnavailable when it published (or ended) without one.
func sharingStatus(ctx context.Context, shares CaptureShareReader, p value.ContextProgressObservation) (*value.ContextSharingStatus, error) {
	if p.ShareID == "" {
		return nil, nil
	}
	if shares == nil {
		return nil, value.ErrUnavailable
	}
	exists, err := shares.CaptureShareExists(ctx, p.ShareID)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	switch {
	case exists:
		return &value.ContextSharingStatus{State: value.SharingShared, ShareID: p.ShareID}, nil
	case p.Phase == "Pending" || p.Phase == "Running" || p.Phase == "Finalizing":
		return &value.ContextSharingStatus{State: value.SharingPending}, nil
	}
	return &value.ContextSharingStatus{State: value.SharingUnavailable}, nil
}
