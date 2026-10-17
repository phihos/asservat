package audit

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
)

// CaptureIntentSnapshot is private immutable provenance, never acquisition
// authority. Receipt is nil until independent acknowledgement commits.
type CaptureIntentSnapshot struct {
	Intent  value.CaptureIntent
	Receipt *value.Receipt
}

type ExactCaptureIntentReader interface {
	ReadCaptureIntent(context.Context, string) (CaptureIntentSnapshot, error)
}

// ExactCaptureIntentPublication reuses the exact acknowledged original without
// another seal, PUT or GET. Pending legacy rows deliberately remain unavailable:
// their conditional PUT writer has no durable one-use claim/positive completion.
// The qualified writer lifecycle is a prerequisite to automatic publication.
type ExactCaptureIntentPublication struct {
	RootID string
	Reader ExactCaptureIntentReader
	Now    func() time.Time
}

func (p ExactCaptureIntentPublication) AcknowledgedCaptureIntent(ctx context.Context, id string) (value.CaptureIntent, error) {
	var zero value.CaptureIntent
	if ctx == nil || ctx.Err() != nil || p.Reader == nil || p.Now == nil || !authorization.UUID(p.RootID) || !authorization.UUID(id) {
		return zero, ErrUnavailable
	}
	started := p.Now()
	until := started.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	s, err := p.Reader.ReadCaptureIntent(call, id)
	if err != nil || !s.Intent.Valid() || s.Intent.RootID != p.RootID || s.Intent.CaptureID != id || s.Receipt == nil || !s.Receipt.ValidCaptureIntent(p.RootID, id) || call.Err() != nil || p.Now().Before(started) || !p.Now().Before(until) {
		return zero, ErrUnavailable
	}
	return s.Intent, nil
}
