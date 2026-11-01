package capture

import (
	"context"
	"crypto/sha256"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/capture"
)

func validOptionalReason(text *string) bool {
	return text == nil || auditapp.ValidCaptureReasonText(*text)
}

func validPreviewReason(p value.ContextPreview) bool {
	if p.Intent.Reason == nil {
		return len(p.ReasonEnvelope) == 0
	}
	if !p.Intent.Reason.Valid() || p.Intent.Reason.ID != p.ID {
		return false
	}
	e, err := auditapp.DecodeCaptureReasonEnvelope(p.ReasonEnvelope)
	return err == nil && auditapp.CaptureReasonEnvelopeMatches(auditvalue.CaptureReasonRef{ID: p.Intent.Reason.ID, CiphertextDigest: p.Intent.Reason.CiphertextDigest, ExpiresAt: p.Intent.Reason.ExpiresAt}, e)
}

// preparePreviewReason seals descriptive text once, after the complete reviewed
// selection exists. It changes no collection scope or authority cutoff. The
// caller must recheck its original current facts after this blocking key call.
func (s ContextInvestigation) preparePreviewReason(ctx context.Context, p *value.ContextPreview, text *string) error {
	if !validOptionalReason(text) {
		return value.ErrInvalid
	}
	if text == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || s.ReasonCipher == nil || p == nil || p.Intent.Reason != nil || len(p.ReasonEnvelope) != 0 {
		return value.ErrUnavailable
	}
	envelope, err := s.ReasonCipher.SealCaptureReason(ctx, auditapp.CaptureReasonBinding{RootID: p.RootID, CaptureID: p.CaptureID, Requester: p.Actor, ScopeDigest: p.ScopeDigest}, *text)
	if err != nil {
		return value.ErrUnavailable
	}
	encoded, err := auditapp.EncodeCaptureReasonEnvelope(envelope)
	if err != nil || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	p.ReasonEnvelope = encoded
	p.Intent.Reason = &value.ProtectedReasonRef{ID: p.ID, CiphertextDigest: artifact.Digest(sha256.Sum256(encoded))}
	return nil
}

// CaptureReasonReader receives metadata only after the existing progress reader
// independently authorized every real child. It cannot turn a reference into
// entitlement and never chooses a first child's authority for a parent.
type CaptureReasonReader interface {
	ReadCaptureReason(context.Context, value.CaptureReasonMetadata) (string, error)
}

type CaptureReasonRecord struct {
	ValidUntil time.Time
	Capture    auditvalue.CaptureIntent
	Envelope   auditvalue.CaptureReasonEnvelope
}
type CaptureReasonRecords interface {
	ReadCaptureReasonRecord(context.Context, string) (CaptureReasonRecord, error)
}

type StoredCaptureReasons struct {
	Records CaptureReasonRecords
	Cipher  auditapp.CaptureReasonCipher
}

func (s StoredCaptureReasons) ReadCaptureReason(ctx context.Context, m value.CaptureReasonMetadata) (string, error) {
	if ctx == nil || ctx.Err() != nil || !m.Valid() || s.Records == nil || s.Cipher == nil {
		return "", value.ErrUnavailable
	}
	record, err := s.Records.ReadCaptureReasonRecord(ctx, m.AuditCaptureID)
	if err != nil || !record.Capture.Valid() || !record.Envelope.Valid() {
		return "", value.ErrUnavailable
	}
	c := record.Capture
	ref := auditvalue.CaptureReasonRef{ID: m.Reference.ID, CiphertextDigest: m.Reference.CiphertextDigest, ExpiresAt: m.Reference.ExpiresAt}
	parent := c.CaptureID
	if c.Group != nil {
		parent = c.Group.ParentCaptureID
	}
	if c.RootID != m.RootID || c.CaptureID != m.AuditCaptureID || parent != m.CaptureID || c.ScopeDigest != m.ScopeDigest || c.Requester() != m.Requester || c.ReasonRef == nil || *c.ReasonRef != ref || !auditapp.CaptureReasonEnvelopeMatches(ref, record.Envelope) {
		return "", value.ErrUnavailable
	}
	if !time.Now().Before(record.ValidUntil) {
		return "", value.ErrUnavailable
	}
	read, end := context.WithDeadline(ctx, record.ValidUntil)
	defer end()
	text, err := s.Cipher.OpenCaptureReason(read, auditapp.CaptureReasonBinding{RootID: m.RootID, CaptureID: m.CaptureID, Requester: m.Requester, ScopeDigest: m.ScopeDigest}, record.Envelope)
	if err != nil || read.Err() != nil || !time.Now().Before(record.ValidUntil) || !auditapp.ValidCaptureReasonText(text) {
		return "", value.ErrUnavailable
	}
	return text, nil
}
