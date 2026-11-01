package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"time"
)

const CaptureReasonInputFormat = "capture-intent-reason/v1"
const CaptureReasonEnvelopeFormat = "asservat-recording-save-reason/v1"
const CaptureReasonPlainLimit = 32 << 10

// CaptureReasonRef identifies opaque encrypted metadata, never acquisition authority.
type CaptureReasonRef struct {
	ID               string
	CiphertextDigest artifact.Digest
	ExpiresAt        time.Time
}

func (r CaptureReasonRef) Valid() bool {
	return authorization.UUID(r.ID) && r.CiphertextDigest != (artifact.Digest{}) && (r.ExpiresAt.IsZero() || microTime(r.ExpiresAt))
}

// Byte fields preserve the provider's exact opaque key representation without
// JSON string-escape amplification. Limits match the existing capture backend.
type CaptureReasonEnvelope struct {
	Format       string `json:"format"`
	KeyReference []byte `json:"keyReference"`
	WrappedKey   []byte `json:"wrappedKey"`
	Ciphertext   []byte `json:"ciphertext"`
}

func (e CaptureReasonEnvelope) Valid() bool {
	return e.Format == CaptureReasonEnvelopeFormat && len(e.KeyReference) > 0 && len(e.KeyReference) <= 256 && len(e.WrappedKey) > 0 && len(e.WrappedKey) <= 8192 && len(e.Ciphertext) > 33 && len(e.Ciphertext) <= 2081
}
