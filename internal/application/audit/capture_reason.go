package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"unicode/utf8"
)

func EncodeCaptureReasonEnvelope(e value.CaptureReasonEnvelope) ([]byte, error) {
	if !e.Valid() {
		return nil, ErrUnavailable
	}
	return captureEncoding(e, 16<<10)
}
func DecodeCaptureReasonEnvelope(raw []byte) (value.CaptureReasonEnvelope, error) {
	var e value.CaptureReasonEnvelope
	if len(raw) == 0 || len(raw) > 16<<10 {
		return e, ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil {
		return value.CaptureReasonEnvelope{}, ErrUnavailable
	}
	canonical, err := EncodeCaptureReasonEnvelope(e)
	if err != nil || !bytes.Equal(canonical, raw) {
		return value.CaptureReasonEnvelope{}, ErrUnavailable
	}
	return e, nil
}
func CaptureReasonEnvelopeMatches(ref value.CaptureReasonRef, e value.CaptureReasonEnvelope) bool {
	if !ref.Valid() {
		return false
	}
	raw, err := EncodeCaptureReasonEnvelope(e)
	if err != nil {
		return false
	}
	return sha256.Sum256(raw) == ref.CiphertextDigest
}

// CaptureReasonBinding uses the genuine parent (or singleton) capture identity
// and complete reviewed selection. It is descriptive metadata, not authority.
type CaptureReasonBinding struct {
	RootID, CaptureID string
	Requester         identity.Principal
	ScopeDigest       artifact.Digest
}
type CaptureReasonCipher interface {
	SealCaptureReason(context.Context, CaptureReasonBinding, string) (value.CaptureReasonEnvelope, error)
	OpenCaptureReason(context.Context, CaptureReasonBinding, value.CaptureReasonEnvelope) (string, error)
}

func CaptureReasonAssociatedData(b CaptureReasonBinding) ([]byte, error) {
	if !authorization.UUID(b.RootID) || !authorization.UUID(b.CaptureID) || !b.Requester.Valid() || b.ScopeDigest == (artifact.Digest{}) {
		return nil, ErrUnavailable
	}
	actor, err := captureEncoding(b.Requester, 8<<10)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(actor)
	return captureEncoding(struct {
		Format, RootID, CaptureID    string
		RequesterDigest, ScopeDigest artifact.Digest
	}{value.CaptureReasonEnvelopeFormat, b.RootID, b.CaptureID, digest, b.ScopeDigest}, 2048)
}
func ValidCaptureReasonText(text string) bool {
	return utf8.ValidString(text) && utf8.RuneCountInString(text) > 0 && utf8.RuneCountInString(text) <= 512
}
