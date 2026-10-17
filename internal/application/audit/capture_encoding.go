package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"bytes"
	"crypto/sha256"
	"encoding/json"
)

// This encoding belongs only to the new private capture format. It avoids HTML
// escaping inflation in bounded identity strings. Legacy records and the
// semantic digests remain unchanged; capture completion uses its own v1 domain.
func captureEncoding(v any, limit int) ([]byte, error) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return nil, ErrUnavailable
	}
	b := out.Bytes()
	if len(b) == 0 || b[len(b)-1] != '\n' || len(b)-1 > limit {
		clear(b)
		return nil, ErrUnavailable
	}
	return bytes.Clone(b[:len(b)-1]), nil
}
func EncodeCaptureOperationIntent(in value.OperationIntent) ([]byte, error) {
	if !in.Valid() || in.Name != value.CaptureOperationName || in.Lifecycle == nil || !value.CaptureOperationPolicy(in.Lifecycle.Policy) {
		return nil, ErrUnavailable
	}
	return captureEncoding(in, 16<<10)
}
func EncodeCaptureOperationOutcome(out value.OperationOutcome) ([]byte, error) {
	if !out.Valid() || out.Intent.Name != value.CaptureOperationName || out.Intent.Lifecycle == nil || !value.CaptureOperationPolicy(out.Intent.Lifecycle.Policy) {
		return nil, ErrUnavailable
	}
	return captureEncoding(out, 24<<10)
}

// New capture completion records use SHA-256 over this exact domain, a NUL,
// the closed phase, another NUL and the same bounded typed JSON bytes used by
// the private frame. Go field order, UTF-8, no HTML escaping and no trailing
// newline are part of v1. Old operation/certificate digest bytes are untouched.
func captureCompletionDigest(v any, phase string) artifact.Digest {
	var b []byte
	var err error
	switch r := v.(type) {
	case value.OperationIntent:
		if phase != "intent" {
			return artifact.Digest{}
		}
		b, err = EncodeCaptureOperationIntent(r)
	case value.OperationOutcome:
		if phase != "outcome" {
			return artifact.Digest{}
		}
		b, err = EncodeCaptureOperationOutcome(r)
	default:
		return artifact.Digest{}
	}
	if err != nil {
		return artifact.Digest{}
	}
	defer clear(b)
	h := sha256.New()
	_, _ = h.Write([]byte("asservat-capture-completion/v1\x00" + phase + "\x00"))
	_, _ = h.Write(b)
	var out artifact.Digest
	copy(out[:], h.Sum(nil))
	return out
}
