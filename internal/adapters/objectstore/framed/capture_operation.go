package framed

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"

	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
)

func captureOperationPlain(record any) ([]byte, error) {
	switch r := record.(type) {
	case audit.OperationIntent:
		return app.EncodeCaptureOperationIntent(r)
	case audit.OperationOutcome:
		return app.EncodeCaptureOperationOutcome(r)
	default:
		return nil, artifact.ErrInvalid
	}
}
func captureEnvelope(e authorityEnvelope) ([]byte, error) {
	// Qualified opaque wrap strings remain bounded text. Reject control bytes
	// whose JSON escaping could exceed the existing two-object ciphertext budget.
	if !identity.Text(e.Key.Reference, 256) || !identity.Text(e.Key.Ciphertext, 8192) {
		return nil, artifact.ErrInvalid
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(e) != nil {
		return nil, artifact.ErrInvalid
	}
	raw := b.Bytes()
	if len(raw)-1 > audit.OperationCipherLimit {
		clear(raw)
		return nil, artifact.ErrLimit
	}
	return bytes.Clone(raw[:len(raw)-1]), nil
}
func sealCaptureOperation(ctx context.Context, keys evidence.KeySealer, format, root, id string, record any) ([]byte, error) {
	plain, e := captureOperationPlain(record)
	if e != nil {
		return nil, e
	}
	defer clear(plain)
	ad := controlAuditAAD(format, root, id, plain)
	a, key, e := newKey(ctx, keys, ad)
	if e != nil {
		return nil, e
	}
	cipher, e := encrypt(a, plain, ad)
	if e != nil {
		return nil, e
	}
	if captureReasonFormat(format) {
		return captureReasonOuterEnvelope(captureReasonOuter{format, []byte(key.Reference), []byte(key.Ciphertext), cipher})
	}
	return captureEnvelope(authorityEnvelope{format, key, cipher})
}
func verifyCaptureOperation(ctx context.Context, keys evidence.KeyOpener, format, root, id string, record any, encoded []byte, maxPlain int) error {
	if len(encoded) == 0 || len(encoded) > audit.OperationCipherLimit {
		return artifact.ErrLimit
	}
	canonical := jsontext.Value(bytes.Clone(encoded))
	if canonical.Canonicalize() != nil {
		return artifact.ErrIntegrity
	}
	if captureReasonFormat(format) {
		return verifyCaptureReasonOperation(ctx, keys, format, root, id, record, canonical, maxPlain)
	}
	var envelope authorityEnvelope
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || envelope.Format != format || len(envelope.Ciphertext) == 0 || len(envelope.Ciphertext) > maxPlain+4096 {
		return artifact.ErrIntegrity
	}
	raw, e := captureEnvelope(envelope)
	if e != nil {
		return e
	}
	other := jsontext.Value(raw)
	if other.Canonicalize() != nil || !bytes.Equal(canonical, other) {
		return artifact.ErrIntegrity
	}
	expected, e := captureOperationPlain(record)
	if e != nil {
		return e
	}
	defer clear(expected)
	ad := controlAuditAAD(format, root, id, expected)
	a, e := openKey(ctx, keys, envelope.Key, ad)
	if e != nil {
		return e
	}
	plain, e := decrypt(a, envelope.Ciphertext, ad, int64(maxPlain))
	if e != nil {
		return e
	}
	defer clear(plain)
	if !bytes.Equal(plain, expected) {
		return artifact.ErrIntegrity
	}
	return nil
}

// Only the new reason formats use opaque byte keys; legacy JSON stays exact.
type captureReasonOuter struct {
	Format       string `json:"format"`
	KeyReference []byte `json:"keyReference"`
	WrappedKey   []byte `json:"wrappedKey"`
	Ciphertext   []byte `json:"ciphertext"`
}

func captureReasonFormat(f string) bool {
	return f == "asservat-capture-reason-intent/v1" || f == "asservat-capture-reason-outcome/v1"
}
func captureReasonOuterEnvelope(e captureReasonOuter) ([]byte, error) {
	if !captureReasonFormat(e.Format) || len(e.KeyReference) == 0 || len(e.KeyReference) > 256 || len(e.WrappedKey) == 0 || len(e.WrappedKey) > 8192 || len(e.Ciphertext) == 0 || len(e.Ciphertext) > audit.CaptureReasonPlainLimit+4096 {
		return nil, artifact.ErrInvalid
	}
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > audit.OperationCipherLimit {
		return nil, artifact.ErrLimit
	}
	return raw, nil
}
func verifyCaptureReasonOperation(ctx context.Context, keys evidence.KeyOpener, format, root, id string, record any, canonical []byte, maxPlain int) error {
	var e captureReasonOuter
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || e.Format != format {
		return artifact.ErrIntegrity
	}
	raw, err := captureReasonOuterEnvelope(e)
	if err != nil {
		return err
	}
	other := jsontext.Value(raw)
	if other.Canonicalize() != nil || !bytes.Equal(other, canonical) {
		return artifact.ErrIntegrity
	}
	expected, err := captureOperationPlain(record)
	if err != nil {
		return err
	}
	defer clear(expected)
	ad := controlAuditAAD(format, root, id, expected)
	a, err := openKey(ctx, keys, artifact.SealedKey{Reference: string(e.KeyReference), Ciphertext: string(e.WrappedKey)}, ad)
	if err != nil {
		return err
	}
	plain, err := decrypt(a, e.Ciphertext, ad, int64(maxPlain))
	if err != nil {
		return err
	}
	defer clear(plain)
	if !bytes.Equal(plain, expected) {
		return artifact.ErrIntegrity
	}
	return nil
}
