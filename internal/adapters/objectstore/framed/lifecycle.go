package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
)

const lifecycleFormat = "asservat-retention-lifecycle/v1"

type signedLifecycle struct {
	Format    string
	Signature []byte
	Encrypted []byte
}

func SealLifecycle(ctx context.Context, keys evidence.KeySealer, signer app.LifecycleSigner, r value.LifecycleDecision) ([]byte, error) {
	if keys == nil || signer == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	sig, err := signer.SignLifecycle(ctx, r)
	if err != nil {
		return nil, err
	}
	if len(sig) < 1 || len(sig) > 2048 {
		return nil, artifact.ErrInvalid
	}
	encrypted, err := sealControlAudit(ctx, keys, lifecycleFormat, r.RootID, r.ID, r, 32<<10)
	if err != nil {
		return nil, err
	}
	return json.Marshal(signedLifecycle{lifecycleFormat, sig, encrypted})
}
func VerifyLifecycle(ctx context.Context, keys evidence.KeyOpener, verifier app.LifecycleVerifier, r value.LifecycleDecision, encoded []byte) error {
	if keys == nil || verifier == nil || !r.Valid() || len(encoded) < 1 || len(encoded) > 128<<10 {
		return artifact.ErrInvalid
	}
	canonical := jsontext.Value(bytes.Clone(encoded))
	if canonical.Canonicalize() != nil {
		return artifact.ErrIntegrity
	}
	var v signedLifecycle
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || v.Format != lifecycleFormat || len(v.Signature) < 1 || len(v.Signature) > 2048 || len(v.Encrypted) < 1 || len(v.Encrypted) > 64<<10 {
		return artifact.ErrIntegrity
	}
	expected, _ := json.Marshal(v)
	c := jsontext.Value(expected)
	if c.Canonicalize() != nil || !bytes.Equal(c, canonical) {
		return artifact.ErrIntegrity
	}
	if err := verifier.VerifyLifecycle(ctx, r, v.Signature); err != nil {
		return artifact.ErrIntegrity
	}
	return verifyControlAudit(ctx, keys, lifecycleFormat, r.RootID, r.ID, r, v.Encrypted, 32<<10)
}
