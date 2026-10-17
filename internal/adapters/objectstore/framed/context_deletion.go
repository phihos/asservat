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

const contextDeletionFormat = "asservat-context-deletion/v1"

type signedContextDeletion struct {
	Format    string
	Signature []byte
	Encrypted []byte
}

func SealContextDeletion(ctx context.Context, keys evidence.KeySealer, signer app.ContextDeletionSigner, r value.ContextDeletionCheckpoint) ([]byte, error) {
	if keys == nil || signer == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	sig, err := signer.SignContextDeletion(ctx, r)
	if err != nil {
		return nil, err
	}
	if len(sig) < 1 || len(sig) > 2048 {
		return nil, artifact.ErrInvalid
	}
	encrypted, err := sealControlAudit(ctx, keys, contextDeletionFormat, r.RootID, r.Location.AttemptID, r, 32<<10)
	if err != nil {
		return nil, err
	}
	return json.Marshal(signedContextDeletion{contextDeletionFormat, sig, encrypted})
}
func VerifyContextDeletion(ctx context.Context, keys evidence.KeyOpener, verifier app.ContextDeletionVerifier, r value.ContextDeletionCheckpoint, encoded []byte) error {
	if keys == nil || verifier == nil || !r.Valid() || len(encoded) < 1 || len(encoded) > 128<<10 {
		return artifact.ErrInvalid
	}
	canonical := jsontext.Value(bytes.Clone(encoded))
	if canonical.Canonicalize() != nil {
		return artifact.ErrIntegrity
	}
	var v signedContextDeletion
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || v.Format != contextDeletionFormat || len(v.Signature) < 1 || len(v.Signature) > 2048 || len(v.Encrypted) < 1 || len(v.Encrypted) > 64<<10 {
		return artifact.ErrIntegrity
	}
	expected, _ := json.Marshal(v)
	c := jsontext.Value(expected)
	if c.Canonicalize() != nil || !bytes.Equal(c, canonical) {
		return artifact.ErrIntegrity
	}
	if err := verifier.VerifyContextDeletion(ctx, r, v.Signature); err != nil {
		return artifact.ErrIntegrity
	}
	return verifyControlAudit(ctx, keys, contextDeletionFormat, r.RootID, r.Location.AttemptID, r, v.Encrypted, 32<<10)
}
