package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
)

const downloadStopRetirementFormat = "asservat-download-stop-retirement/v1"

type signedDownloadStopRetirement struct {
	Format    string
	Signature []byte
	Encrypted []byte
}

func SealDownloadStopRetirement(ctx context.Context, keys evidence.KeySealer, signer app.DownloadStopRetirementSigner, r value.DownloadStopRetirement) ([]byte, error) {
	if keys == nil || signer == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	sig, err := signer.SignDownloadStopRetirement(ctx, r)
	if err != nil {
		return nil, err
	}
	if len(sig) < 1 || len(sig) > 2048 {
		return nil, artifact.ErrInvalid
	}
	encrypted, err := sealControlAudit(ctx, keys, downloadStopRetirementFormat, r.RootID, r.DownloadID, r, 8<<10)
	if err != nil {
		return nil, err
	}
	return json.Marshal(signedDownloadStopRetirement{downloadStopRetirementFormat, sig, encrypted})
}
func VerifyDownloadStopRetirement(ctx context.Context, keys evidence.KeyOpener, verifier app.DownloadStopRetirementVerifier, r value.DownloadStopRetirement, encoded []byte) error {
	if keys == nil || verifier == nil || !r.Valid() || len(encoded) < 1 || len(encoded) > 64<<10 {
		return artifact.ErrInvalid
	}
	canonical := jsontext.Value(bytes.Clone(encoded))
	if canonical.Canonicalize() != nil {
		return artifact.ErrIntegrity
	}
	var v signedDownloadStopRetirement
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || v.Format != downloadStopRetirementFormat || len(v.Signature) < 1 || len(v.Signature) > 2048 || len(v.Encrypted) < 1 || len(v.Encrypted) > 64<<10 {
		return artifact.ErrIntegrity
	}
	expected, _ := json.Marshal(v)
	c := jsontext.Value(expected)
	if c.Canonicalize() != nil || !bytes.Equal(c, canonical) {
		return artifact.ErrIntegrity
	}
	if err := verifier.VerifyDownloadStopRetirement(ctx, r, v.Signature); err != nil {
		return artifact.ErrIntegrity
	}
	return verifyControlAudit(ctx, keys, downloadStopRetirementFormat, r.RootID, r.DownloadID, r, v.Encrypted, 8<<10)
}
