package framed

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

const auditFormat = "asservat-authority-audit/v1"

type authorityEnvelope struct {
	Format     string             `json:"format"`
	Key        artifact.SealedKey `json:"key"`
	Ciphertext []byte             `json:"ciphertext"`
}

func controlAuditAAD(format, root, event string, plain []byte) []byte {
	b, _ := json.Marshal(struct {
		Format, RootID, EventID string
		Digest                  artifact.Digest
	}{format, root, event, digest(plain)})
	return b
}

// SealAuthority uses a separate format, binding and KMS role from artifact
// encryption. It accepts minimized control records, never arbitrary evidence.
func SealAuthority(ctx context.Context, keys evidence.KeySealer, r audit.AuthorityRecord) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, auditFormat, r.RootID, r.ID, r, 8<<20)
}

func sealControlAudit(ctx context.Context, keys evidence.KeySealer, format, root, event string, record any, maxPlain int) ([]byte, error) {
	plain, err := json.Marshal(record)
	if err != nil || len(plain) > maxPlain {
		return nil, artifact.ErrLimit
	}
	defer clear(plain)
	ad := controlAuditAAD(format, root, event, plain)
	a, key, err := newKey(ctx, keys, ad)
	if err != nil {
		return nil, err
	}
	if len(key.Reference) == 0 || len(key.Reference) > 256 || len(key.Ciphertext) == 0 || len(key.Ciphertext) > 8192 {
		return nil, artifact.ErrInvalid
	}
	cipher, err := encrypt(a, plain, ad)
	if err != nil {
		return nil, err
	}
	return json.Marshal(authorityEnvelope{format, key, cipher})
}

// VerifyAuthority authenticates the complete encrypted record against the frozen
// SQL outbox value. No ETag, HEAD response or unverified plaintext is sufficient.
func VerifyAuthority(ctx context.Context, keys evidence.KeyOpener, r audit.AuthorityRecord, encoded []byte) error {
	if keys == nil || !r.Valid() || len(encoded) == 0 || len(encoded) > 16<<20 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, auditFormat, r.RootID, r.ID, r, encoded, 8<<20)
}

func verifyControlAudit(ctx context.Context, keys evidence.KeyOpener, format, root, event string, record any, encoded []byte, maxPlain int) error {
	c := jsontext.Value(bytes.Clone(encoded))
	if c.Canonicalize() != nil {
		return artifact.ErrIntegrity
	}
	var e authorityEnvelope
	d := json.NewDecoder(bytes.NewReader(c))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || e.Format != format || len(e.Ciphertext) == 0 || len(e.Ciphertext) > maxPlain+4096 {
		return artifact.ErrIntegrity
	}
	canonical, _ := json.Marshal(e)
	other := jsontext.Value(canonical)
	if other.Canonicalize() != nil || !bytes.Equal(c, other) {
		return artifact.ErrIntegrity
	}
	if len(e.Key.Reference) == 0 || len(e.Key.Reference) > 256 || len(e.Key.Ciphertext) == 0 || len(e.Key.Ciphertext) > 8192 {
		return artifact.ErrIntegrity
	}
	expected, err := json.Marshal(record)
	if err != nil || len(expected) > maxPlain {
		return artifact.ErrLimit
	}
	defer clear(expected)
	ad := controlAuditAAD(format, root, event, expected)
	a, err := openKey(ctx, keys, e.Key, ad)
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
