package kms

import (
	"bytes"
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// BrowserCipher uses a separate configured key provider from evidence.
// SQL stores only an authenticated envelope; access/refresh/PKCE values remain
// encrypted. Binding includes installation epoch, issuer, client, row and version.
type BrowserCipher struct {
	Sealer evidence.KeySealer
	Opener evidence.KeyOpener
}

var _ app.CredentialCipher = BrowserCipher{}

type browserEnvelope struct {
	Format     string
	Key        artifact.SealedKey
	Ciphertext []byte
}

func (c BrowserCipher) Encrypt(ctx context.Context, b, ad []byte) ([]byte, error) {
	if c.Sealer == nil || len(b) == 0 || len(b) > 128<<10 || len(ad) == 0 || len(ad) > 2048 {
		return nil, identity.ErrInvalid
	}
	h, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, identity.ErrUnavailable
	}
	var raw bytes.Buffer
	if insecurecleartextkeyset.Write(h, keyset.NewBinaryWriter(&raw)) != nil {
		return nil, identity.ErrUnavailable
	}
	defer clear(raw.Bytes())
	k, err := c.Sealer.Seal(ctx, raw.Bytes(), ad)
	if err != nil {
		return nil, identity.ErrUnavailable
	}
	a, err := aead.New(h)
	if err != nil {
		return nil, identity.ErrUnavailable
	}
	sealed, err := a.Encrypt(b, ad)
	if err != nil {
		return nil, identity.ErrUnavailable
	}
	return json.Marshal(browserEnvelope{"asservat-browser-credentials/v1", k, sealed})
}
func (c BrowserCipher) Decrypt(ctx context.Context, b, ad []byte) ([]byte, error) {
	if c.Opener == nil || len(b) == 0 || len(b) > identity.MaxSessionCiphertext || len(ad) == 0 || len(ad) > 2048 {
		return nil, identity.ErrInvalid
	}
	var envelope browserEnvelope
	if json.Unmarshal(b, &envelope) != nil || envelope.Format != "asservat-browser-credentials/v1" || len(envelope.Ciphertext) == 0 || len(envelope.Ciphertext) > (128<<10)+64 {
		return nil, identity.ErrDenied
	}
	raw, err := c.Opener.Open(ctx, envelope.Key, ad)
	if err != nil {
		return nil, identity.ErrUnavailable
	}
	defer clear(raw)
	h, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, identity.ErrDenied
	}
	a, err := aead.New(h)
	if err != nil {
		return nil, identity.ErrDenied
	}
	plain, err := a.Decrypt(envelope.Ciphertext, ad)
	if err != nil {
		return nil, identity.ErrDenied
	}
	return plain, nil
}
