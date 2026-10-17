package framed

import (
	"context"
	"encoding/json/jsontext"
	"sync/atomic"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const manifestType = "application/vnd.asservat.manifest+json"

type ManifestWriter struct {
	binding artifact.Binding
	key     tink.StreamingAEAD
	sealed  artifact.SealedKey
	used    atomic.Bool
}

// PrepareManifest is called before acquisition alongside Prepare. The caller
// validates the full manifest schema/provenance; this wrapper validates bounded
// JSON and supplies an independent key, fixed-purpose AAD and complete stream.
func PrepareManifest(ctx context.Context, b artifact.Binding, s evidence.KeySealer) (*ManifestWriter, error) {
	if b.Validate() != nil || s == nil {
		return nil, artifact.ErrInvalid
	}
	b.MediaType = manifestType
	k, sealed, err := newKey(ctx, s, aad(b, "manifest-key", 0, 0, 0, "none"))
	if err != nil {
		return nil, err
	}
	return &ManifestWriter{binding: b, key: k, sealed: sealed}, nil
}

func (w *ManifestWriter) Seal(ctx context.Context, manifest []byte) ([]byte, artifact.SealedKey, error) {
	if len(manifest) < 1 || int64(len(manifest)) > artifact.MaxRootBytes || !w.used.CompareAndSwap(false, true) {
		return nil, artifact.SealedKey{}, artifact.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, artifact.SealedKey{}, err
	}
	v := jsontext.Value(append([]byte(nil), manifest...))
	defer clear(v)
	if v.Canonicalize() != nil {
		return nil, artifact.SealedKey{}, artifact.ErrInvalid
	}
	// Preserve supplied JSON bytes; canonical JSON is required only for AAD.
	c, err := encrypt(w.key, manifest, aad(w.binding, "manifest", 0, 0, 0, "json"))
	if err != nil {
		return nil, artifact.SealedKey{}, err
	}
	if int64(len(c)) > artifact.MaxRootBytes+artifact.CipherOverhead {
		return nil, artifact.SealedKey{}, artifact.ErrLimit
	}
	return c, w.sealed, nil
}

func OpenManifest(ctx context.Context, b artifact.Binding, keys evidence.KeyOpener, key artifact.SealedKey, cipher []byte, expected artifact.Digest) ([]byte, error) {
	if b.Validate() != nil || keys == nil || len(cipher) < 1 || int64(len(cipher)) > artifact.MaxRootBytes+artifact.CipherOverhead || digest(cipher) != expected {
		return nil, artifact.ErrIntegrity
	}
	b.MediaType = manifestType
	k, err := openKey(ctx, keys, key, aad(b, "manifest-key", 0, 0, 0, "none"))
	if err != nil {
		return nil, err
	}
	v, err := decrypt(k, cipher, aad(b, "manifest", 0, 0, 0, "json"), artifact.MaxRootBytes)
	if err != nil {
		return nil, err
	}
	canonical := jsontext.Value(append([]byte(nil), v...))
	defer clear(canonical)
	if canonical.Canonicalize() != nil {
		clear(v)
		return nil, artifact.ErrIntegrity
	}
	return v, nil
}
