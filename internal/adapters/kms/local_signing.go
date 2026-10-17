package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"io"
)

// LocalSigningKey is the key-service-side implementation. The private seed must
// remain in that role; application callers need a scoped remote signer, not this
// type. The expected public key comes from independently protected signing trust.
type LocalSigningKey struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func NewLocalSigningKey(scope LocalKeyScope, version int, public ed25519.PublicKey, secret io.Reader) (*LocalSigningKey, error) {
	if scope.Purpose != "policy-submission" || version < 1 || version > 2147483647 || len(public) != ed25519.PublicKeySize {
		return nil, ErrKeyService
	}
	s, err := readLocalKeys(scope, secret)
	if err != nil {
		return nil, err
	}
	defer s.clear()
	// Old versions are retained for recovery/verification, not new signatures.
	if s.ActiveVersion != version {
		return nil, ErrKeyService
	}
	for _, k := range s.Keys {
		if k.Version != version {
			continue
		}
		private := ed25519.NewKeyFromSeed(k.Material)
		derived := private.Public().(ed25519.PublicKey)
		if !bytes.Equal(derived, public) {
			clear(private)
			return nil, ErrKeyService
		}
		return &LocalSigningKey{private: private, public: bytes.Clone(public)}, nil
	}
	return nil, ErrKeyService
}

func (s *LocalSigningKey) ForContext(ctx context.Context) crypto.Signer {
	if s == nil || ctx == nil {
		return nil
	}
	return &localRequestSigner{s, ctx}
}

type localRequestSigner struct {
	key *LocalSigningKey
	ctx context.Context
}

var _ crypto.Signer = (*localRequestSigner)(nil)

func (s *localRequestSigner) Public() crypto.PublicKey {
	return ed25519.PublicKey(bytes.Clone(s.key.public))
}

func (s *localRequestSigner) Sign(_ io.Reader, input []byte, options crypto.SignerOpts) ([]byte, error) {
	if s.key == nil || s.ctx == nil || s.ctx.Err() != nil || !plainEd25519Options(options) || len(input) < 1 || len(input) > 16384 {
		return nil, ErrKeyService
	}
	sig := ed25519.Sign(s.key.private, input)
	if s.ctx.Err() != nil {
		clear(sig)
		return nil, ErrKeyService
	}
	return sig, nil
}
