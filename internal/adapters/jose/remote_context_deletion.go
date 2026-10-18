package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"time"

	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// RemoteContextDeletionSignatures produces exactly the detached JWS of
// ContextDeletionSignatures while the private key stays in the key provider
// (ADR-205 decision 6). Each signature is checked against the pinned public
// key and the in-process verifier before it is returned. It does not claim
// or repeat SQL work.
type RemoteContextDeletionSignatures struct {
	root, keyID string
	public      ed25519.PublicKey
	signer      func(context.Context) crypto.Signer
	verifier    *ContextDeletionSignatures
}

var _ app.ContextDeletionSigner = (*RemoteContextDeletionSignatures)(nil)
var _ app.ContextDeletionVerifier = (*RemoteContextDeletionSignatures)(nil)

func NewRemoteContextDeletionSignatures(root, keyID string, public map[string]ed25519.PublicKey, signer func(context.Context) crypto.Signer) (*RemoteContextDeletionSignatures, error) {
	if signer == nil || !identity.Text(keyID, 128) || len(public[keyID]) != ed25519.PublicKeySize {
		return nil, value.ErrInvalid
	}
	verify, err := NewContextDeletionSignatures(root, "", nil, public)
	if err != nil {
		return nil, err
	}
	return &RemoteContextDeletionSignatures{root: root, keyID: keyID, public: bytes.Clone(public[keyID]), signer: signer, verifier: verify}, nil
}

// SignContextDeletion makes one provider request within five seconds of the
// caller's original deadline; an unknown outcome is not retried here.
func (s *RemoteContextDeletionSignatures) SignContextDeletion(ctx context.Context, r value.ContextDeletionCheckpoint) ([]byte, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.root != r.RootID {
		return nil, value.ErrUnavailable
	}
	payload, err := contextDeletionPayload(r)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	live, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	handle := s.signer(live)
	if handle == nil || live.Err() != nil {
		return nil, value.ErrUnavailable
	}
	key, ok := handle.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(key, s.public) {
		return nil, value.ErrUnavailable
	}
	h := jws.NewHeaders()
	_ = h.Set(jws.TypeKey, ContextDeletionType)
	_ = h.Set(jws.KeyIDKey, s.keyID)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), handle, jws.WithProtectedHeaders(h)))
	defer clear(signed)
	if err != nil || live.Err() != nil {
		return nil, value.ErrUnavailable
	}
	parts := bytes.Split(signed, []byte("."))
	if len(parts) != 3 {
		return nil, value.ErrUnavailable
	}
	// Standard detached compact JWS: the encrypted record supplies the payload.
	detached := append(append(bytes.Clone(parts[0]), '.', '.'), parts[2]...)
	if err = s.verifier.VerifyContextDeletion(live, r, detached); err != nil || live.Err() != nil {
		clear(detached)
		return nil, value.ErrUnavailable
	}
	return detached, nil
}

// VerifyContextDeletion is the in-process verifier over the same pinned keys.
func (s *RemoteContextDeletionSignatures) VerifyContextDeletion(ctx context.Context, r value.ContextDeletionCheckpoint, detached []byte) error {
	if s == nil || ctx == nil {
		return value.ErrUnavailable
	}
	return s.verifier.VerifyContextDeletion(ctx, r, detached)
}
