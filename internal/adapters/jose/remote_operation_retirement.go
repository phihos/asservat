package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"time"

	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// RemoteOperationRetirementSignatures preserves the existing detached JWS and
// exact retained certificate interval while keeping private signing material
// inside the configured key provider. It does not claim or repeat SQL work.
type RemoteOperationRetirementSignatures struct {
	root, keyID string
	public      ed25519.PublicKey
	signer      func(context.Context) crypto.Signer
	verifier    *OperationRetirementSignatures
}

var _ app.OperationRetirementSigner = (*RemoteOperationRetirementSignatures)(nil)

func NewRemoteOperationRetirementSignatures(root, keyID string, public map[string]ed25519.PublicKey, signer func(context.Context) crypto.Signer) (*RemoteOperationRetirementSignatures, error) {
	if signer == nil || !identity.Text(keyID, 128) || len(public[keyID]) != ed25519.PublicKeySize {
		return nil, app.ErrUnavailable
	}
	verify, err := NewOperationRetirementSignatures(root, "", nil, public)
	if err != nil {
		return nil, err
	}
	return &RemoteOperationRetirementSignatures{root: root, keyID: keyID, public: bytes.Clone(public[keyID]), signer: signer, verifier: verify}, nil
}

func (s *RemoteOperationRetirementSignatures) SignOperationRetirement(ctx context.Context, record value.OperationRetirement) ([]byte, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.root != record.RootID || !record.Valid() || time.Now().Before(record.PurgedAt) || !time.Now().Before(record.CertificateWriteUntil) {
		return nil, app.ErrUnavailable
	}
	until := identity.Earlier(time.Now().Add(5*time.Second), record.CertificateWriteUntil)
	live, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if live.Err() != nil {
		return nil, app.ErrUnavailable
	}
	payload, err := operationRetirementPayload(record)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	handle := s.signer(live)
	if handle == nil || live.Err() != nil {
		return nil, app.ErrUnavailable
	}
	key, ok := handle.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(key, s.public) {
		return nil, app.ErrUnavailable
	}
	header := jws.NewHeaders()
	_ = header.Set(jws.TypeKey, OperationRetirementType)
	_ = header.Set(jws.KeyIDKey, s.keyID)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), handle, jws.WithProtectedHeaders(header)))
	defer clear(signed)
	if err != nil || live.Err() != nil || !time.Now().Before(until) {
		return nil, app.ErrUnavailable
	}
	parts := bytes.Split(signed, []byte("."))
	if len(parts) != 3 {
		return nil, app.ErrUnavailable
	}
	detached := append(append(bytes.Clone(parts[0]), '.', '.'), parts[2]...)
	if err = s.verifier.VerifyOperationRetirement(live, record, detached); err != nil || live.Err() != nil || !time.Now().Before(until) {
		clear(detached)
		return nil, app.ErrUnavailable
	}
	return detached, nil
}
