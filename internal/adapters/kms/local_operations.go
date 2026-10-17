package kms

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"io"

	app "asservat.local/asservat/internal/application/authorization"
	value "asservat.local/asservat/internal/domain/authorization"
)

// LocalOperations is the private-key holder behind the authenticated service,
// not an alternative client implementation for a collector or hub process.
type LocalOperations struct {
	scope   value.KeyScope
	keys    *LocalKeyBackend
	signer  *LocalSigningKey
	version int
}

var _ app.KeyOperationBackend = (*LocalOperations)(nil)

func NewLocalOperations(scope value.KeyScope, version int, public ed25519.PublicKey, secret io.Reader) (*LocalOperations, error) {
	if !scope.Valid() {
		return nil, ErrKeyService
	}
	local := LocalKeyScope{scope.InstallationID, scope.Purpose, scope.KeyID}
	s := &LocalOperations{scope: scope, version: version}
	var err error
	if scope.Purpose == "policy-submission" {
		s.signer, err = NewLocalSigningKey(local, version, public, secret)
	} else {
		if version != 0 || len(public) != 0 {
			return nil, ErrKeyService
		}
		s.keys, err = NewLocalKeyBackend(local, secret)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *LocalOperations) Execute(ctx context.Context, r value.KeyRequest) (value.KeyResult, error) {
	var result value.KeyResult
	if s == nil || ctx == nil || ctx.Err() != nil || r.Scope != s.scope || !r.Valid() {
		return result, ErrKeyService
	}
	var err error
	switch r.Operation {
	case "wrap":
		if s.keys == nil {
			return result, ErrKeyService
		}
		result.Sealed, err = s.keys.Seal(ctx, r.Input, r.Binding)
	case "unwrap":
		if s.keys == nil {
			return result, ErrKeyService
		}
		result.Output, err = s.keys.Open(ctx, r.Sealed, r.Binding)
	case "sign":
		if s.signer == nil || r.Version != s.version {
			return result, ErrKeyService
		}
		result.Output, err = s.signer.ForContext(ctx).Sign(nil, r.Input, crypto.Hash(0))
	default:
		err = ErrKeyService
	}
	return result, err
}
