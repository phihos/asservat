package kms

import (
	"context"
	"io"

	app "asservat.local/asservat/internal/application/authorization"
	value "asservat.local/asservat/internal/domain/authorization"
)

// LocalOperations is the private-key holder behind the authenticated service,
// not an alternative client implementation for a collector or hub process.
type LocalOperations struct {
	scope value.KeyScope
	keys  *LocalKeyBackend
}

var _ app.KeyOperationBackend = (*LocalOperations)(nil)

func NewLocalOperations(scope value.KeyScope, secret io.Reader) (*LocalOperations, error) {
	if !scope.Valid() {
		return nil, ErrKeyService
	}
	keys, err := NewLocalKeyBackend(LocalKeyScope{scope.InstallationID, scope.Purpose, scope.KeyID}, secret)
	if err != nil {
		return nil, err
	}
	return &LocalOperations{scope: scope, keys: keys}, nil
}

func (s *LocalOperations) Execute(ctx context.Context, r value.KeyRequest) (value.KeyResult, error) {
	var result value.KeyResult
	if s == nil || ctx == nil || ctx.Err() != nil || r.Scope != s.scope || !r.Valid() {
		return result, ErrKeyService
	}
	var err error
	switch r.Operation {
	case "wrap":
		result.Sealed, err = s.keys.Seal(ctx, r.Input, r.Binding)
	case "unwrap":
		result.Output, err = s.keys.Open(ctx, r.Sealed, r.Binding)
	default:
		err = ErrKeyService
	}
	return result, err
}
