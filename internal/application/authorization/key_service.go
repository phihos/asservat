package authorization

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

var ErrKeyDenied = errors.New("key operation denied")
var ErrKeyUnavailable = errors.New("key operation unavailable")

type KeyOperationAuthorizer interface {
	// Resolve must consult current accepted authority, recovery, original
	// operation deadlines and exact artifact/session/signature scope. It must
	// never turn a role, certificate or caller-supplied UUID into a grant.
	Resolve(context.Context, value.KeyPeer, value.KeyRequestInfo) (value.KeyOperationPermit, error)
}

type KeyOperationBackend interface {
	Execute(context.Context, value.KeyRequest) (value.KeyResult, error)
}

type KeyService struct {
	Scope     value.KeyScope
	Authority KeyOperationAuthorizer
	Backend   KeyOperationBackend
	Now       func() time.Time
}

// DescribeKeyRequest is a versioned canonical digest over all fields, with
// hashes replacing secret bytes. It is shared by callers and service checks;
// it supplies request identity, never authority.
func DescribeKeyRequest(r value.KeyRequest) (value.KeyRequestInfo, error) {
	if !r.Valid() {
		return value.KeyRequestInfo{}, ErrKeyDenied
	}
	input := artifact.Digest(sha256.Sum256(r.Input))
	b, err := json.Marshal(struct {
		Format, Installation, Purpose, KeyID, Authority, Operation, Reference string
		Version                                                               int
		Binding, Input, Ciphertext                                            artifact.Digest
	}{"asservat-key-request-digest/v1", r.Scope.InstallationID, r.Scope.Purpose, r.Scope.KeyID, r.AuthorityID, r.Operation, r.Sealed.Reference, r.Version, artifact.Digest(sha256.Sum256(r.Binding)), input, artifact.Digest(sha256.Sum256([]byte(r.Sealed.Ciphertext)))})
	canonical := jsontext.Value(b)
	if err != nil || canonical.Canonicalize() != nil {
		return value.KeyRequestInfo{}, ErrKeyUnavailable
	}
	return value.KeyRequestInfo{Scope: r.Scope, AuthorityID: r.AuthorityID, Operation: r.Operation, Reference: r.Sealed.Reference, Version: r.Version, Binding: bytes.Clone(r.Binding), InputDigest: input, RequestDigest: artifact.Digest(sha256.Sum256(canonical))}, nil
}

func (s KeyService) Execute(ctx context.Context, peer value.KeyPeer, request value.KeyRequest) (value.KeyResult, error) {
	if ctx == nil || s.Now == nil || s.Authority == nil || s.Backend == nil || !s.Scope.Valid() {
		return value.KeyResult{}, ErrKeyUnavailable
	}
	configuration, ok := s.Backend.(KeyConfigurationGuard)
	if !ok {
		return value.KeyResult{}, ErrKeyUnavailable
	}
	if ctx.Err() != nil || request.Scope != s.Scope || !peer.Valid(s.Now()) || !peer.CanRequest(request.Scope, request.Operation) {
		return value.KeyResult{}, ErrKeyDenied
	}
	// Own buffers across blocking authority I/O. A resolver receives no keyset
	// and cannot mutate the eventual cryptographic request through its binding.
	request.Binding, request.Input = bytes.Clone(request.Binding), bytes.Clone(request.Input)
	defer clear(request.Binding)
	defer clear(request.Input)
	info, err := DescribeKeyRequest(request)
	if err != nil {
		return value.KeyResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	observation := info
	observation.Binding = bytes.Clone(info.Binding)
	permit, err := s.Authority.Resolve(ctx, peer, observation)
	if err != nil || ctx.Err() != nil || !permit.Valid(peer, info, s.Now()) {
		return value.KeyResult{}, ErrKeyDenied
	}
	effect, end := context.WithDeadline(ctx, permit.ValidUntil)
	defer end()
	keyUntil, err := configuration.CurrentKeyConfiguration(effect, s.Scope, permit.RecoveryEpoch)
	if err != nil || effect.Err() != nil || !s.Now().Before(keyUntil) || keyUntil.After(s.Now().Add(5*time.Second)) || !permit.Valid(peer, info, s.Now()) {
		return value.KeyResult{}, ErrKeyUnavailable
	}
	effect, stopKeys := context.WithDeadline(effect, keyUntil)
	defer stopKeys()
	result, err := s.Backend.Execute(effect, request)
	if err != nil || effect.Err() != nil || !permit.Valid(peer, info, s.Now()) || !result.Valid(request.Operation) {
		clear(result.Output)
		return value.KeyResult{}, ErrKeyUnavailable
	}
	currentUntil, err := configuration.CurrentKeyConfiguration(effect, s.Scope, permit.RecoveryEpoch)
	if err != nil || effect.Err() != nil || !s.Now().Before(currentUntil) || currentUntil.After(s.Now().Add(5*time.Second)) || !s.Now().Before(keyUntil) || !permit.Valid(peer, info, s.Now()) {
		clear(result.Output)
		return value.KeyResult{}, ErrKeyUnavailable
	}
	result.RequestDigest = info.RequestDigest
	result.ValidUntil, _ = effect.Deadline()
	if currentUntil.Before(result.ValidUntil) {
		result.ValidUntil = currentUntil
	}
	return result, nil
}

// KeyOperationAuthorizers dispatches one key-service scope's authority by
// "operation/role" first, then by operation (ADR-176/181): artifact wraps,
// verification unwraps and download unwraps have separate authorities. An
// operation without an authority is denied; there is no other fallback.
type KeyOperationAuthorizers map[string]KeyOperationAuthorizer

func (a KeyOperationAuthorizers) Resolve(ctx context.Context, peer value.KeyPeer, r value.KeyRequestInfo) (value.KeyOperationPermit, error) {
	authority, ok := a[r.Operation+"/"+peer.Role]
	if !ok {
		authority, ok = a[r.Operation]
	}
	if !ok || authority == nil {
		return value.KeyOperationPermit{}, ErrKeyDenied
	}
	return authority.Resolve(ctx, peer, r)
}
