package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"
	"time"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// ProtectedLocalOperations never changes the loaded crypto maps. Loading a new
// accepted snapshot creates a new instance; an old instance fails its guard.
type ProtectedLocalOperations struct {
	source   app.KeyMaterialReader
	ledger   app.KeyConfigurationLedger
	scope    value.KeyScope
	snapshot value.LocalKeyConfiguration
	backend  *LocalOperations
	now      func() time.Time
}

var _ app.KeyOperationBackend = (*ProtectedLocalOperations)(nil)
var _ app.KeyConfigurationGuard = (*ProtectedLocalOperations)(nil)

func describeLocalMaterial(m app.KeyMaterial, scope value.KeyScope, now time.Time) (value.LocalKeyConfiguration, error) {
	c := m.Configuration
	if c.Scope != scope || artifact.Digest(sha256.Sum256(m.Payload)) != c.SecretDigest {
		return c, ErrKeyService
	}
	k, err := readLocalKeys(LocalKeyScope{scope.InstallationID, scope.Purpose, scope.KeyID}, bytes.NewReader(m.Payload))
	if err != nil {
		return c, err
	}
	defer k.clear()
	c.ActiveVersion = k.ActiveVersion
	c.Versions = nil
	for _, v := range k.Keys {
		c.Versions = append(c.Versions, value.LocalKeyVersion{Version: v.Version, Fingerprint: artifact.Digest(sha256.Sum256(v.Material))})
	}
	slices.SortFunc(c.Versions, func(a, b value.LocalKeyVersion) int { return a.Version - b.Version })
	if !c.Valid(now) {
		return c, ErrKeyService
	}
	return c, nil
}
func LoadProtectedLocalOperations(ctx context.Context, scope value.KeyScope, source app.KeyMaterialReader, ledger app.KeyConfigurationLedger, now func() time.Time) (*ProtectedLocalOperations, error) {
	if ctx == nil || !scope.Valid() || source == nil || ledger == nil || now == nil {
		return nil, ErrKeyService
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	m, err := source.ReadKeyMaterial(ctx)
	defer clear(m.Payload)
	if err != nil {
		return nil, ErrKeyService
	}
	c, err := describeLocalMaterial(m, scope, now())
	if err != nil {
		return nil, err
	}
	until, err := ledger.ObserveLocalKeys(ctx, c)
	if err != nil || ctx.Err() != nil || c.Suspended || !c.Valid(now()) || !now().Before(until) || until.After(c.FreshUntil) {
		return nil, ErrKeyService
	}
	backend, err := NewLocalOperations(scope, bytes.NewReader(m.Payload))
	if err != nil {
		return nil, err
	}
	return &ProtectedLocalOperations{source: source, ledger: ledger, scope: scope, snapshot: c, backend: backend, now: now}, nil
}
func (s *ProtectedLocalOperations) CurrentKeyConfiguration(ctx context.Context, scope value.KeyScope, epoch string) (time.Time, error) {
	if s == nil || s.source == nil || s.ledger == nil || s.now == nil || ctx == nil || ctx.Err() != nil || scope != s.scope || epoch != s.snapshot.RecoveryEpoch {
		return time.Time{}, providerStep("scope", ErrKeyService)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	m, err := s.source.ReadKeyMaterial(ctx)
	defer clear(m.Payload)
	if err != nil {
		return time.Time{}, providerStep("source", ErrKeyService)
	}
	c, err := describeLocalMaterial(m, scope, s.now())
	if err != nil {
		return time.Time{}, providerStep("material", ErrKeyService)
	}
	until, err := s.ledger.ObserveLocalKeys(ctx, c)
	if err != nil {
		return time.Time{}, providerStep("ledger", ErrKeyService)
	}
	if c.Suspended || !c.SameSnapshot(s.snapshot) {
		return time.Time{}, providerStep("rotation", ErrKeyService)
	}
	now := s.now()
	if ctx.Err() != nil || !c.Valid(now) || !now.Before(until) || until.After(c.FreshUntil) {
		return time.Time{}, providerStep("deadline", ErrKeyService)
	}
	return until, nil
}
func (s *ProtectedLocalOperations) Execute(ctx context.Context, r value.KeyRequest) (value.KeyResult, error) {
	if s == nil || s.backend == nil {
		return value.KeyResult{}, ErrKeyService
	}
	// KeyService is responsible for invoking this instance's mandatory guard
	// before and after crypto, with the operation permit's recovery epoch.
	return s.backend.Execute(ctx, r)
}
