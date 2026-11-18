package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// ProtectedLocalOperations selects an immutable backend for each operation.
// Rotation replaces the generation after the ledger accepts the mounted keys.
type ProtectedLocalOperations struct {
	source   app.KeyMaterialReader
	ledger   app.KeyConfigurationLedger
	scope    value.KeyScope
	epoch    string
	mu       sync.Mutex
	snapshot value.LocalKeyConfiguration
	keys     *app.KeyGeneration
	now      func() time.Time
}

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
func LoadProtectedLocalOperations(ctx context.Context, scope value.KeyScope, epoch string, source app.KeyMaterialReader, ledger app.KeyConfigurationLedger, now func() time.Time) (*ProtectedLocalOperations, error) {
	if !scope.Valid() || !value.UUID(epoch) {
		return nil, ErrKeyService
	}
	s := &ProtectedLocalOperations{source: source, ledger: ledger, scope: scope, epoch: epoch, now: now}
	if _, _, err := s.CurrentKeyConfiguration(ctx, scope, epoch); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ProtectedLocalOperations) CurrentKeyConfiguration(ctx context.Context, scope value.KeyScope, epoch string) (*app.KeyGeneration, time.Time, error) {
	if s == nil || s.source == nil || s.ledger == nil || s.now == nil || ctx == nil || ctx.Err() != nil || scope != s.scope || epoch != s.epoch {
		return nil, time.Time{}, providerStep("scope", ErrKeyService)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	m, err := s.source.ReadKeyMaterial(ctx)
	defer clear(m.Payload)
	if err != nil {
		return nil, time.Time{}, providerStep("source", ErrKeyService)
	}
	c, err := describeLocalMaterial(m, scope, s.now())
	if err != nil {
		return nil, time.Time{}, providerStep("material", ErrKeyService)
	}
	if c.RecoveryEpoch != epoch {
		return nil, time.Time{}, providerStep("scope", ErrKeyService)
	}
	until, err := s.ledger.ObserveLocalKeys(ctx, c)
	if err != nil {
		return nil, time.Time{}, providerStep("ledger", ErrKeyService)
	}
	if c.Suspended {
		return nil, time.Time{}, providerStep("rotation", ErrKeyService)
	}
	now := s.now()
	if ctx.Err() != nil || !c.Valid(now) || !now.Before(until) || until.After(c.FreshUntil) {
		return nil, time.Time{}, providerStep("deadline", ErrKeyService)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !c.SameSnapshot(s.snapshot) {
		// Another operation may already have installed a later ledger observation.
		if c.Revision.Generation <= s.snapshot.Revision.Generation {
			return nil, time.Time{}, providerStep("rotation", ErrKeyService)
		}
		backend, err := NewLocalOperations(scope, bytes.NewReader(m.Payload))
		if err != nil {
			return nil, time.Time{}, providerStep("material", ErrKeyService)
		}
		s.keys = &app.KeyGeneration{Operations: backend}
		s.snapshot = c
	}
	return s.keys, until, nil
}
