package kms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"slices"
	"sync"
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
	cacheMu  sync.Mutex
	cached   value.LocalKeyConfiguration
	refresh  chan struct{}
}

var _ app.KeyOperationBackend = (*ProtectedLocalOperations)(nil)
var _ app.KeyConfigurationGuard = (*ProtectedLocalOperations)(nil)

func describeLocalMaterial(m app.KeyMaterial, scope value.KeyScope, now time.Time) (value.LocalKeyConfiguration, int, error) {
	c := m.Configuration
	if c.Scope != scope || artifact.Digest(sha256.Sum256(m.Payload)) != c.SecretDigest {
		return c, 0, ErrKeyService
	}
	k, err := readLocalKeys(LocalKeyScope{scope.InstallationID, scope.Purpose, scope.KeyID}, bytes.NewReader(m.Payload))
	if err != nil {
		return c, 0, err
	}
	defer k.clear()
	c.ActiveVersion = k.ActiveVersion
	c.Versions = nil
	for _, v := range k.Keys {
		c.Versions = append(c.Versions, value.LocalKeyVersion{Version: v.Version, Fingerprint: artifact.Digest(sha256.Sum256(v.Material))})
	}
	slices.SortFunc(c.Versions, func(a, b value.LocalKeyVersion) int { return a.Version - b.Version })
	version := 0
	if scope.Purpose == "policy-submission" {
		version = k.ActiveVersion
		for _, v := range k.Keys {
			if v.Version == version {
				private := ed25519.NewKeyFromSeed(v.Material)
				valid := bytes.Equal(private.Public().(ed25519.PublicKey), m.SigningPublic)
				clear(private)
				if !valid {
					return c, 0, ErrKeyService
				}
			}
		}
	} else if len(m.SigningPublic) != 0 {
		return c, 0, ErrKeyService
	}
	if !c.Valid(now) {
		return c, 0, ErrKeyService
	}
	return c, version, nil
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
	c, version, err := describeLocalMaterial(m, scope, now())
	if err != nil {
		return nil, err
	}
	until, err := ledger.ObserveLocalKeys(ctx, c)
	if err != nil || ctx.Err() != nil || c.Suspended || !c.Valid(now()) || !now().Before(until) || until.After(c.FreshUntil) {
		return nil, ErrKeyService
	}
	backend, err := NewLocalOperations(scope, version, m.SigningPublic, bytes.NewReader(m.Payload))
	if err != nil {
		return nil, err
	}
	return &ProtectedLocalOperations{source: source, ledger: ledger, scope: scope, snapshot: c, backend: backend, now: now, cached: c, refresh: make(chan struct{}, 1)}, nil
}
func (s *ProtectedLocalOperations) CurrentKeyConfiguration(ctx context.Context, scope value.KeyScope, epoch string) (time.Time, error) {
	if s == nil || s.source == nil || s.ledger == nil || s.now == nil || s.refresh == nil || ctx == nil || ctx.Err() != nil || scope != s.scope || epoch != s.snapshot.RecoveryEpoch {
		return time.Time{}, ErrKeyService
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := s.currentSnapshot(ctx)
	if err != nil {
		return time.Time{}, err
	}
	until, err := s.ledger.ObserveLocalKeys(ctx, c)
	if err != nil || ctx.Err() != nil || !c.SameSnapshot(s.snapshot) || c.Suspended || !c.Valid(s.now()) || !s.now().Before(until) || until.After(c.FreshUntil) {
		return time.Time{}, ErrKeyService
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

// Only public fingerprints/observation times are cached. The original source
// expiry never moves on a cache hit. Concurrent refreshes coalesce per scope.
func (s *ProtectedLocalOperations) currentSnapshot(ctx context.Context) (value.LocalKeyConfiguration, error) {
	read := func() (value.LocalKeyConfiguration, bool) {
		s.cacheMu.Lock()
		defer s.cacheMu.Unlock()
		c := s.cached
		c.Versions = append([]value.LocalKeyVersion(nil), c.Versions...)
		return c, c.Valid(s.now())
	}
	if c, ok := read(); ok {
		return c, nil
	}
	select {
	case s.refresh <- struct{}{}:
	case <-ctx.Done():
		return value.LocalKeyConfiguration{}, ErrKeyService
	}
	defer func() { <-s.refresh }()
	if c, ok := read(); ok {
		return c, nil
	}
	m, e := s.source.ReadKeyMaterial(ctx)
	defer clear(m.Payload)
	if e != nil {
		return value.LocalKeyConfiguration{}, ErrKeyService
	}
	c, _, e := describeLocalMaterial(m, s.scope, s.now())
	if e != nil || ctx.Err() != nil {
		return value.LocalKeyConfiguration{}, ErrKeyService
	}
	s.cacheMu.Lock()
	s.cached = c
	s.cacheMu.Unlock()
	return c, nil
}
