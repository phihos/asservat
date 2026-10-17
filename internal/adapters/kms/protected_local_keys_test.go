package kms

import (
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type materialSourceFunc func(context.Context) (app.KeyMaterial, error)

func (f materialSourceFunc) ReadKeyMaterial(c context.Context) (app.KeyMaterial, error) { return f(c) }

type keyLedgerFunc func(context.Context, value.LocalKeyConfiguration) (time.Time, error)

func (f keyLedgerFunc) ObserveLocalKeys(c context.Context, v value.LocalKeyConfiguration) (time.Time, error) {
	return f(c, v)
}
func TestProtectedKeysCoalesceWithoutRenewingObservations(t *testing.T) {
	ctx := context.Background()
	base := time.Now()
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	scope := value.KeyScope{InstallationID: localScope.InstallationID, Purpose: localScope.Purpose, KeyID: localScope.KeyID}
	payload := localSecret(t, localScope, 1, 1)
	snapshot := value.LocalKeyConfiguration{Scope: scope, ClusterID: "00000000-0000-4000-8000-000000000002", NamespaceUID: "namespace", RecoveryEpoch: "00000000-0000-4000-8000-000000000003", Revision: identity.Revision{UID: "configuration", Generation: 1, Digest: artifact.Digest{1}}, SecretUID: "secret", SecretDigest: artifact.Digest(sha256.Sum256(payload))}
	var reads atomic.Int32
	var unavailable atomic.Bool
	source := materialSourceFunc(func(context.Context) (app.KeyMaterial, error) {
		reads.Add(1)
		if unavailable.Load() {
			return app.KeyMaterial{}, ErrKeyService
		}
		c := snapshot
		c.ObservedAt = now()
		c.FreshUntil = c.ObservedAt.Add(5 * time.Second)
		return app.KeyMaterial{Configuration: c, Payload: bytes.Clone(payload)}, nil
	})
	ledger := keyLedgerFunc(func(_ context.Context, c value.LocalKeyConfiguration) (time.Time, error) {
		if !c.Valid(now()) {
			return time.Time{}, ErrKeyService
		}
		return c.FreshUntil, nil
	})
	service, e := LoadProtectedLocalOperations(ctx, scope, source, ledger, now)
	if e != nil {
		t.Fatal(e)
	}
	clock.Add(int64(2 * time.Second))
	until, e := service.CurrentKeyConfiguration(ctx, scope, snapshot.RecoveryEpoch)
	if e != nil || !until.Equal(base.Add(5*time.Second)) || reads.Load() != 1 {
		t.Fatal("cache hit extended original deadline", e, reads.Load())
	}
	clock.Add(int64(3 * time.Second))
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := service.CurrentKeyConfiguration(ctx, scope, snapshot.RecoveryEpoch); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if reads.Load() != 2 {
		t.Fatal("concurrent refresh stampede", reads.Load())
	}
	unavailable.Store(true)
	clock.Add(int64(5 * time.Second))
	if _, e = service.CurrentKeyConfiguration(ctx, scope, snapshot.RecoveryEpoch); e == nil {
		t.Fatal("unavailable source reused expired cache")
	}
	if _, e = service.CurrentKeyConfiguration(ctx, scope, "00000000-0000-4000-8000-000000000099"); e == nil {
		t.Fatal("different recovery epoch accepted")
	}
}
