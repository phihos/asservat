package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type materialSourceFunc func(context.Context) (app.KeyMaterial, error)

func (f materialSourceFunc) ReadKeyMaterial(c context.Context) (app.KeyMaterial, error) { return f(c) }

type keyLedgerFunc func(context.Context, value.LocalKeyConfiguration) (time.Time, error)

func (f keyLedgerFunc) ObserveLocalKeys(c context.Context, v value.LocalKeyConfiguration) (time.Time, error) {
	return f(c, v)
}

type attributedKeyAuthority func(context.Context, value.KeyPeer, value.KeyRequestInfo) (value.KeyOperationPermit, error)

func (f attributedKeyAuthority) Resolve(ctx context.Context, p value.KeyPeer, r value.KeyRequestInfo) (value.KeyOperationPermit, error) {
	return f(ctx, p, r)
}

func TestFreshKeyPermitUsesItsOwnConfigurationObservation(t *testing.T) {
	base := time.Now().UTC()
	now := base.Add(-5*time.Second + time.Millisecond)
	scope := value.KeyScope{InstallationID: localScope.InstallationID, Purpose: localScope.Purpose, KeyID: localScope.KeyID}
	payload := localSecret(t, localScope, 1, 1)
	snapshot := value.LocalKeyConfiguration{Scope: scope, ClusterID: "00000000-0000-4000-8000-000000000002", NamespaceUID: "synthetic", RecoveryEpoch: "00000000-0000-4000-8000-000000000003", Revision: identity.Revision{UID: "configuration", Generation: 1, Digest: artifact.Digest(sha256.Sum256(payload))}, SecretUID: "fixture-key", SecretDigest: artifact.Digest(sha256.Sum256(payload))}
	sourceUnavailable := false
	var onRead func()
	source := materialSourceFunc(func(context.Context) (app.KeyMaterial, error) {
		if sourceUnavailable {
			return app.KeyMaterial{}, ErrKeyService
		}
		if onRead != nil {
			onRead()
		}
		c := snapshot
		c.SecretDigest = artifact.Digest(sha256.Sum256(payload))
		c.ObservedAt = now
		c.FreshUntil = now.Add(5 * time.Second)
		return app.KeyMaterial{Configuration: c, Payload: bytes.Clone(payload)}, nil
	})
	delay := false
	ledger := keyLedgerFunc(func(_ context.Context, c value.LocalKeyConfiguration) (time.Time, error) {
		if delay {
			now = now.Add(2 * time.Millisecond)
		}
		if !c.Valid(now) {
			return time.Time{}, ErrKeyService
		}
		return c.FreshUntil, nil
	})
	backend, err := LoadProtectedLocalOperations(t.Context(), scope, snapshot.RecoveryEpoch, source, ledger, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	now, delay = base, true
	peer := value.KeyPeer{InstallationID: scope.InstallationID, ClusterID: snapshot.ClusterID, PeerID: "00000000-0000-4000-8000-000000000004", Role: "collector", Certificate: artifact.Digest{1}, NotBefore: base.Add(-time.Minute), NotAfter: base.Add(time.Minute)}
	permitUntil := base.Add(3 * time.Second)
	calls := 0
	authority := attributedKeyAuthority(func(_ context.Context, p value.KeyPeer, r value.KeyRequestInfo) (value.KeyOperationPermit, error) {
		calls++
		return value.KeyOperationPermit{AuthorityID: r.AuthorityID, RecoveryEpoch: snapshot.RecoveryEpoch, Revision: 1, Certificate: p.Certificate, RequestDigest: r.RequestDigest, ObservedAt: base, ValidUntil: permitUntil}, nil
	})
	service := app.KeyService{Scope: scope, Authority: authority, Backend: backend, Now: func() time.Time { return now }}
	r := value.KeyRequest{Scope: scope, AuthorityID: "00000000-0000-4000-8000-000000000005", Operation: "wrap", Binding: []byte("test-binding"), Input: []byte("synthetic-keyset")}
	result, err := service.Execute(t.Context(), peer, r)
	if calls != 1 || err != nil || !result.Valid("wrap") || result.ValidUntil.After(permitUntil) {
		t.Fatal("fresh operation lost its original permit", calls, err)
	}

	requireRefusal := func(stage string) {
		t.Helper()
		_, err := service.Execute(t.Context(), peer, r)
		var fixed interface{ FixedStep() string }
		if !errors.Is(err, app.ErrKeyUnavailable) || !errors.As(err, &fixed) || fixed.FixedStep() != stage {
			t.Fatal("unexpected key refusal", stage, err)
		}
	}
	// Rotation changes the real mounted material under the running backend.
	var rotated localKeySecret
	if err := json.Unmarshal(payload, &rotated); err != nil {
		t.Fatal(err)
	}
	defer rotated.clear()
	rotated.ActiveVersion = 2
	rotated.Keys = append(rotated.Keys, localKeyVersion{Version: 2, Material: bytes.Repeat([]byte{0x42}, 32)})
	updated, err := json.Marshal(rotated)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(updated)
	before := result.Sealed
	originalPayload, originalSnapshot := payload, snapshot
	// Replace the mount between the before and after reads of one operation.
	reads := 0
	onRead = func() {
		reads++
		if reads == 2 {
			payload = updated
			snapshot.Revision.Digest = artifact.Digest(sha256.Sum256(payload))
			snapshot.Revision.Generation = 2
		}
	}
	if crossed, err := service.Execute(t.Context(), peer, r); !errors.Is(err, app.ErrKeyUnavailable) || crossed.Sealed != (artifact.SealedKey{}) {
		t.Fatal("operation crossing active key rotation returned a result", err)
	}
	onRead = nil
	after, err := service.Execute(t.Context(), peer, r)
	if err != nil || !strings.HasSuffix(after.Sealed.Reference, "/2") {
		t.Fatal("next operation did not wrap with v2", err)
	}
	reader := peer
	reader.Role = "acquisition"
	unwrap := value.KeyRequest{Scope: r.Scope, Operation: "unwrap", AuthorityID: r.AuthorityID, Binding: r.Binding, Sealed: before}
	plain, err := service.Execute(t.Context(), reader, unwrap)
	if err != nil || !bytes.Equal(plain.Output, r.Input) || !strings.HasSuffix(before.Reference, "/1") {
		t.Fatal("retained v1 key could not unwrap after rotation", err)
	}
	// A delayed v1 observation cannot reinstall v1 after the v2 operation.
	payload, snapshot = originalPayload, originalSnapshot
	requireRefusal("configuration-before/rotation")
	sourceUnavailable = true
	requireRefusal("configuration-before/source")
	if _, _, err := backend.CurrentKeyConfiguration(t.Context(), scope, "00000000-0000-4000-8000-000000000099"); err == nil {
		t.Fatal("wrong recovery epoch accepted")
	}
}
