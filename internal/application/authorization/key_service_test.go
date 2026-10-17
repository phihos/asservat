package authorization

import (
	"bytes"
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type keyAuthorityFunc func(context.Context, value.KeyPeer, value.KeyRequestInfo) (value.KeyOperationPermit, error)

func (f keyAuthorityFunc) Resolve(c context.Context, p value.KeyPeer, r value.KeyRequestInfo) (value.KeyOperationPermit, error) {
	return f(c, p, r)
}

type keyBackendFunc func(context.Context, value.KeyRequest) (value.KeyResult, error)

func (f keyBackendFunc) Execute(c context.Context, r value.KeyRequest) (value.KeyResult, error) {
	return f(c, r)
}

func TestKeyServiceRequiresCurrentKeyConfiguration(t *testing.T) {
	now := time.Now().UTC()
	scope := value.KeyScope{InstallationID: "00000000-0000-4000-8000-000000000001", Purpose: "artifact", KeyID: "evidence"}
	r := value.KeyRequest{Scope: scope, AuthorityID: "00000000-0000-4000-8000-000000000002", Operation: "wrap", Binding: []byte("binding"), Input: []byte("synthetic keyset")}
	p := value.KeyPeer{InstallationID: scope.InstallationID, PeerID: "00000000-0000-4000-8000-000000000003", Role: "collector", Certificate: artifact.Digest{1}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
	s := KeyService{Scope: scope, Now: time.Now,
		Authority: keyAuthorityFunc(func(_ context.Context, p value.KeyPeer, i value.KeyRequestInfo) (value.KeyOperationPermit, error) {
			return value.KeyOperationPermit{AuthorityID: i.AuthorityID, RecoveryEpoch: "00000000-0000-4000-8000-000000000004", Revision: 1, Certificate: p.Certificate, RequestDigest: i.RequestDigest, ObservedAt: now, ValidUntil: now.Add(4 * time.Second)}, nil
		}),
		Backend: keyBackendFunc(func(context.Context, value.KeyRequest) (value.KeyResult, error) {
			return value.KeyResult{Sealed: artifact.SealedKey{Reference: "synthetic", Ciphertext: "synthetic"}}, nil
		}),
	}
	if _, err := s.Execute(context.Background(), p, r); err == nil {
		t.Fatal("a service without current key configuration accepted an operation")
	}
}

func TestKeyServiceOriginalAuthorityBounds(t *testing.T) {
	base := time.Now().UTC()
	scope := value.KeyScope{InstallationID: "00000000-0000-4000-8000-000000000001", Purpose: "artifact", KeyID: "evidence"}
	request := value.KeyRequest{Scope: scope, AuthorityID: "00000000-0000-4000-8000-000000000002", Operation: "unwrap", Binding: []byte("synthetic binding"), Sealed: artifact.SealedKey{Reference: "asservat-local-keyset/v1/" + scope.InstallationID + "/artifact/evidence/1", Ciphertext: "synthetic"}}
	peer := value.KeyPeer{InstallationID: scope.InstallationID, PeerID: "00000000-0000-4000-8000-000000000003", Role: "acquisition", Certificate: artifact.Digest{1}, NotBefore: base.Add(-time.Minute), NotAfter: base.Add(20 * time.Minute)}
	for _, mode := range []string{"ok", "missing-authority", "wrong-role", "different-installation", "unknown-authority", "wrong-digest", "wrong-peer", "no-recovery", "long-lease", "future-observation", "expired-after-authority", "expired-after-backend", "canceled-after-backend", "malformed-output", "mutated-binding", "configuration-denied", "configuration-revoked-after-crypto", "configuration-expired-before-crypto", "configuration-blocked-past-permit", "configuration-shorter"} {
		t.Run(mode, func(t *testing.T) {
			now, calls := base, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := peer
			if mode == "wrong-role" {
				p.Role = "collector"
			}
			if mode == "different-installation" {
				p.InstallationID = "00000000-0000-4000-8000-000000000009"
			}
			var secret []byte
			s := KeyService{Scope: scope, Now: func() time.Time { return now }}
			s.Authority = keyAuthorityFunc(func(_ context.Context, p value.KeyPeer, r value.KeyRequestInfo) (value.KeyOperationPermit, error) {
				permit := value.KeyOperationPermit{AuthorityID: r.AuthorityID, RecoveryEpoch: "00000000-0000-4000-8000-000000000004", Revision: 1, Certificate: p.Certificate, RequestDigest: r.RequestDigest, ObservedAt: base, ValidUntil: base.Add(4 * time.Second)}
				switch mode {
				case "unknown-authority":
					permit.AuthorityID = "00000000-0000-4000-8000-000000000008"
				case "wrong-digest":
					permit.RequestDigest[0]++
				case "wrong-peer":
					permit.Certificate[0]++
				case "no-recovery":
					permit.RecoveryEpoch = ""
				case "long-lease":
					permit.ValidUntil = base.Add(6 * time.Second)
				case "future-observation":
					permit.ObservedAt = base.Add(time.Second)
				case "expired-after-authority":
					now = base.Add(4 * time.Second)
				case "mutated-binding":
					clear(r.Binding)
				}
				return permit, nil
			})
			if mode == "missing-authority" {
				s.Authority = nil
			}
			s.Backend = keyBackendFunc(func(c context.Context, r value.KeyRequest) (value.KeyResult, error) {
				calls++
				if !bytes.Equal(r.Binding, request.Binding) {
					t.Fatal("authority changed backend binding")
				}
				deadline, ok := c.Deadline()
				if !ok || deadline.After(base.Add(4*time.Second)) {
					t.Fatal("backend lost original deadline")
				}
				secret = []byte("synthetic returned key")
				if mode == "expired-after-backend" {
					now = base.Add(4 * time.Second)
				}
				if mode == "canceled-after-backend" {
					cancel()
				}
				if mode == "malformed-output" {
					secret = make([]byte, 4097)
				}
				return value.KeyResult{Output: secret}, nil
			})
			checks := 0
			s.Backend = guardedKeyBackend{s.Backend, func(_ context.Context, k value.KeyScope, epoch string) (time.Time, error) {
				checks++
				if k != scope || epoch != "00000000-0000-4000-8000-000000000004" {
					t.Fatal("configuration lost operation binding")
				}
				if mode == "configuration-denied" || (mode == "configuration-revoked-after-crypto" && checks == 2) {
					return time.Time{}, ErrKeyUnavailable
				}
				if mode == "configuration-expired-before-crypto" {
					return base, nil
				}
				if mode == "configuration-blocked-past-permit" {
					now = base.Add(4 * time.Second)
				}
				if mode == "configuration-shorter" && checks == 1 {
					return base.Add(time.Second), nil
				}
				return now.Add(4 * time.Second), nil
			}}
			result, err := s.Execute(ctx, p, request)
			if mode == "ok" || mode == "mutated-binding" || mode == "configuration-shorter" {
				expectedUntil := base.Add(4 * time.Second)
				if mode == "configuration-shorter" {
					expectedUntil = base.Add(time.Second)
				}
				if err != nil || !bytes.Equal(result.Output, []byte("synthetic returned key")) || result.ValidUntil != expectedUntil {
					t.Fatal("authorized operation failed", err)
				}
				return
			}
			if err == nil || len(result.Output) != 0 {
				t.Fatal("invalid authority returned a key")
			}
			if mode == "expired-after-backend" || mode == "canceled-after-backend" || mode == "malformed-output" || mode == "configuration-revoked-after-crypto" {
				if calls != 1 || !bytes.Equal(secret, make([]byte, len(secret))) {
					t.Fatal("late result not cleared")
				}
			} else if calls != 0 {
				t.Fatal("backend invoked before valid authority")
			}
		})
	}
}

func TestKeyRequestDigestCoversExactOperation(t *testing.T) {
	r := value.KeyRequest{Scope: value.KeyScope{InstallationID: "00000000-0000-4000-8000-000000000001", Purpose: "artifact", KeyID: "key"}, AuthorityID: "00000000-0000-4000-8000-000000000002", Operation: "wrap", Binding: []byte("binding"), Input: []byte("synthetic key")}
	first, err := DescribeKeyRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*value.KeyRequest){
		func(r *value.KeyRequest) { r.Scope.InstallationID = "00000000-0000-4000-8000-000000000008" },
		func(r *value.KeyRequest) { r.Scope.Purpose = "audit" },
		func(r *value.KeyRequest) { r.Scope.KeyID = "another" },
		func(r *value.KeyRequest) { r.AuthorityID = "00000000-0000-4000-8000-000000000008" },
		func(r *value.KeyRequest) { r.Binding = []byte("another") },
		func(r *value.KeyRequest) { r.Input = []byte("another key") },
	} {
		changed := r
		change(&changed)
		info, err := DescribeKeyRequest(changed)
		if err != nil || info.RequestDigest == first.RequestDigest {
			t.Fatal("substitution retained request identity")
		}
	}
}

// Unit-only configuration source; the production backend uses Kubernetes/SQL.
type guardedKeyBackend struct {
	KeyOperationBackend
	check func(context.Context, value.KeyScope, string) (time.Time, error)
}

func (s guardedKeyBackend) CurrentKeyConfiguration(c context.Context, k value.KeyScope, e string) (time.Time, error) {
	return s.check(c, k, e)
}
