package kms

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func initialRoleCapIssue(t *testing.T, f *initialProviderFixture) (contracts.InitialProviderIssue, contracts.InitialProviderParent) {
	t.Helper()
	parent, _, e := f.issuer.Check(context.Background(), time.Now().Add(15*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	return contracts.InitialProviderIssue{ID: "20000000-0000-4000-8000-000000000010", StartedAt: now, Until: now.Add(4 * time.Second), ExpiresBefore: parent.ExpiresAt}, parent
}

// OpenBao2.7.1 stores request explicit_max_ttl in TokenEntry, but applies a
// role-only cap to Auth without copying it there. Self lookup therefore returns
// zero for this nonrenewable role-issued child even though its actual expiry and
// the independently checked role are bounded. The issuer's cap remains explicit.
func TestInitialProviderRoleOnlyChildCap(t *testing.T) {
	f := newInitialProviderFixture(t)
	f.childChange = func(d *initialTokenLookup) { d.MaxTTL = 0 }
	issue, parent := initialRoleCapIssue(t, f)
	got, e := f.issuer.Issue(context.Background(), "wrap", issue, parent)
	if e != nil {
		t.Fatal("qualified role-only child rejected", e)
	}
	if !got.ExpiresAt.Before(issue.ExpiresBefore) || got.IssuedAt.Before(issue.StartedAt) {
		t.Fatal("child lifetime escaped original claim")
	}
	if e = f.issuer.Verify(context.Background(), "wrap", issue, parent, got); e != nil {
		t.Fatal("same child verification rejected", e)
	}
	f.mu.Lock()
	calls := f.posts
	f.mu.Unlock()
	if calls != 1 {
		t.Fatal("issuer replayed create")
	}
}
func TestInitialProviderRoleOnlyCapCannotRelaxIssuerOrChild(t *testing.T) {
	t.Run("issuer-still-requires-explicit-cap", func(t *testing.T) {
		f := newInitialProviderFixture(t)
		f.parentChange = func(d *initialTokenLookup) { d.MaxTTL = 0 }
		if _, _, e := f.issuer.Check(context.Background(), time.Now().Add(15*time.Minute)); e == nil {
			t.Fatal("uncapped issuer accepted")
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.posts != 0 {
			t.Fatal("preflight issued a token")
		}
	})
	for name, change := range map[string]func(*initialTokenLookup){
		"renewable":     func(d *initialTokenLookup) { d.Renewable = true },
		"periodic":      func(d *initialTokenLookup) { d.Period = 10 },
		"orphan":        func(d *initialTokenLookup) { d.Orphan = true },
		"wrong-role":    func(d *initialTokenLookup) { d.Role = "other-role" },
		"wrong-path":    func(d *initialTokenLookup) { d.Path = "auth/token/create" },
		"late-expiry":   func(d *initialTokenLookup) { d.Expire = d.Expire.Add(20 * time.Minute) },
		"negative-cap":  func(d *initialTokenLookup) { d.MaxTTL = -1 },
		"oversized-cap": func(d *initialTokenLookup) { d.MaxTTL = 901 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newInitialProviderFixture(t)
			f.childChange = func(d *initialTokenLookup) { d.MaxTTL = 0; change(d) }
			issue, parent := initialRoleCapIssue(t, f)
			got, e := f.issuer.Issue(context.Background(), "wrap", issue, parent)
			if e == nil || got.Token != "" {
				t.Fatal("unsafe role-only child accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.posts != 1 {
				t.Fatal("unknown issued result replayed or preflight changed")
			}
		})
	}
}
