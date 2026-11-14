package kms

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func bundledInitialFixture(t *testing.T) (*initialProviderFixture, contracts.BundledInitialProviderIdentity) {
	t.Helper()
	f := newInitialProviderFixture(t)
	now := time.Now().UTC()
	selected := contracts.BundledInitialProviderIdentity{
		Format: contracts.BundledInitialProviderIdentityFormat, BackendName: "trial",
		Namespace:    contracts.WorkerObjectReference{Name: "bootstrap", UID: "20000000-0000-4000-8000-000000000010"},
		SetupAccount: contracts.WorkerObjectReference{Name: "trial-setup", UID: "20000000-0000-4000-8000-000000000011"},
		EntityID:     "20000000-0000-4000-8000-000000000012",
		SetupParent:  contracts.InitialProviderParent{Accessor: "original-setup-parent", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(299 * time.Second)},
	}
	f.parent.Entity = selected.EntityID
	f.parent.Issued = now
	f.parent.Expire = selected.SetupParent.ExpiresAt.Add(-BundledInitialProviderSafetyMargin)
	f.parent.CreationTTL = int64(f.parent.Expire.Sub(now) / time.Second)
	f.parent.MaxTTL = f.parent.CreationTTL
	endpoint := "https://trial-openbao.bootstrap.svc:8200"
	target, _ := url.Parse(f.server.URL)
	h := f.server.Client()
	transport := h.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = f.server.Certificate().DNSNames[0]
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target.Host)
	}
	h.Transport = transport
	var err error
	f.issuer, err = NewBundledInitialProviderIssuer(endpoint, "original-issuer-token", "transit", "initial-audit", "20000000-0000-4000-8000-000000000002", "20000000-0000-4000-8000-000000000003", f.profile, selected, h, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.issuer.Close)
	return f, selected
}

func TestBundledInitialIssuerMatchesExactInheritedEntity(t *testing.T) {
	f, selected := bundledInitialFixture(t)
	if _, _, err := f.issuer.Check(context.Background(), time.Now().Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*initialTokenLookup){
		func(v *initialTokenLookup) { v.Entity = "" },
		func(v *initialTokenLookup) { v.Entity = "foreign-entity" },
		func(v *initialTokenLookup) { v.IdentityPolicies = []string{"extra"} },
		func(v *initialTokenLookup) { v.Expire = selected.SetupParent.ExpiresAt },
	} {
		f.parentChange = change
		if _, _, err := f.issuer.Check(context.Background(), time.Now().Add(15*time.Minute)); err == nil {
			t.Fatal("changed entity/identity policy/original setup bound accepted")
		}
	}
}

func TestDefaultInitialIssuerStillRejectsInheritedEntity(t *testing.T) {
	f := newInitialProviderFixture(t)
	f.parent.Entity = "20000000-0000-4000-8000-000000000012"
	if _, _, err := f.issuer.Check(context.Background(), time.Now().Add(15*time.Minute)); err == nil {
		t.Fatal("default constructor accepted service entity")
	}
}

func TestBundledInitialIssuerChildrenKeepEntityAndOriginalBound(t *testing.T) {
	f, selected := bundledInitialFixture(t)
	parent, claim := f.claim(t)
	got, err := f.issuer.Issue(context.Background(), "wrap", claim, parent)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExpiresAt.After(selected.SetupParent.ExpiresAt.Add(-BundledInitialProviderSafetyMargin)) {
		t.Fatal("child outlived original setup bound")
	}
	if err = f.issuer.Verify(context.Background(), "wrap", claim, parent, got); err != nil {
		t.Fatal(err)
	}
	f.childChange = func(v *initialTokenLookup) { v.Entity = "20000000-0000-4000-8000-000000000099" }
	if err = f.issuer.Verify(context.Background(), "wrap", claim, parent, got); err == nil {
		t.Fatal("foreign child entity accepted")
	}
	f.childChange = nil
	claim.Response = &got
	if _, err = f.issuer.Revoke(context.Background(), "wrap", claim, parent, got); err != nil {
		t.Fatal(err)
	}
	if _, err = f.issuer.Revoke(context.Background(), "wrap", claim, parent, got); err != nil {
		t.Fatal("exact rights-reduction replay refused", err)
	}
}

func TestBundledInitialIssuerOriginalAncestorExpiryNeverRenews(t *testing.T) {
	f, selected := bundledInitialFixture(t)
	// Even a replaced provider reply with an apparently live issuer cannot
	// extend the independently retained original setup parent's hard end.
	f.parentChange = func(v *initialTokenLookup) {
		v.Issued = selected.SetupParent.ExpiresAt
		v.Expire = v.Issued.Add(time.Minute)
	}
	f.issuer.now = func() time.Time { return selected.SetupParent.ExpiresAt.Add(time.Second) }
	if _, _, err := f.issuer.Check(context.Background(), f.issuer.now().Add(15*time.Minute)); err == nil {
		t.Fatal("original ancestor end was renewed")
	}
}

func TestBundledInitialIssuerRejectsForeignEntityInCreateReply(t *testing.T) {
	f, _ := bundledInitialFixture(t)
	parent, claim := f.claim(t)
	f.issueMode = "foreign-entity"
	if _, err := f.issuer.Issue(context.Background(), "wrap", claim, parent); err == nil {
		t.Fatal("foreign create response entity accepted")
	}
	if f.posts != 1 {
		t.Fatal("uncertain issued token was replayed")
	}
}
