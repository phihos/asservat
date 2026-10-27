package authorization

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func TestGrantResumeHintNeedsOriginalClientAndCurrentCollectionRights(t *testing.T) {
	f := newGrantFixture(t)
	ctx := context.Background()
	in := f.input(81, nil)
	in.Scope = []byte(`{"schemaVersion":"recorder-preview/v1","timing":"approvedAcceptance/v1"}`)
	in.ExecutionDigest = sha256.Sum256(in.Scope)
	g, _, err := f.svc.Request(ctx, grantIdentity{f.requester, &f.now}, in)
	if err != nil {
		t.Fatal(err)
	}
	g = f.approve(t, g)
	get := func(caller identity.Identity) GrantView {
		t.Helper()
		v, _, err := f.svc.Get(ctx, grantIdentity{caller, &f.now}, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := get(f.requester); !v.CanResume || !v.CanResolve {
		t.Fatal("current original requester cannot resume")
	}
	otherClient := f.requester
	otherClient.Principal.ClientID = "agent"
	if v := get(otherClient); v.CanResume || v.CanResolve {
		t.Fatal("another original-human client inherited a grant")
	}
	if get(f.approver).CanResume {
		t.Fatal("reviewer inherited requester capture")
	}
	noCaptureScope := f.requester
	noCaptureScope.Scopes = []string{"evidence:read"}
	if v := get(noCaptureScope); v.CanResume || v.CanResolve {
		t.Fatal("missing capture scope can resume")
	}
	previous := f.projection
	f.projection = func(t value.Target) value.Projection { p := previous(t); p.Allows = nil; return p }
	if get(f.requester).CanResume {
		t.Fatal("lost ordinary collection rights can resume")
	}
	f.projection = previous
	if _, _, err = f.svc.Revoke(ctx, grantIdentity{f.requester, &f.now}, g.ID, g.Revision, "revoke"); err != nil {
		t.Fatal(err)
	}
	if v := get(f.requester); v.CanResume || !v.CanResolve {
		t.Fatal("revoked grant start/recovery hints")
	}
}

func TestGrantResumeHintRefusesLegacyScopeAndExpiry(t *testing.T) {
	f := newGrantFixture(t)
	g := f.approve(t, f.request(t, 82, nil))
	v, _, err := f.svc.Get(context.Background(), grantIdentity{f.requester, &f.now}, g.ID)
	if err != nil || v.CanResume {
		t.Fatal("legacy timing offered resume", err)
	}
	f.now = g.ExpiresAt.Add(time.Second)
	v, _, err = f.svc.Get(context.Background(), grantIdentity{f.requester, &f.now}, g.ID)
	if err != nil || v.CanResume {
		t.Fatal("expired grant offered resume", err)
	}
}

func TestMarkedGrantResumeHintExpiresAtOriginalDeadline(t *testing.T) {
	f := newGrantFixture(t)
	in := f.input(83, nil)
	in.Scope = []byte(`{"schemaVersion":"recorder-preview/v1","timing":"approvedAcceptance/v1"}`)
	in.ExecutionDigest = sha256.Sum256(in.Scope)
	g, _, err := f.svc.Request(context.Background(), grantIdentity{f.requester, &f.now}, in)
	if err != nil {
		t.Fatal(err)
	}
	g = f.approve(t, g)
	v, _, err := f.svc.Get(context.Background(), grantIdentity{f.requester, &f.now}, g.ID)
	if err != nil || !v.CanResume {
		t.Fatal("marked grant must initially resume", err)
	}
	f.now = g.ExpiresAt
	v, _, err = f.svc.Get(context.Background(), grantIdentity{f.requester, &f.now}, g.ID)
	if err != nil || v.CanResume || !v.CanResolve {
		t.Fatal("original expiry must remove start hint but retain recovery", err)
	}
}
