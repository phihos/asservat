package authorization

import (
	"context"
	"crypto/sha256"
	"testing"

	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func TestGrantResumeHintFollowsRequesterAndCurrentCollectionRights(t *testing.T) {
	f := newGrantFixture(t)
	ctx := context.Background()
	in := f.input(81, nil)
	in.Scope = []byte(`{"schemaVersion":"recorder-preview/v1","timing":"approvedAcceptance/v1"}`)
	in.ExecutionDigest = sha256.Sum256(in.Scope)
	g, _, err := f.svc.Request(ctx, grantIdentity{f.requester, &f.now}, in)
	if err != nil {
		t.Fatal(err)
	}
	get := func(caller identity.Identity) GrantView {
		t.Helper()
		v, _, err := f.svc.Get(ctx, grantIdentity{caller, &f.now}, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if get(f.requester).CanResume {
		t.Fatal("pending review offered resume")
	}
	g = f.approve(t, g)
	otherClient := f.requester
	otherClient.Principal.ClientID = "agent"
	for _, caller := range []identity.Identity{f.requester, otherClient} {
		if !get(caller).CanResume {
			t.Fatal("a client of the requesting human cannot resume", caller.Principal.ClientID)
		}
	}
	if get(f.approver).CanResume {
		t.Fatal("reviewer inherited requester capture")
	}
	previous := f.projection
	f.projection = func(t value.Target) value.Projection { p := previous(t); p.Allows = nil; return p }
	if get(f.requester).CanResume {
		t.Fatal("lost ordinary collection rights can resume")
	}
	f.projection = previous
	f.now = g.ExpiresAt
	if get(f.requester).CanResume {
		t.Fatal("expired grant offered resume")
	}
}
