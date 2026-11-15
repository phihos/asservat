package evidence

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// stopFixture models the SQL ledger: the first key stores the stop, the same
// key returns it and any other key conflicts.
type stopFixture struct {
	now    time.Time
	i      identity.Identity
	stored *artifact.DownloadStop
	state  string
	root   string
	stops  int
}

func (f *stopFixture) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return f.i, ctx.Err()
}
func (f *stopFixture) StopDownload(_ context.Context, i identity.Identity, id string, key artifact.Digest, request string) (artifact.DownloadStop, error) {
	f.stops++
	if f.stored != nil {
		if f.stored.Actor != i.Principal || f.stored.KeyDigest != key {
			return artifact.DownloadStop{}, artifact.ErrDownloadConflict
		}
		return *f.stored, nil
	}
	f.stored = &artifact.DownloadStop{RootID: f.root, DownloadID: id, RequestID: request, Actor: i.Principal, KeyDigest: key, State: f.state}
	return *f.stored, nil
}

const stopDownloadID, stopRequestID = "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"

func newStopFixture(t *testing.T) (*stopFixture, ContextDownloadStopCoordinator) {
	t.Helper()
	base, _ := newDownloadControlFixture(t)
	now := time.Now().UTC()
	base.refresh(now)
	f := &stopFixture{now: now, i: base.i, state: "Cancelled", root: base.a.Scope.RootID}
	f.i.Scopes = []string{"openid"}
	if !f.i.Valid(now) {
		t.Fatal("invalid synthetic stop fixture")
	}
	return f, ContextDownloadStopCoordinator{Ledger: f, Now: func() time.Time { return f.now }}
}

func TestDownloadStopWithoutEvidenceScopesAndSameKeyReplay(t *testing.T) {
	f, s := newStopFixture(t)
	out, e := s.CancelContextDownload(t.Context(), f, stopDownloadID, "same-key", stopRequestID)
	if e != nil || out.State != "Cancelled" || out.RequestID != stopRequestID {
		t.Fatal(out, e)
	}
	out, e = s.CancelContextDownload(t.Context(), f, stopDownloadID, "same-key", "44444444-4444-4444-8444-444444444444")
	if e != nil || out.RequestID != stopRequestID || out.State != "Cancelled" {
		t.Fatal("replay did not return the original stop", out, e)
	}
	if _, e = s.CancelContextDownload(t.Context(), f, stopDownloadID, "different-key", stopRequestID); e == nil {
		t.Fatal("new key accepted")
	}
}

func TestDownloadStopAlreadyTerminalIsCoarseAndActorBound(t *testing.T) {
	f, s := newStopFixture(t)
	f.state = "AlreadyTerminal"
	out, e := s.CancelContextDownload(t.Context(), f, stopDownloadID, "same-key", stopRequestID)
	if e != nil || out.State != "AlreadyTerminal" {
		t.Fatal(out, e)
	}
	f.i.Principal.ClientID = "different-client"
	if _, e = s.CancelContextDownload(t.Context(), f, stopDownloadID, "same-key", stopRequestID); e == nil {
		t.Fatal("foreign client read stop receipt")
	}
}

func TestDownloadStopExpiredIdentityDenied(t *testing.T) {
	f, s := newStopFixture(t)
	f.now = f.now.Add(time.Hour)
	if out, e := s.CancelContextDownload(t.Context(), f, stopDownloadID, "same-key", stopRequestID); e == nil || out.DownloadID != "" || f.stops != 0 {
		t.Fatal("expired identity stopped a download", out, e)
	}
}
