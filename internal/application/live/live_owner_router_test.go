package live

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	v "asservat.local/asservat/internal/domain/live"
)

type ownerRouteFixture struct {
	s           *Service
	f           *fixture
	calls       int
	unavailable bool
}

func (f *ownerRouteFixture) LocateLiveOwner(_ context.Context, k RouteKeys) (OwnerCommandRoute, bool, error) {
	f.calls++
	if f.unavailable {
		return nil, false, v.ErrUnavailable
	}
	id := k.WatchID
	if id == "" {
		id = f.f.keys[hex.EncodeToString(k.OpenKey[:])]
	}
	c, found := f.f.controls[id]
	if !found {
		return nil, false, nil
	}
	if c.PrincipalKey != k.PrincipalKey {
		return nil, false, v.ErrDenied
	}
	return ownerTestRoute{f.s}, true, nil
}

type ownerTestRoute struct{ s *Service }

func (r ownerTestRoute) OwnerID() string { return r.s.cfg.OwnerID }
func (r ownerTestRoute) Begin(ctx context.Context, who CurrentIdentity, c Command, k RouteKeys) (CommandDelivery, error) {
	return r.s.BeginOwnedLocalCommand(ctx, who, c, k)
}
func secondOwner(t *testing.T, s *Service, f *fixture) *Service {
	t.Helper()
	c := s.cfg
	c.OwnerID = "22222222-2222-4222-8222-222222222222"
	next, err := New(c, f, f, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	return next
}
func TestLiveOwnerRoutesOriginalSessionAndSameKeyWithoutTakeover(t *testing.T) {
	s, f, who, open := setup(t)
	w, err := s.Open(t.Context(), who, open)
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Millisecond)
	f.add()
	second := secondOwner(t, s, f)
	lookup := &ownerRouteFixture{s: s, f: f}
	routed, err := NewRoutedService(second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	request := v.Read{ID: w.ID, Cursor: *w.Cursor, Limit: 20}
	// The unchanged original API demonstrates the missing process-local state.
	if _, err = second.Read(t.Context(), who, request); err == nil {
		t.Fatal("second process fabricated local session")
	}
	d, err := routed.BeginLiveCommand(t.Context(), who, Command{Read: &request})
	if err != nil {
		t.Fatal(err)
	}
	result := d.Result()
	if result.Batch == nil || len(result.Batch.Rows) != 1 || !result.Batch.DisclosureUntil.Before(w.ExpiresAt) || d.CheckDisclosure(t.Context()) != nil {
		t.Fatal("original read/cutoff lost", result, err)
	}
	if len(second.sessions) != 0 || f.created != 1 || f.reads != 1 {
		t.Fatal("adopted session or repeated acquisition", f.created, f.reads)
	}
	if err = d.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if d.CheckDisclosure(t.Context()) == nil {
		t.Fatal("closed delivery still discloses")
	}
	heads := f.heads
	replay, err := routed.Open(t.Context(), who, open)
	if err != nil || replay.ID != w.ID || !replay.ExpiresAt.Equal(w.ExpiresAt) || f.created != 1 || f.heads != heads {
		t.Fatal("same key restarted/reselected", replay, err)
	}
	other := who
	other.i.Principal.ClientID = "mcp"
	if _, err = routed.Read(t.Context(), other, request); err == nil || f.reads != 1 {
		t.Fatal("shared human locator became other-client authority")
	}
	lookup.unavailable = true
	if _, err = routed.Open(t.Context(), who, open); !errors.Is(err, v.ErrUnavailable) || f.created != 1 {
		t.Fatal("unavailable owner fell back to new local Open", err)
	}
	if lookup.calls != 4 {
		t.Fatal("unexpected extra locator reads", lookup.calls)
	}
}
func TestLiveOwnerRouteKeysMatchExistingAdmissionAndKeepClientsSeparate(t *testing.T) {
	s, f, who, open := setup(t)
	k, err := s.OwnerRouteKeys(t.Context(), who, Command{Open: &open})
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.Open(t.Context(), who, open)
	if err != nil {
		t.Fatal(err)
	}
	c := f.controls[w.ID]
	if c.PrincipalKey != k.PrincipalKey || c.RequestDigest != k.RequestDigest || f.keys[hex.EncodeToString(k.OpenKey[:])] != w.ID {
		t.Fatal("locator grammar drifted from actual Create")
	}
	other := who
	other.i.Principal.ClientID = "mcp"
	next, err := s.OwnerRouteKeys(t.Context(), other, Command{Open: &open})
	if err != nil || next.PrincipalKey != k.PrincipalKey || next.OpenKey == k.OpenKey {
		t.Fatal("client reset budget or shared open key")
	}
}
