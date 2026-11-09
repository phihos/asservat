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

type ownerFailingRoute struct {
	owner string
	err   error
}

func (r ownerFailingRoute) OwnerID() string { return r.owner }
func (r ownerFailingRoute) Begin(context.Context, CurrentIdentity, Command, RouteKeys) (CommandDelivery, error) {
	if r.err != nil {
		return nil, r.err
	}
	return nil, errors.Join(v.ErrUnavailable, v.ErrOwnerLost)
}

type ownerFailingLookup struct{ route OwnerCommandRoute }

func (f ownerFailingLookup) LocateLiveOwner(context.Context, RouteKeys) (OwnerCommandRoute, bool, error) {
	return f.route, true, nil
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
func TestLiveOwnerFailureClosesOnlyTheOriginalClientView(t *testing.T) {
	s, f, who, open := setup(t)
	w, err := s.Open(t.Context(), who, open)
	if err != nil {
		t.Fatal(err)
	}
	before := f.controls[w.ID]
	second := secondOwner(t, s, f)
	routed, err := NewRoutedService(second, ownerFailingLookup{ownerFailingRoute{owner: s.cfg.OwnerID}})
	if err != nil {
		t.Fatal(err)
	}
	request := v.Read{ID: w.ID, Cursor: *w.Cursor, Limit: 20}
	other := who
	other.i.Principal.ClientID = "mcp"
	if _, err = routed.Read(t.Context(), other, request); err == nil {
		t.Fatal("another client closed the lost owner's view")
	}
	if got := f.controls[w.ID]; got != before || f.reads != 0 {
		t.Fatal("refused recovery changed control or read a source", got, f.reads)
	}
	healthy, err := NewRoutedService(second, ownerFailingLookup{ownerFailingRoute{owner: s.cfg.OwnerID, err: v.ErrUnavailable}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = healthy.Read(t.Context(), who, request); !errors.Is(err, v.ErrUnavailable) || errors.Is(err, v.ErrOwnerLost) {
		t.Fatal("healthy owner failure became owner loss", err)
	}
	if got := f.controls[w.ID]; got != before {
		t.Fatal("healthy owner failure closed the view", got)
	}
	transient, err := NewRoutedService(second, ownerFailingLookup{ownerFailingRoute{owner: s.cfg.OwnerID, err: errors.Join(v.ErrUnavailable, v.ErrTransient)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = transient.Read(t.Context(), who, request); !errors.Is(err, v.ErrTransient) {
		t.Fatal("transient source miss became terminal owner recovery", err)
	}
	if got := f.controls[w.ID]; got != before {
		t.Fatal("transient source miss closed the view", got)
	}
	batch, err := routed.Read(t.Context(), who, request)
	if err != nil {
		t.Fatal(err)
	}
	after := f.controls[w.ID]
	if batch.WatchID != w.ID || batch.Revision != w.Revision || batch.State != "Closed" || len(batch.Rows) != 0 || len(batch.Gaps) != 1 || batch.Gaps[0].Reason != "reconnect" || batch.Cursor != "" || batch.Spent != before.Spent {
		t.Fatal("owner failure did not return a terminal empty original-revision batch", batch)
	}
	if after.State != "Closed" || after.Revision != before.Revision || !after.ExpiresAt.Equal(before.ExpiresAt) || !after.IdleUntil.Equal(before.IdleUntil) || after.Spent != before.Spent || len(second.sessions) != 0 || f.reads != 0 {
		t.Fatal("recovery renewed, adopted or read private session state", after)
	}
	replayed, err := routed.Read(t.Context(), who, request)
	if err != nil || replayed.State != "Closed" || replayed.Revision != before.Revision || len(replayed.Rows) != 0 {
		t.Fatal("terminal recovery was not stable", replayed, err)
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
