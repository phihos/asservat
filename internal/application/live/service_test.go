package live

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
)

const uid = "11111111-1111-4111-8111-111111111111"

type fixedIdentity struct{ i identity.Identity }

func (f fixedIdentity) ResolveIdentity(context.Context) (identity.Identity, error) { return f.i, nil }

type fixture struct {
	now                            time.Time
	authorityUntil                 time.Time
	afterProjection, afterChange   func()
	afterHead, afterCurrent        func()
	source                         v.Source
	denied                         bool
	transient, ledgerTransient     bool
	ended                          bool
	broken                         bool
	reads, heads, changes, created int
	seq                            uint64
	rows                           []v.Row
	controls                       map[string]Control
	keys                           map[string]string
	mu                             sync.Mutex
}

func (f *fixture) Inventory(context.Context, CurrentIdentity, targets.WorkloadRequest, string, int) ([]v.Source, string, error) {
	if f.denied {
		return nil, "", v.ErrDenied
	}
	return []v.Source{f.source}, "", nil
}
func (f *fixture) Check(_ context.Context, _ CurrentIdentity, source v.Source, _ string) (v.Source, time.Time, error) {
	if f.transient {
		return v.Source{}, time.Time{}, v.ErrUnavailable
	}
	if f.ended {
		return v.Source{}, time.Time{}, v.ErrEnded
	}
	if f.denied || !source.Same(f.source) {
		return v.Source{}, time.Time{}, v.ErrDenied
	}
	until := f.now.Add(5 * time.Second)
	if !f.authorityUntil.IsZero() {
		until = minTime(until, f.authorityUntil)
	}
	return f.source, until, nil
}
func (f *fixture) Head(context.Context, []v.Source, string) ([]v.Position, error) {
	f.heads++
	if f.afterHead != nil {
		f.afterHead()
	}
	return []v.Position{{Sequence: f.seq}}, nil
}
func (f *fixture) Read(_ context.Context, _ []v.Source, _ string, positions []v.Position, limit, scan, waitMS int) (Projection, error) {
	f.reads++
	if f.broken {
		return Projection{}, v.ErrUnavailable
	}
	rows := []v.Row{}
	for _, r := range f.rows {
		if r.Sequence > positions[0].Sequence && len(rows) < limit {
			rows = append(rows, r.Clone())
		}
	}
	if f.afterProjection != nil {
		f.afterProjection()
	}
	return Projection{Rows: rows, Positions: []v.Position{{Sequence: f.seq}}, Sources: []v.SourceStatus{{ID: uid, State: "Ready", Coverage: "observed"}}, Gaps: []v.Gap{}, Examined: len(f.rows), Bytes: 100}, nil
}
func (f *fixture) Create(_ context.Context, c Control, key string) (Control, bool, error) {
	f.created++
	if old, ok := f.keys[key]; ok {
		prior := f.controls[old]
		if prior.RequestDigest != c.RequestDigest {
			return Control{}, false, v.ErrConflict
		}
		return prior, true, nil
	}
	f.controls[c.ID] = c
	f.keys[key] = c.ID
	return c, false, nil
}
func (f *fixture) Change(_ context.Context, c Control, expected, cost int64) (Control, error) {
	f.changes++
	prior := f.controls[c.ID]
	if prior.Revision != expected || prior.Fence != c.Fence {
		return Control{}, v.ErrConflict
	}
	if c.Spent != prior.Spent+cost || c.Spent > c.OutputLimit {
		return Control{}, v.ErrCapacity
	}
	f.controls[c.ID] = c
	if f.afterChange != nil {
		f.afterChange()
	}
	return c, nil
}
func setup(t *testing.T) (*Service, *fixture, fixedIdentity, v.Open) {
	t.Helper()
	now := time.Now().UTC()
	f := &fixture{now: now, controls: map[string]Control{}, keys: map[string]string{}}
	b := collector.SourceBinding{RootID: uid, AcceptanceID: uid, SourceID: uid, Fence: uid, PodUID: uid, NodeUID: uid, BootID: uid, CollectorPodUID: uid, CollectorEpoch: uid, PolicyUID: "policy", ActionID: "packets", Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}}
	f.source = v.Source{Binding: b, Target: authorization.Target{ClusterID: uid, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: uid}, OwnerKind: "policy", OwnerID: "policy", State: "Ready", SaveVia: "recordingSave", Projections: []string{v.Packet}, LeaseUntil: now.Add(30 * time.Second), HardUntil: now.Add(time.Hour), PrivacyUntil: now.Add(time.Hour)}
	n := 0
	keys, err := auditapp.NewOperationMAC("audit-v1", bytes.Repeat([]byte{1}, 32), "accounts-v1", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Close)
	s, e := New(Config{RootID: uid, OwnerID: uid, Keys: keys, Now: func() time.Time { return f.now }, NewID: func() string { n++; return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }, Limits: v.DefaultLimits(), MaxWatches: 10, MaxControls: 40}, f, f, f)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	i := fixedIdentity{identity.Identity{Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "viewer", ClientID: "console", Kind: identity.Human}, Scopes: []string{"evidence:read"}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(time.Minute)}}
	page, _, e := s.List(t.Context(), i, targets.WorkloadRequest{ClusterID: uid, Namespace: "ns", Kind: "Deployment", Name: "workload"}, "", 20)
	if e != nil || len(page.Sources) != 1 {
		t.Fatal(page, e)
	}
	r := v.Open{Handles: []string{page.Sources[0].Handle}, Projection: v.Packet, Key: "open", Filter: v.Filter{All: []v.Predicate{}}}
	return s, f, i, r
}
func (f *fixture) add() {
	f.seq++
	f.rows = append(f.rows, v.Row{ID: fmt.Sprint(f.seq), SourceID: uid, Sequence: f.seq, ObservedAt: f.now, ReceivedAt: f.now, ExpiresAt: f.now.Add(30 * time.Second), Projection: v.Packet, PodUID: uid, Packet: &v.PacketFields{Protocol: "TCP", RemoteIP: "192.0.2.1", RemotePort: 8080, Direction: "unknown", WireBytes: 64}})
}

func TestLiveAcceptedScopeCeilingsAndLaterLoweringNeverRenewWatch(t *testing.T) {
	s, f, i, r := setup(t)
	f.source.ViewLimits = v.Limits{Duration: 60, Output: 1 << 20, Rate: 16 << 10, Rows: 10, Buffer: 64 << 10, RowAge: 10, Replay: 2}
	w, e := s.Open(t.Context(), i, r)
	if e != nil || w.Limits != f.source.ViewLimits || !w.ExpiresAt.Equal(f.now.Add(time.Minute)) {
		t.Fatal(w, e)
	}
	f.add()
	batch, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || len(batch.Rows) != 1 || batch.Rows[0].ExpiresAt.After(f.now.Add(10*time.Second)) {
		t.Fatal(batch, e)
	}
	// A looser later policy cannot expand the already accepted watch.
	f.source.ViewLimits = v.DefaultLimits()
	if _, e = s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: batch.Cursor}); e != nil {
		t.Fatal(e)
	}
	f.source.ViewLimits.Rows = 1
	before := f.reads
	if _, e = s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: batch.Cursor}); e == nil || f.reads != before {
		t.Fatal("lowering did not close before dispatch", e)
	}
}

func TestLivePrincipalAccountingIsSharedAcrossClientsButHandlesRemainClientBound(t *testing.T) {
	s, f, console, request := setup(t)
	first, e := s.Open(t.Context(), console, request)
	if e != nil {
		t.Fatal(e)
	}
	mcp := console
	mcp.i.Principal.ClientID = "mcp"
	if _, e = s.Open(t.Context(), mcp, request); e == nil {
		t.Fatal("foreign-client source reference accepted")
	}
	page, _, e := s.List(t.Context(), mcp, targets.WorkloadRequest{ClusterID: uid, Namespace: "ns", Kind: "Deployment", Name: "workload"}, "", 20)
	if e != nil || len(page.Sources) != 1 {
		t.Fatal(page, e)
	}
	request.Handles = []string{page.Sources[0].Handle}
	second, e := s.Open(t.Context(), mcp, request)
	if e != nil || second.ID == first.ID {
		t.Fatal(second, e)
	}
	if f.controls[first.ID].PrincipalKey != f.controls[second.ID].PrincipalKey || f.created != 2 {
		t.Fatal("same principal acquired a separate client budget")
	}
	if _, e = s.Read(t.Context(), mcp, v.Read{ID: first.ID, Cursor: *first.Cursor}); e == nil {
		t.Fatal("shared budget opened foreign-client watch")
	}
}
func TestLiveOpenDoesNotBackfillAndReplayChargesSameStableRows(t *testing.T) {
	s, f, i, r := setup(t)
	f.add()
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	if f.heads != 1 || f.reads != 0 {
		t.Fatal("open read/backfill", f)
	}
	replay, e := s.Open(t.Context(), i, r)
	if e != nil || replay.ID != w.ID || !replay.ExpiresAt.Equal(w.ExpiresAt) {
		t.Fatal("open replay", e)
	}
	f.add()
	batch, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || len(batch.Rows) != 1 || batch.Rows[0].Sequence != 2 || batch.Cursor == *w.Cursor {
		t.Fatal(batch, e)
	}
	again, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || again.ID != batch.ID || len(again.Rows) != 1 || again.Rows[0].ID != batch.Rows[0].ID || again.Spent <= batch.Spent || f.reads != 1 || again.Cursor != batch.Cursor {
		t.Fatal("replay replaced payload or did not charge", again, e)
	}
	f.denied = true
	if denied, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor}); e == nil || len(denied.Rows) != 0 {
		t.Fatal("replay bypassed revocation")
	}
}
func TestLivePauseResumeHeadRevisionAndOriginalExpiry(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	paused, e := s.Update(t.Context(), i, v.Update{ID: w.ID, Revision: 1, Key: "pause", Mode: "Paused"}, false)
	if e != nil || paused.State != "Paused" || !paused.ExpiresAt.Equal(w.ExpiresAt) {
		t.Fatal(paused, e)
	}
	f.add()
	b, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *paused.Cursor})
	if e != nil || len(b.Rows) != 0 || f.reads != 0 {
		t.Fatal("paused view read source", e)
	}
	resumed, e := s.Update(t.Context(), i, v.Update{ID: w.ID, Revision: 2, Key: "resume", Mode: "Active"}, false)
	if e != nil || resumed.Revision != 3 || !resumed.ExpiresAt.Equal(w.ExpiresAt) {
		t.Fatal(resumed, e)
	}
	if _, e = s.Update(t.Context(), i, v.Update{ID: w.ID, Revision: 1, Key: "stale", Mode: "Active"}, false); e == nil {
		t.Fatal("stale revision")
	}
	b, e = s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *resumed.Cursor})
	if e != nil || len(b.Rows) != 0 {
		t.Fatal("resume backfilled paused row", b, e)
	}
	if _, e = s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor}); e == nil {
		t.Fatal("old revision cursor survived")
	}
}
func TestLiveNoFieldOracleForeignCursorAndExpiredRows(t *testing.T) {
	s, f, i, r := setup(t)
	r.Filter = v.Filter{All: []v.Predicate{{Field: "peer_uid", Op: "neq", Value: json.RawMessage(`"hidden"`)}}}
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	b, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || len(b.Rows) != 0 {
		t.Fatal("unknown predicate leaked", b, e)
	}
	if _, e = s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: "forged"}); e == nil {
		t.Fatal("forged cursor")
	}
	other := i
	other.i.Principal.Subject = "recipient"
	if _, e = s.Read(t.Context(), other, v.Read{ID: w.ID, Cursor: b.Cursor}); e == nil {
		t.Fatal("foreign viewer")
	}
}

func TestLiveAcceptedFilterAndReplayNeverBorrowCallerMemory(t *testing.T) {
	s, f, i, r := setup(t)
	r.Filter = v.Filter{All: []v.Predicate{{Field: "port", Op: "eq", Value: json.RawMessage("8080")}}}
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	copy(r.Filter.All[0].Value, "9090")
	f.add()
	b, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || len(b.Rows) != 1 {
		t.Fatal("input mutation changed accepted filter", b, e)
	}
	b.Rows[0].Packet.RemoteIP = "203.0.113.99"
	again, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || again.Rows[0].Packet.RemoteIP != "192.0.2.1" {
		t.Fatal("returned page mutation changed replay", again, e)
	}
}

func TestLiveAbandonedReplayErasedWithoutAnotherRead(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	if _, e = s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor}); e != nil {
		t.Fatal(e)
	}
	st := s.sessions[w.ID]
	st.mu.Lock()
	st.timer.Stop()
	st.mu.Unlock()
	f.now = f.now.Add(v.ReplayAge)
	s.expireSession(st)
	st.mu.Lock()
	if len(st.replay) != 0 {
		t.Fatal("abandoned replay retained beyond5s")
	}
	st.timer.Stop()
	st.mu.Unlock()
	f.now = f.now.Add(v.IdleAge)
	s.expireSession(st)
	if len(s.sessions) != 0 || len(st.selected) != 0 || len(st.filter.All) != 0 {
		t.Fatal("idle scope/payload retained")
	}
}

type blockedLiveReader struct {
	*fixture
	entered, release, returned chan struct{}
}

func (f blockedLiveReader) Read(ctx context.Context, _ []v.Source, _ string, _ []v.Position, _, _, _ int) (Projection, error) {
	close(f.entered)
	<-ctx.Done()
	<-f.release
	close(f.returned)
	return Projection{}, ctx.Err()
}
func TestLiveRuntimeCloseCancelsAndJoinsReadBeforeScopeRelease(t *testing.T) {
	s, f, i, r := setup(t)
	blocked := blockedLiveReader{f, make(chan struct{}), make(chan struct{}), make(chan struct{})}
	s.reader = blocked
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor, WaitMS: 5000}); done <- e }()
	<-blocked.entered
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("close claimed join before reader returned")
	case <-time.After(10 * time.Millisecond):
	}
	close(blocked.release)
	<-blocked.returned
	<-closed
	if e := <-done; e == nil {
		t.Fatal("canceled read returned rows")
	}
}

func TestLiveOpenReplayDoesNotNeedExpiredDiscoveryOrTouchSourceHead(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	before := f.heads

	// Keep the existing view active, while its original discovery reference
	// expires. Retry must find original acceptance before interpreting handles.
	for step := 0; step < 3; step++ {
		f.now = f.now.Add(21 * time.Second)
		f.source.LeaseUntil = f.now.Add(30 * time.Second)
		i.i.VerifiedAt = f.now
		i.i.ValidUntil = f.now.Add(time.Minute)
		if _, e = s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *s.sessions[w.ID].watch.Cursor}); e != nil {
			t.Fatal(e)
		}
	}

	again, e := s.Open(t.Context(), i, r)
	if e != nil || again.ID != w.ID || !again.ExpiresAt.Equal(w.ExpiresAt) || f.heads != before || f.created != 1 {
		t.Fatalf("replayed acceptance rediscovered or reacquired: watch=%+v err=%v heads=%d/%d creates=%d", again, e, f.heads, before, f.created)
	}
	changed := r
	changed.Duration = 12
	if _, e = s.Open(t.Context(), i, changed); !errors.Is(e, v.ErrConflict) {
		t.Fatalf("changed retry: %v", e)
	}
	f.denied = true
	if _, e = s.Open(t.Context(), i, r); e == nil {
		t.Fatal("replay bypassed current rights")
	}
}

func TestLiveExpiredReplayUsesAuthenticatedLaggingCursorAndFreshHead(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	first, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || len(first.Rows) != 1 {
		t.Fatal(first, e)
	}
	f.now = f.now.Add(6 * time.Second)
	f.add()
	before := f.reads
	lag, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || len(lag.Rows) != 0 || len(lag.Gaps) != 1 || lag.Gaps[0].Reason != "bufferExpired" || lag.Cursor == first.Cursor || f.reads != before {
		t.Fatalf("expired replay backfilled: %+v %v", lag, e)
	}
	fresh, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: lag.Cursor})
	if e != nil || len(fresh.Rows) != 0 {
		t.Fatal("lag recovery did not start at head", fresh, e)
	}
	forged := lag.Cursor[:len(lag.Cursor)-1] + "z"
	if _, e = s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: forged}); !errors.Is(e, v.ErrConflict) {
		t.Fatal("forged cursor accepted", e)
	}
}

func (f *fixture) CurrentLive(_ context.Context, c Control) error {
	if f.afterCurrent != nil {
		f.afterCurrent()
	}
	if f.ledgerTransient {
		return v.ErrUnavailable
	}
	old, ok := f.controls[c.ID]
	if !ok || old.Fence != c.Fence || old.Revision != c.Revision || old.Spent != c.Spent {
		return v.ErrDenied
	}
	return nil
}
func TestLiveStaleOwnerDeniesBeforePrivateRead(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	changed := f.controls[w.ID]
	changed.Fence = "replacement"
	f.controls[w.ID] = changed
	f.add()
	if out, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor}); e == nil || len(out.Rows) != 0 || f.reads != 0 {
		t.Fatal("stale owner read", out, e, f.reads)
	}
}

func TestLiveDisconnectedResumeKeepsScopeAndStartsAtCurrentHead(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.broken = true
	if out, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor}); e == nil || len(out.Rows) != 0 {
		t.Fatal("broken reader disclosed")
	}
	f.add()
	f.broken = false
	resumed, e := s.Update(t.Context(), i, v.Update{ID: w.ID, Revision: w.Revision, Key: "reconnect", Mode: "Active"}, false)
	if e != nil || resumed.State != "Active" || !resumed.ExpiresAt.Equal(w.ExpiresAt) {
		t.Fatal("same original scope could not resume", resumed, e)
	}
	f.add()
	out, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *resumed.Cursor})
	if e != nil || len(out.Rows) != 1 || out.Rows[0].Sequence != 2 {
		t.Fatal("reconnect backfilled", out, e)
	}
}
func TestLiveClosedViewReleasesLocalSubscriberSlotAndClearsScope(t *testing.T) {
	s, f, i, r := setup(t)
	s.cfg.MaxWatches = 1
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Update(t.Context(), i, v.Update{ID: w.ID, Revision: 1, Key: "close"}, true); e != nil {
		t.Fatal(e)
	}
	st := s.sessions[w.ID]
	st.mu.Lock()
	retained := len(st.selected) + len(st.filter.All) + len(st.replay)
	st.mu.Unlock()
	if retained != 0 {
		t.Fatal("close retained scope", retained)
	}
	r.Key = "another"
	if _, e = s.Open(t.Context(), i, r); e != nil {
		t.Fatal("closed view still consumed subscriber slot", e)
	}
	if f.reads != 0 {
		t.Fatal("closure acquired data")
	}
}
func TestLiveInventoryReportsUnavailableCapabilityWithoutInventingActiveLease(t *testing.T) {
	s, f, i, _ := setup(t)
	f.source.Projections = nil
	f.source.State = "Unavailable"
	f.source.LeaseUntil = f.now.Add(-time.Second)
	f.source.Blockers = []string{"ProjectionUnavailable"}
	page, _, e := s.List(t.Context(), i, targets.WorkloadRequest{ClusterID: uid, Namespace: "ns", Kind: "Deployment", Name: "workload"}, "", 20)
	if e != nil || len(page.Sources) != 1 || page.Sources[0].Eligible || len(page.Sources[0].Projections) != 0 || !page.Sources[0].LeaseUntil.Equal(f.source.LeaseUntil) {
		t.Fatal(page, e)
	}
	if _, e = s.Open(t.Context(), i, v.Open{Handles: []string{page.Sources[0].Handle}, Projection: v.Packet, Key: "unavailable"}); e == nil {
		t.Fatal("metadata handle granted unavailable source")
	}
	if f.reads != 0 || f.heads != 0 || f.created != 0 {
		t.Fatal("inventory acquired or admitted", f.reads, f.heads, f.created)
	}
}
func TestLiveStoppedSourceClearsReplayAndReturnsNoMoreRows(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	first, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil {
		t.Fatal(e)
	}
	f.source.State = "Stopped"
	before := f.reads
	out, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: first.Cursor})
	if e != nil || out.State != "SourceEnded" || len(out.Rows) != 0 || len(out.Gaps) != 1 || out.Gaps[0].Reason != "sourceEnded" || f.reads != before {
		t.Fatal(out, e, f.reads)
	}
	if len(s.sessions[w.ID].selected) != 0 || len(s.sessions[w.ID].replay) != 0 {
		t.Fatal("ended source retained rows/scope")
	}
}

func (f *fixture) Resolve(_ context.Context, _ CurrentIdentity, id, kind, projection string) (v.Source, time.Time, error) {
	if f.denied || id != f.source.ID() || kind != f.source.OwnerKind {
		return v.Source{}, time.Time{}, v.ErrDenied
	}
	return f.Check(context.Background(), nil, f.source, projection)
}
func TestLiveStatelessHandleIsReferenceNotFiveSecondObservationOrPermit(t *testing.T) {
	s, f, i, _ := setup(t)
	i.i.ValidUntil = f.now.Add(5 * time.Second)
	page, _, e := s.List(t.Context(), i, targets.WorkloadRequest{ClusterID: uid, Namespace: "ns", Kind: "Deployment", Name: "workload"}, "", 20)
	if e != nil || len(page.Sources) != 1 {
		t.Fatal(page, e)
	}
	handle := page.Sources[0].Handle
	end := page.Sources[0].HandleExpires
	if len(handle) > 128 || !end.After(i.i.ValidUntil) || end.After(f.now.Add(time.Minute)) {
		t.Fatal("reference borrowed operation observation", handle, end)
	}
	f.now = f.now.Add(6 * time.Second)
	i.i.VerifiedAt = f.now
	i.i.ValidUntil = f.now.Add(5 * time.Second)
	decoded, e := s.decodeSourceHandle(i.i.Principal, handle)
	if e != nil || !decoded.Until.Equal(end) {
		t.Fatal("validation renewed or expired reference", decoded, e)
	}
	w, e := s.Open(t.Context(), i, v.Open{Handles: []string{handle}, Projection: v.Packet, Key: "stateless"})
	if e != nil || w.ID == "" {
		t.Fatal("fresh authority could not use original reference", e)
	}
	other := i
	other.i.Principal.ClientID = "another-client"
	if _, e = s.Open(t.Context(), other, v.Open{Handles: []string{handle}, Projection: v.Packet, Key: "foreign"}); e == nil {
		t.Fatal("handle crossed client")
	}
	f.source.Binding.Fence = "22222222-2222-4222-8222-222222222222"
	if _, e = s.Open(t.Context(), i, v.Open{Handles: []string{handle}, Projection: v.Packet, Key: "changed"}); e == nil {
		t.Fatal("handle substituted source version")
	}
}

func TestLiveFinalAuthorityCutoffSurvivesBlockingChargeWithoutRefund(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	f.afterProjection = func() { f.authorityUntil = f.now.Add(time.Second) }
	f.afterChange = func() { f.now = f.now.Add(2 * time.Second) }
	batch, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e == nil || len(batch.Rows) != 0 || f.controls[w.ID].Spent == 0 {
		t.Fatal("expired final source proof disclosed rows or refunded uncertain spend", batch, e, f.controls[w.ID].Spent)
	}
}

func TestLiveSourceEndingDuringReadDropsSelectedRowsAndReturnsTerminalCoverage(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	f.afterProjection = func() { f.source.State = "Stopped" }
	batch, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || batch.State != "SourceEnded" || len(batch.Rows) != 0 || len(batch.Gaps) != 1 || batch.Gaps[0].Reason != "sourceEnded" {
		t.Fatal(batch, e)
	}
}

func TestLiveDisplayFilterExclusionsAreNotReportedAsSensorLoss(t *testing.T) {
	s, f, i, r := setup(t)
	r.Filter = v.Filter{All: []v.Predicate{{Field: "protocol", Op: "eq", Value: json.RawMessage(`"UDP"`)}}}
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	batch, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || len(batch.Rows) != 0 {
		t.Fatal(batch, e)
	}
	filtered := false
	for _, g := range batch.Gaps {
		if g.Reason == "sensorLoss" {
			t.Fatal("display-only exclusion became source loss")
		}
		if g.Reason == "filteredOut" && g.Count != nil && *g.Count == 1 {
			filtered = true
		}
	}
	if !filtered || f.reads != 1 || f.seq != 1 {
		t.Fatal("intentional display exclusion was indistinguishable from missing source activity", batch.Gaps)
	}
}

type liveInventoryPage struct {
	*fixture
	requested int
}

func (f *liveInventoryPage) Inventory(_ context.Context, _ CurrentIdentity, _ targets.WorkloadRequest, _ string, limit int) ([]v.Source, string, error) {
	f.requested = limit
	out := make([]v.Source, limit)
	for n := range out {
		out[n] = f.source.Clone()
		out[n].Binding.SourceID = fmt.Sprintf("00000000-0000-4000-8000-%012d", n+100)
	}
	return out, "existing-position", nil
}
func TestLiveInventoryLargeRequestedPageUsesBoundedProducerAndOriginalContinuation(t *testing.T) {
	s, f, i, _ := setup(t)
	paged := &liveInventoryPage{fixture: f}
	s.sources = paged
	out, next, e := s.List(t.Context(), i, targets.WorkloadRequest{ClusterID: uid, Namespace: "ns", Kind: "Deployment", Name: "workload"}, "", 100)
	b, _ := json.Marshal(out)
	if e != nil || paged.requested != 20 || len(out.Sources) != 20 || next != "existing-position" || len(b) > 20<<10 {
		t.Fatal("inventory exceeded public envelope or lost original cursor", e, paged.requested, len(out.Sources), next, len(b))
	}
}

func TestLiveSmallAcceptedReplayBufferNeverRetainsOversizedBatch(t *testing.T) {
	s, f, i, r := setup(t)
	f.source.ViewLimits = v.DefaultLimits()
	f.source.ViewLimits.Buffer = 1024
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	f.add()
	b, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || len(b.Rows) != 2 {
		t.Fatal(b, e)
	}
	st := s.sessions[w.ID]
	st.mu.Lock()
	used := 0
	for _, p := range st.replay {
		raw, _ := json.Marshal(p.batch)
		used += len(raw)
	}
	st.mu.Unlock()
	if used > w.Limits.Buffer {
		t.Fatal("accepted replay buffer exceeded", used, w.Limits.Buffer)
	}
}

func TestLiveLaggingHeadPreservesFinalCutoffAndTerminalState(t *testing.T) {
	for _, mode := range []string{"earlier-cutoff", "source-ended"} {
		t.Run(mode, func(t *testing.T) {
			s, f, i, r := setup(t)
			w, e := s.Open(t.Context(), i, r)
			if e != nil {
				t.Fatal(e)
			}
			f.add()
			if _, e = s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor}); e != nil {
				t.Fatal(e)
			}
			f.now = f.now.Add(6 * time.Second) // authenticated original cursor now lags expired replay
			before := f.controls[w.ID].Spent
			f.afterHead = func() {
				if mode == "earlier-cutoff" {
					f.authorityUntil = f.now.Add(time.Second)
				} else {
					f.source.State = "Stopped"
				}
			}
			if mode == "earlier-cutoff" {
				f.afterChange = func() { f.now = f.now.Add(2 * time.Second) }
			}
			batch, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
			if mode == "earlier-cutoff" {
				if e == nil || len(batch.Rows) != 0 || f.controls[w.ID].Spent <= before {
					t.Fatal("lagging head discarded final cutoff or refunded spend", batch, e)
				}
				return
			}
			if e != nil || batch.State != "SourceEnded" || len(batch.Rows) != 0 || len(batch.Gaps) != 1 || batch.Gaps[0].Reason != "sourceEnded" {
				t.Fatal("ended source became active lagging heartbeat", batch, e)
			}
			if len(s.sessions[w.ID].selected) != 0 || len(s.sessions[w.ID].positions) != 0 {
				t.Fatal("terminal lag recovery restored source details")
			}
		})
	}
}

type closedReceiptBatchSources struct {
	*fixture
	checks int
}

func (f *closedReceiptBatchSources) CheckSources(ctx context.Context, current CurrentIdentity, in []v.Source, projection string) ([]v.Source, time.Time, error) {
	f.checks++
	if len(in) == 0 {
		return nil, time.Time{}, v.ErrInvalid
	}
	out := make([]v.Source, len(in))
	until := f.now.Add(5 * time.Second)
	for n, source := range in {
		var e error
		var end time.Time
		out[n], end, e = f.Check(ctx, current, source, projection)
		if e != nil {
			return nil, time.Time{}, e
		}
		until = minTime(until, end)
	}
	return out, until, nil
}
func TestLiveClosedReceiptRetryUsesCurrentActorAndOriginalControlWithoutSourceScope(t *testing.T) {
	s, f, i, r := setup(t)
	sources := &closedReceiptBatchSources{fixture: f}
	s.sources = sources
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	request := v.Update{ID: w.ID, Revision: w.Revision, Key: "close-receipt"}
	receipt, e := s.Update(t.Context(), i, request, true)
	if e != nil {
		t.Fatal(e)
	}
	st := s.sessions[w.ID]
	if len(st.selected) != 0 || len(st.replay) != 0 || len(st.filter.All) != 0 {
		t.Fatal("close retained source scope")
	}
	checks, heads, reads, changes := sources.checks, f.heads, f.reads, f.changes
	again, e := s.Update(t.Context(), i, request, true)
	if e != nil || hash(again) != hash(receipt) {
		t.Fatal("lost Close response cannot replay exact immutable receipt", again, e)
	}
	if sources.checks != checks || f.heads != heads || f.reads != reads || f.changes != changes {
		t.Fatal("close receipt reauthorized erased sources or renewed/charged", sources.checks, checks, f.changes, changes)
	}
	other := i
	other.i.Principal.ClientID = "other"
	if _, e = s.Update(t.Context(), other, request, true); e == nil {
		t.Fatal("closed receipt crossed client")
	}
	changed := request
	changed.Revision++
	if _, e = s.Update(t.Context(), i, changed, true); !errors.Is(e, v.ErrConflict) {
		t.Fatal("changed key input replayed", e)
	}
	control := f.controls[w.ID]
	bad := control
	bad.Fence = "22222222-2222-4222-8222-222222222222"
	f.controls[w.ID] = bad
	if _, e = s.Update(t.Context(), i, request, true); e == nil {
		t.Fatal("closed receipt bypassed current original ledger")
	}
	f.controls[w.ID] = control
	// Recheck the same request identity after a blocking original-control read.
	f.afterCurrent = func() { i.i.Policy.Generation++ }
	if _, e = s.Update(t.Context(), &i, request, true); e == nil {
		t.Fatal("closed receipt ignored current identity change during ledger read")
	}
	f.afterCurrent = nil
	i.i.Policy.Generation--
	originalNow := f.now
	f.afterCurrent = func() { f.now = control.IdleUntil }
	if _, e = s.Update(t.Context(), i, request, true); e == nil {
		t.Fatal("closed receipt ignored original deadline crossed during ledger read")
	}
	f.afterCurrent = nil
	f.now = originalNow
	if sources.checks != checks || f.changes != changes {
		t.Fatal("failed receipt retry reacquired source or changed original spend")
	}
	f.now = control.IdleUntil
	if _, e = s.Update(t.Context(), i, request, true); e == nil {
		t.Fatal("closed receipt renewed original idle deadline")
	}
}

// A node wait that outlasts the first check's window is disclosed under the
// fresh post-read check; revocation seen by that check still refuses.
func TestLiveReadDisclosesUnderFreshCheckAfterLongWait(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	f.afterProjection = func() { f.now = f.now.Add(6 * time.Second) }
	batch, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor, WaitMS: 5000})
	if e != nil || len(batch.Rows) != 1 || !batch.DisclosureUntil.After(f.now) {
		t.Fatal("long wait not disclosed under fresh check", batch.DisclosureUntil, f.now, e)
	}
	f.add()
	f.afterProjection = func() { f.denied = true }
	if denied, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: batch.Cursor}); e == nil || len(denied.Rows) != 0 {
		t.Fatal("revocation after the node read disclosed rows")
	}
}

// A transient source/status miss fails only that read without disclosure
// and leaves the view open; an access denial still ends it.
func TestLiveTransientSourceMissKeepsViewOpen(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	f.transient = true
	if b, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor}); !errors.Is(e, v.ErrTransient) || len(b.Rows) != 0 {
		t.Fatal("transient miss disclosed or was not marked transient", e)
	}
	f.transient = false
	batch, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || len(batch.Rows) != 1 || batch.State != "Active" {
		t.Fatal("view did not survive a transient miss", batch.State, e)
	}
	f.ledgerTransient = true
	if _, e := s.Update(t.Context(), i, v.Update{ID: w.ID, Revision: batch.Revision, Key: "pause-transient", Mode: "Paused"}, false); !errors.Is(e, v.ErrTransient) {
		t.Fatal("transient ledger miss on update was not transient", e)
	}
	f.ledgerTransient = false
	f.add()
	if again, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: batch.Cursor}); e != nil || again.State != "Active" {
		t.Fatal("view did not survive a transient ledger miss", again.State, e)
	} else {
		batch = again
	}
	f.add()
	f.denied = true
	if _, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: batch.Cursor}); e == nil || errors.Is(e, v.ErrTransient) {
		t.Fatal("denial treated as transient", e)
	}
}

// Rows keep their managed age; the five-second check bounds the read, not
// how long an already disclosed row stays displayable.
func TestLiveRowExpiryIsNotTheFreshnessCheckBound(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	// The identity snapshot itself is only fresh for five seconds.
	short := i
	short.i.ValidUntil = f.now.Add(5 * time.Second)
	batch, e := s.Read(t.Context(), short, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || len(batch.Rows) != 1 {
		t.Fatal(batch, e)
	}
	if !batch.Rows[0].ExpiresAt.After(f.now.Add(5*time.Second)) || batch.Rows[0].ExpiresAt.After(w.ExpiresAt) {
		t.Fatal("row expiry is the freshness bound or exceeds the watch", batch.Rows[0].ExpiresAt, f.now, w.ExpiresAt)
	}
}

// A source lease that lapses during a read's check (renewal pending) fails
// only that read; after renewal the same rows are delivered.
func TestLiveLeaseLapseDuringCheckIsTransient(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.add()
	f.source.LeaseUntil = f.now.Add(time.Second)
	f.afterCurrent = func() { f.now = f.now.Add(2 * time.Second) }
	if b, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor}); !errors.Is(e, v.ErrTransient) || len(b.Rows) != 0 {
		t.Fatal("lapsed lease was not a transient refusal", e)
	}
	f.afterCurrent = nil
	f.source.LeaseUntil = f.now.Add(time.Minute)
	batch, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || len(batch.Rows) != 1 || batch.State != "Active" {
		t.Fatal("renewed lease did not deliver the original row", batch.State, e)
	}
}

// An ended finite source ends the view normally instead of refusing reads.
func TestLiveEndedFiniteSourceEndsViewAsSourceEnded(t *testing.T) {
	s, f, i, r := setup(t)
	w, e := s.Open(t.Context(), i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.ended = true
	batch, e := s.Read(t.Context(), i, v.Read{ID: w.ID, Cursor: *w.Cursor})
	if e != nil || batch.State != "SourceEnded" || len(batch.Rows) != 0 {
		t.Fatal("ended source did not end the view", batch.State, e)
	}
	found := false
	for _, g := range batch.Gaps {
		found = found || g.Reason == "sourceEnded"
	}
	if !found {
		t.Fatal("ended view reported no sourceEnded gap", batch.Gaps)
	}
}
