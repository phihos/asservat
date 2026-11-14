package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
	native "asservat.local/asservat/internal/transport/native"
)

// Only the owner credential/TLS/H2, command services and forwarding are real.
// Human identity, current source/ledger and protected registry/route observations
// are synthetic. Two identity reads per source phase model the existing batched
// C3 contract, independent of selected source count; this is no SQL/API proof.
type liveOwnerFacts struct {
	mu          sync.Mutex
	sources     []v.Source
	controls    map[string]liveapp.Control
	keys        map[string]string
	count       atomic.Int32
	reads       atomic.Int32
	phaseUntil  time.Time
	block       chan struct{}
	entered     chan struct{}
	afterRead   func()
	empty       bool
	transient   bool
	unavailable bool
	delay       time.Duration
}

func (f *liveOwnerFacts) Inventory(context.Context, liveapp.CurrentIdentity, targets.WorkloadRequest, string, int) ([]v.Source, string, error) {
	return f.sources, "", nil
}
func (f *liveOwnerFacts) Resolve(ctx context.Context, c liveapp.CurrentIdentity, id, kind, projection string) (v.Source, time.Time, error) {
	for _, s := range f.sources {
		if s.ID() == id {
			return s, time.Now().Add(5 * time.Second), nil
		}
	}
	return v.Source{}, time.Time{}, v.ErrDenied
}
func (f *liveOwnerFacts) Check(ctx context.Context, c liveapp.CurrentIdentity, s v.Source, p string) (v.Source, time.Time, error) {
	return s, time.Now().Add(5 * time.Second), nil
}
func (f *liveOwnerFacts) phase(ctx context.Context, c liveapp.CurrentIdentity) (time.Time, error) {
	until := time.Now().Add(5 * time.Second)
	for range 2 {
		i, e := c.ResolveIdentity(ctx)
		if e != nil {
			return time.Time{}, e
		}
		until = identity.Earlier(until, i.ValidUntil)
	}
	if !f.phaseUntil.IsZero() {
		until = identity.Earlier(until, f.phaseUntil)
	}
	return until, nil
}
func (f *liveOwnerFacts) ResolveSources(ctx context.Context, c liveapp.CurrentIdentity, refs []v.SourceReference, p string) ([]v.Source, time.Time, error) {
	u, e := f.phase(ctx, c)
	return append([]v.Source(nil), f.sources...), u, e
}
func (f *liveOwnerFacts) CheckSources(ctx context.Context, c liveapp.CurrentIdentity, ss []v.Source, p string) ([]v.Source, time.Time, error) {
	u, e := f.phase(ctx, c)
	return append([]v.Source(nil), ss...), u, e
}
func (f *liveOwnerFacts) Head(context.Context, []v.Source, string) ([]v.Position, error) {
	return make([]v.Position, len(f.sources)), nil
}
func (f *liveOwnerFacts) Read(ctx context.Context, ss []v.Source, p string, positions []v.Position, limit, scan, wait int) (liveapp.Projection, error) {
	f.reads.Add(1)
	if f.delay > 0 {
		timer := time.NewTimer(f.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return liveapp.Projection{}, ctx.Err()
		}
	}
	if f.entered != nil {
		close(f.entered)
	}
	if f.block != nil {
		select {
		case <-ctx.Done():
			return liveapp.Projection{}, ctx.Err()
		case <-f.block:
		}
	}
	if f.transient {
		return liveapp.Projection{}, fmt.Errorf("%w: %w: synthetic source miss", v.ErrUnavailable, v.ErrTransient)
	}
	if f.unavailable {
		return liveapp.Projection{}, v.ErrUnavailable
	}
	now := time.Now()
	rows := []v.Row{}
	for _, s := range ss {
		rows = append(rows, v.Row{ID: s.ID() + "-1", SourceID: s.ID(), Sequence: 1, ObservedAt: now, ReceivedAt: now, ExpiresAt: now.Add(20 * time.Second), Projection: p, PodUID: s.Binding.PodUID, Packet: &v.PacketFields{Protocol: "TCP", RemoteIP: "192.0.2.1", RemotePort: 8080, Direction: "unknown", WireBytes: 64}})
	}
	if f.empty {
		rows = []v.Row{}
	}
	next := make([]v.Position, len(ss))
	status := make([]v.SourceStatus, len(ss))
	for j, s := range ss {
		next[j].Sequence = 1
		status[j] = v.SourceStatus{ID: s.ID(), State: "Ready", Coverage: "observed"}
	}
	if f.afterRead != nil {
		f.afterRead()
	}
	return liveapp.Projection{Rows: rows, Positions: next, Sources: status, Gaps: []v.Gap{}, Examined: len(rows), Bytes: int64(len(rows) * 64)}, nil
}
func (f *liveOwnerFacts) CurrentLive(_ context.Context, c liveapp.Control) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if old, ok := f.controls[c.ID]; !ok || old != c {
		return v.ErrDenied
	}
	return nil
}
func (f *liveOwnerFacts) Create(_ context.Context, _ string, c liveapp.Control, key string) (liveapp.Control, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.keys[key]; ok {
		return f.controls[id], true, nil
	}
	f.controls[c.ID] = c
	f.keys[key] = c.ID
	return c, false, nil
}
func (f *liveOwnerFacts) Change(_ context.Context, c liveapp.Control, revision, cost int64) (liveapp.Control, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.controls[c.ID]
	if old.Revision != revision || c.Spent != old.Spent+cost {
		return liveapp.Control{}, v.ErrConflict
	}
	f.controls[c.ID] = c
	return c, nil
}

type liveOwnerIdentityFixture struct {
	i        identity.Identity
	calls    atomic.Int32
	changeAt int32
	change   func(*identity.Identity)
}

func (f *liveOwnerIdentityFixture) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	n := f.calls.Add(1)
	i := f.i
	if f.changeAt > 0 && n >= f.changeAt {
		f.change(&i)
	}
	if ctx.Err() != nil {
		return identity.Identity{}, ctx.Err()
	}
	return i, nil
}

type countedLiveBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (r countedLiveBody) Read(p []byte) (int, error) {
	n, e := r.ReadCloser.Read(p)
	r.n.Add(int64(n))
	return n, e
}

type countedLiveWriter struct {
	wire *bytes.Buffer
	mu   *sync.Mutex
	http.ResponseWriter
	n *atomic.Int64
}

func (w countedLiveWriter) Write(p []byte) (int, error) {
	n, e := w.ResponseWriter.Write(p)
	w.mu.Lock()
	w.wire.Write(p[:n])
	w.mu.Unlock()
	w.n.Add(int64(n))
	return n, e
}
func (w countedLiveWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type liveOwnerH2Fixture struct {
	forward    *liveOwnerForwarder
	facts      *liveOwnerFacts
	current    *liveOwnerIdentityFixture
	service    *liveapp.Service
	request    v.Open
	watch      v.Watch
	peer       *observationForwardFixture
	requests   atomic.Int32
	in, out    atomic.Int64
	server     *httptest.Server
	serverKeys *mtls.OwnerCredentials
	handler    *native.LiveOwnerHandler
	joined     atomic.Int32
	wire       bytes.Buffer
	wireMu     sync.Mutex
}

func (f *liveOwnerH2Fixture) begin(ctx context.Context, c liveapp.Command) (liveapp.CommandDelivery, error) {
	k, e := f.service.OwnerRouteKeys(ctx, f.current, c)
	if e != nil {
		return nil, e
	}
	return f.forward.begin(ctx, f.current, c, k, f.peer.servers[0])
}

type liveOwnerRejectNative struct{ calls atomic.Int32 }

func (a *liveOwnerRejectNative) OpenNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (native.Conversation, error) {
	a.calls.Add(1)
	return nil, v.ErrDenied
}
