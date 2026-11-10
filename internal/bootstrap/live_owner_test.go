package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	auditapp "asservat.local/asservat/internal/application/audit"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
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

func newLiveOwnerH2Fixture(t *testing.T, count int) *liveOwnerH2Fixture {
	t.Helper()
	old, peer := newObservationForwardFixture(t, "valid", 0)
	binding := peer.client
	binding.PodUID = observationForwardID(10)
	binding.ProcessEpoch = observationForwardID(30)
	peer.servers = []fleet.OwnerBinding{binding}
	serverKeys, e := mtls.NewOwnerCredentialsForPool(binding, "server", peer.pin.Pool, peer.base.roots, peer, peer, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(serverKeys.Close)
	if e = serverKeys.Enroll(t.Context()); e != nil {
		t.Fatal(e)
	}
	facts := &liveOwnerFacts{controls: map[string]liveapp.Control{}, keys: map[string]string{}}
	now := time.Now()
	for j := range count {
		id := observationForwardID(100 + j)
		b := collector.SourceBinding{RootID: peer.pin.RootID, AcceptanceID: id, SourceID: id, Fence: id, PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, PolicyUID: "policy", ActionID: "packets", Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}}
		facts.sources = append(facts.sources, v.Source{Binding: b, Target: authorization.Target{ClusterID: runtimeID, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: id}, OwnerKind: "policy", OwnerID: "policy", State: "Ready", SaveVia: "recordingSave", Projections: []string{v.Packet}, LeaseUntil: now.Add(30 * time.Second), HardUntil: now.Add(time.Hour), PrivacyUntil: now.Add(time.Hour)})
	}
	keys, e := auditapp.NewOperationMAC("audit-v1", bytes.Repeat([]byte{1}, 32), "accounts-v1", bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(keys.Close)
	service, e := liveapp.New(liveapp.Config{RootID: peer.pin.RootID, OwnerID: binding.ProcessEpoch, Keys: keys, Now: time.Now, NewID: func() string { return observationForwardID(500 + int(facts.count.Add(1))) }, Limits: v.DefaultLimits(), MaxWatches: 10, MaxControls: 40}, facts, facts, facts)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(service.Close)
	current := &liveOwnerIdentityFixture{i: identity.Identity{Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "viewer", ClientID: "console", Kind: identity.Human}, Scopes: []string{"evidence:read"}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(time.Minute)}}
	page, _, e := service.List(t.Context(), current, targets.WorkloadRequest{ClusterID: runtimeID, Namespace: "ns", Kind: "Deployment", Name: "workload"}, "", 20)
	if e != nil || len(page.Sources) != count {
		t.Fatal(page, e)
	}
	request := v.Open{Projection: v.Packet, Key: "open", Filter: v.Filter{All: []v.Predicate{}}}
	for _, s := range page.Sources {
		request.Handles = append(request.Handles, s.Handle)
	}
	watch, e := service.Open(t.Context(), current, request)
	if e != nil {
		t.Fatal(e)
	}
	root, cancel := context.WithCancel(t.Context())
	runtime := &OwnerRuntime{root: root, binding: peer.client, pool: peer.pin.Pool, roots: peer.base.roots, client: old.client}
	forward := &liveOwnerForwarder{runtime: runtime, root: root, cancel: cancel, rootID: peer.pin.RootID, owners: old.owners, verifier: old.verifier, slots: make(chan struct{}, 2), deliveries: map[*liveOwnerDelivery]struct{}{}}
	receiver := &liveOwnerForwarder{runtime: &OwnerRuntime{root: root, binding: binding, pool: peer.pin.Pool, roots: peer.base.roots, server: serverKeys}, rootID: peer.pin.RootID, owners: old.owners, verifier: old.verifier}
	name, _ := mtls.OwnerServerName(binding)
	authority := net.JoinHostPort(name, strconv.Itoa(peer.pin.Pool.NativePort))
	handler, e := native.NewLiveOwnerHandler(authority, peer.pin.RootID, binding.ProcessEpoch, service, receiver, 2)
	if e != nil {
		t.Fatal(e)
	}
	f := &liveOwnerH2Fixture{forward: forward, facts: facts, current: current, service: service, request: request, watch: watch, peer: peer}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		defer f.joined.Add(1)
		r.Body = countedLiveBody{r.Body, &f.in}
		handler.ServeHTTP(countedLiveWriter{ResponseWriter: w, n: &f.out, wire: &f.wire, mu: &f.wireMu}, r)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{GetCertificate: serverKeys.GetCertificate, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: peer.base.roots.Clone(), MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	server.StartTLS()
	f.server = server
	f.serverKeys = serverKeys
	f.handler = handler
	forward.newClient = func(endpoint, address string, trust *tls.Config) (*mtls.LiveOwnerClient, error) {
		if address != "10.0.0.1:9444" {
			return nil, v.ErrUnavailable
		}
		original := trust.VerifyConnection
		trust.VerifyConnection = func(s tls.ConnectionState) error {
			e := original(s)
			if e != nil {
				t.Log("handshake facts", s.HandshakeComplete, s.Version, s.NegotiatedProtocol, len(s.VerifiedChains))
				t.Log("current peer admission", e)
			}
			return e
		}
		return mtls.NewLiveOwnerClient(endpoint, server.Listener.Addr().String(), trust)
	}
	t.Cleanup(func() { forward.Close(); server.Close() })
	current.calls.Store(0)
	peer.registry.Store(0)
	peer.guards.Store(0)
	peer.routes.Store(0)
	return f
}
func (f *liveOwnerH2Fixture) begin(ctx context.Context, c liveapp.Command) (liveapp.CommandDelivery, error) {
	k, e := f.service.OwnerRouteKeys(ctx, f.current, c)
	if e != nil {
		return nil, e
	}
	return f.forward.begin(ctx, f.current, c, k, f.peer.servers[0])
}

func TestLiveOwnerActualH2CurrentIdentityAndJoinedDelivery(t *testing.T) {
	for _, count := range []int{1, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := newLiveOwnerH2Fixture(t, count)
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			started := time.Now()
			d, e := f.begin(ctx, liveapp.Command{Read: &v.Read{ID: f.watch.ID, Cursor: *f.watch.Cursor}})
			if e != nil {
				f.wireMu.Lock()
				raw := bytes.Clone(f.wire.Bytes())
				f.wireMu.Unlock()
				reader := bytes.NewReader(raw)
				for reader.Len() > 0 {
					frame, err := contracts.ReadNativeFrame(reader)
					if err != nil {
						break
					}
					var decoded map[string]any
					_ = json.Unmarshal(frame.Payload, &decoded)
					t.Log("response frame", decoded)
				}
				t.Fatal("forwarded read", e, "requests", f.requests.Load(), "identities", f.current.calls.Load(), "reads", f.facts.reads.Load(), "in/out", f.in.Load(), f.out.Load())
			}
			result := d.Result()
			if result.Batch == nil || len(result.Batch.Rows) != count || result.Batch.DisclosureUntil.IsZero() || d.CheckDisclosure(ctx) != nil {
				t.Fatal("bound result", result, d.CheckDisclosure(ctx))
			}
			if f.current.calls.Load() != 8 || f.facts.reads.Load() != 1 || f.requests.Load() != 1 {
				t.Fatal("identity callback amplification", f.current.calls.Load(), f.facts.reads.Load(), f.requests.Load())
			}
			if e = d.Close(ctx); e != nil {
				t.Fatal("joined close", e)
			}
			if len(f.forward.slots) != 0 || d.CheckDisclosure(ctx) == nil {
				t.Fatal("delivery slot or authority survives close")
			}
			if f.peer.registry.Load() != 8 {
				t.Fatal("duplicate same-phase registration observations", f.peer.registry.Load())
			}
			elapsed := time.Since(started)
			t.Logf("sources=%d callbacks=7 routeIdentity=1 requests=1 framedRequestBytes=%d framedResponseBytes=%d elapsed=%s registryObservations=%d protectionObservations=%d routeObservations=%d", count, f.in.Load(), f.out.Load(), elapsed, f.peer.registry.Load(), f.peer.guards.Load(), f.peer.routes.Load())
			// An actual same-cursor replay charges again, reuses rows and performs no read.
			f.current.calls.Store(0)
			d, e = f.begin(ctx, liveapp.Command{Read: &v.Read{ID: f.watch.ID, Cursor: *f.watch.Cursor}})
			if e != nil {
				t.Fatal("replay", e)
			}
			replay := d.Result().Batch
			if replay.ID != result.Batch.ID || replay.Spent <= result.Batch.Spent || f.facts.reads.Load() != 1 || f.current.calls.Load() != 5 {
				t.Fatal("replay effects", replay, f.facts.reads.Load(), f.current.calls.Load())
			}
			if e = d.Close(ctx); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestLiveOwnerActualH2DistinguishesSourceAndOwnerFailures(t *testing.T) {
	f := newLiveOwnerH2Fixture(t, 1)
	for _, mode := range []string{"transient", "unavailable"} {
		f.facts.transient = mode == "transient"
		f.facts.unavailable = mode == "unavailable"
		_, err := f.begin(t.Context(), liveapp.Command{Read: &v.Read{ID: f.watch.ID, Cursor: *f.watch.Cursor}})
		if mode == "transient" && !errors.Is(err, v.ErrTransient) {
			t.Fatal("private owner forwarding lost the transient source class", err)
		}
		if !errors.Is(err, v.ErrUnavailable) || errors.Is(err, v.ErrOwnerLost) {
			t.Fatal("reachable owner error frame became owner loss", mode, err)
		}
	}
	f.facts.transient = false
	f.facts.unavailable = false
	f.server.Close()
	_, err := f.begin(t.Context(), liveapp.Command{Read: &v.Read{ID: f.watch.ID, Cursor: *f.watch.Cursor}})
	if !errors.Is(err, v.ErrOwnerLost) || !errors.Is(err, v.ErrUnavailable) {
		t.Fatal("dial failure was not marked as owner loss", err)
	}
}

func TestLiveOwnerActualH2RejectsChangedIngressAndCanceledRead(t *testing.T) {
	for _, mode := range []string{"client", "principal", "policy", "client-after-read", "expired-after-read", "cancel", "final-cutoff", "peer-revoked", "close-canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newLiveOwnerH2Fixture(t, 1)
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			switch mode {
			case "client", "principal", "policy":
				f.current.changeAt = 2
				f.current.change = func(i *identity.Identity) {
					if mode == "client" {
						i.Principal.ClientID = "mcp"
					} else if mode == "principal" {
						i.Principal.Subject = "other"
					} else {
						i.Policy.Generation++
					}
				}
			case "client-after-read", "expired-after-read":
				f.current.changeAt = 6
				f.current.change = func(i *identity.Identity) {
					if mode == "client-after-read" {
						i.Principal.ClientID = "mcp"
					} else {
						i.ValidUntil = time.Now().Add(-time.Millisecond)
					}
				}
			case "cancel":
				f.facts.block = make(chan struct{})
				f.facts.entered = make(chan struct{})
				go func() { <-f.facts.entered; cancel() }()
			case "final-cutoff":
				f.facts.afterRead = func() { f.facts.phaseUntil = time.Now().Add(-time.Millisecond) }
			case "peer-revoked":
				f.facts.afterRead = func() { f.peer.mu.Lock(); clear(f.peer.identities); f.peer.mu.Unlock() }
			}
			d, e := f.begin(ctx, liveapp.Command{Read: &v.Read{ID: f.watch.ID, Cursor: *f.watch.Cursor}})
			if mode == "close-canceled" {
				if e != nil {
					t.Fatal(e)
				}
				cancel()
				if d.Close(ctx) == nil {
					t.Fatal("canceled close acknowledged")
				}
			} else if e == nil {
				_ = d.Close(ctx)
				t.Fatal("invalid forwarded operation accepted")
			}
			if len(f.forward.slots) != 0 {
				t.Fatal("outbound slot leaked")
			}
			if (mode == "client" || mode == "principal" || mode == "policy") && f.facts.reads.Load() != 0 {
				t.Fatal("changed ingress reached source")
			}
			if mode == "client-after-read" || mode == "expired-after-read" {
				if f.facts.reads.Load() != 1 {
					t.Fatal("final current identity control did not reach source")
				}
				for _, c := range f.facts.controls {
					if c.Spent != 0 {
						t.Fatal("final identity loss charged disclosed data", c.Spent)
					}
				}
			}
			if mode == "cancel" && !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("original cancel lost")
			}
		})
	}
}

func TestLiveOwnerActualH2OpenReplayUpdateAndClose(t *testing.T) {
	f := newLiveOwnerH2Fixture(t, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	for _, op := range []string{"open-replay", "pause", "close"} {
		f.current.calls.Store(0)
		command := liveapp.Command{Open: &f.request}
		if op != "open-replay" {
			command = liveapp.Command{Update: &v.Update{ID: f.watch.ID, Revision: 1, Key: op, Mode: "Paused"}}
		}
		if op == "close" {
			command.Close = true
			command.Update.Mode = ""
			command.Update.Revision = 2
		}
		d, e := f.begin(ctx, command)
		if e != nil {
			t.Fatal(op, e)
		}
		w := d.Result().Watch
		if w == nil || w.ID != f.watch.ID || !w.ExpiresAt.Equal(f.watch.ExpiresAt) || f.current.calls.Load() != 5 || f.facts.reads.Load() != 0 || len(f.facts.controls) != 1 {
			t.Fatal("changed original control", op, w, f.current.calls.Load())
		}
		if op == "pause" && w.State != "Paused" || op == "close" && w.State != "Closed" {
			t.Fatal("wrong lifecycle", op, w)
		}
		if e = d.Close(ctx); e != nil {
			t.Fatal("joined", op, e)
		}
	}
}
func TestLiveOwnerActualH2EOFRootClosureAndBoundedSlots(t *testing.T) {
	for _, mode := range []string{"peer-EOF", "root-close", "slots", "empty-cutoff"} {
		t.Run(mode, func(t *testing.T) {
			f := newLiveOwnerH2Fixture(t, 1)
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			if mode == "empty-cutoff" {
				f.facts.empty = true
				f.facts.afterRead = func() { f.facts.phaseUntil = time.Now().Add(150 * time.Millisecond) }
			}
			cmd := liveapp.Command{Read: &v.Read{ID: f.watch.ID, Cursor: *f.watch.Cursor}}
			d, e := f.begin(ctx, cmd)
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "peer-EOF":
				f.server.CloseClientConnections()
			case "root-close":
				f.forward.Close()
			case "empty-cutoff":
				if b := d.Result().Batch; b == nil || len(b.Rows) != 0 || b.DisclosureUntil.After(f.facts.phaseUntil) {
					t.Fatal("empty batch lost original cutoff", b)
				}
			case "slots":
				second, e := f.begin(ctx, cmd)
				if e != nil {
					t.Fatal(e)
				}
				requests := f.requests.Load()
				if third, e := f.begin(ctx, cmd); !errors.Is(e, v.ErrCapacity) || third != nil || f.requests.Load() != requests {
					t.Fatal("original slots widened", third, e)
				}
				if e = d.Close(ctx); e != nil {
					t.Fatal(e)
				}
				if e = second.Close(ctx); e != nil {
					t.Fatal(e)
				}
			}
			if mode != "slots" {
				select {
				case <-d.Done():
				case <-ctx.Done():
					t.Fatal("owner loss/cutoff did not cancel disclosure", ctx.Err())
				}
				if d.CheckDisclosure(ctx) == nil {
					t.Fatal("disclosure outlived owner")
				}
				_ = d.Close(ctx)
			}
			if len(f.forward.slots) != 0 {
				t.Fatal("operation not joined before slot reuse")
			}
		})
	}
}

type liveOwnerRejectNative struct{ calls atomic.Int32 }

func (a *liveOwnerRejectNative) OpenNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (native.Conversation, error) {
	a.calls.Add(1)
	return nil, v.ErrDenied
}
func TestLiveOwnerActualSharedNativeListener(t *testing.T) {
	f := newLiveOwnerH2Fixture(t, 1)
	f.server.Close()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	name, _ := mtls.OwnerServerName(f.peer.servers[0])
	authority := net.JoinHostPort(name, "9444")
	ordinary := &liveOwnerRejectNative{}
	handler, e := native.NewHandler(contracts.NativeOwnerPath, authority, ordinary, 2)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		done <- native.ServeWithLiveOwner(f.forward.root, listener, f.peer.base.roots, f.serverKeys, handler, nil, f.handler, 2, 0)
	}()
	f.forward.newClient = func(endpoint, address string, trust *tls.Config) (*mtls.LiveOwnerClient, error) {
		if address != "10.0.0.1:9444" {
			return nil, v.ErrUnavailable
		}
		return mtls.NewLiveOwnerClient(endpoint, listener.Addr().String(), trust)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	d, e := f.begin(ctx, liveapp.Command{Read: &v.Read{ID: f.watch.ID, Cursor: *f.watch.Cursor}})
	if e != nil {
		f.forward.Close()
		<-done
		t.Fatal("actual shared native listener", e)
	}
	if b := d.Result().Batch; b == nil || len(b.Rows) != 1 || b.Cursor == "" || b.Rows[0].Packet == nil {
		t.Fatal("private typed result", b)
	}
	if e = d.Close(ctx); e != nil {
		t.Fatal("native listener done", e)
	}
	f.forward.Close()
	if e = <-done; !errors.Is(e, context.Canceled) {
		t.Fatal("native listener did not join", e)
	}
	if ordinary.calls.Load() != 0 || len(f.forward.slots) != 0 {
		t.Fatal("purpose fallback or slot leak", ordinary.calls.Load())
	}
}

func TestLiveOwnerActualH2OriginalCommandOutlivesHelloPrelude(t *testing.T) {
	f := newLiveOwnerH2Fixture(t, 1)
	f.facts.delay = 2200 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	d, e := f.begin(ctx, liveapp.Command{Read: &v.Read{ID: f.watch.ID, Cursor: *f.watch.Cursor}})
	if e != nil {
		t.Fatal("healthy operation within original deadline lost after Hello prelude", e)
	}
	if b := d.Result().Batch; b == nil || len(b.Rows) != 1 || d.CheckDisclosure(ctx) != nil {
		t.Fatal("missing original delayed result", b)
	}
	if e = d.Close(ctx); e != nil {
		t.Fatal("original delayed operation not joined", e)
	}
}
