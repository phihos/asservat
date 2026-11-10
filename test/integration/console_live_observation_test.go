package integration

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/console"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/browser"
	mcptransport "asservat.local/asservat/internal/transport/mcp"
	"asservat.local/asservat/internal/transport/presentation"
	"context"
	"encoding/json"
	"fmt"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Explicit synthetic current-source authority and ledger; the real C13 service,
// canonical C20/audit delivery, sessions, TLS, SDK and compiled React run below.
// No SQL, node transport, acquisition or source clock qualification is claimed.
type consoleLiveFixture struct {
	mu                      sync.Mutex
	sources                 []v.Source
	rows                    map[string][]v.Row
	controls                map[string]app.Control
	keys                    map[string]string
	heads, reads, created   int
	auditBegin, auditFinish int
}

func (f *consoleLiveFixture) Configured() bool { return true }
func (f *consoleLiveFixture) Begin(_ context.Context, _ audit.OperationIntent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auditBegin++
	return nil
}
func (f *consoleLiveFixture) Finish(_ context.Context, _ audit.OperationOutcome) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auditFinish++
	return nil
}
func (f *consoleLiveFixture) allowed(ctx context.Context, current app.CurrentIdentity) error {
	i, e := current.ResolveIdentity(ctx)
	if e != nil || !i.Valid(time.Now()) || !slices.Contains(i.Scopes, "evidence:read") || !slices.Contains(i.Groups, "maintainers") {
		return v.ErrDenied
	}
	return nil
}
func (f *consoleLiveFixture) Inventory(ctx context.Context, current app.CurrentIdentity, _ targets.WorkloadRequest, _ string, _ int) ([]v.Source, string, error) {
	if e := f.allowed(ctx, current); e != nil {
		return nil, "", e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]v.Source, len(f.sources))
	for n, s := range f.sources {
		out[n] = s.Clone()
	}
	return out, "", nil
}
func (f *consoleLiveFixture) Resolve(ctx context.Context, current app.CurrentIdentity, id, kind, projection string) (v.Source, time.Time, error) {
	f.mu.Lock()
	var found v.Source
	for _, s := range f.sources {
		if s.ID() == id && s.OwnerKind == kind {
			found = s.Clone()
		}
	}
	f.mu.Unlock()
	return f.Check(ctx, current, found, projection)
}
func (f *consoleLiveFixture) Check(ctx context.Context, current app.CurrentIdentity, expected v.Source, projection string) (v.Source, time.Time, error) {
	if e := f.allowed(ctx, current); e != nil {
		return v.Source{}, time.Time{}, e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sources {
		if s.Same(expected) && s.Valid(time.Now()) && (projection == "" || slices.Contains(s.Projections, projection)) {
			return s.Clone(), time.Now().Add(5 * time.Second), nil
		}
	}
	return v.Source{}, time.Time{}, v.ErrDenied
}
func (f *consoleLiveFixture) Head(_ context.Context, sources []v.Source, _ string) ([]v.Position, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heads++
	out := make([]v.Position, len(sources))
	for n, s := range sources {
		out[n].Sequence = uint64(len(f.rows[s.ID()]))
	}
	return out, nil
}
func (f *consoleLiveFixture) Read(_ context.Context, sources []v.Source, _ string, positions []v.Position, limit, scan, wait int) (app.Projection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	out := app.Projection{Rows: []v.Row{}, Sources: []v.SourceStatus{}, Gaps: []v.Gap{}, Positions: append([]v.Position(nil), positions...)}
	for n, s := range sources {
		rows := f.rows[s.ID()]
		out.Positions[n].Sequence = uint64(len(rows))
		for _, r := range rows {
			if r.Sequence > positions[n].Sequence && len(out.Rows) < limit {
				copy := r.Clone()
				copy.ReceivedAt = time.Now()
				out.Rows = append(out.Rows, copy)
				out.Examined++
				out.Bytes += int64(copy.Bytes())
			}
		}
		out.Sources = append(out.Sources, v.SourceStatus{ID: s.ID(), State: s.State, Coverage: "partial"})
		id := s.ID()
		out.Gaps = append(out.Gaps, v.Gap{Reason: "sensorLoss", SourceID: &id, From: time.Now(), Until: time.Now()})
	}
	return out, nil
}
func (f *consoleLiveFixture) CurrentLive(_ context.Context, c app.Control) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.controls[c.ID] != c {
		return v.ErrDenied
	}
	return nil
}
func (f *consoleLiveFixture) Create(_ context.Context, _ string, c app.Control, key string) (app.Control, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.keys[key]; ok {
		return f.controls[id], true, nil
	}
	f.created++
	f.controls[c.ID] = c
	f.keys[key] = c.ID
	return c, false, nil
}
func (f *consoleLiveFixture) Change(_ context.Context, c app.Control, revision, cost int64) (app.Control, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	old, ok := f.controls[c.ID]
	if !ok || old.Revision != revision || old.Fence != c.Fence || c.Spent != old.Spent+cost || c.Spent > c.OutputLimit {
		return app.Control{}, v.ErrDenied
	}
	f.controls[c.ID] = c
	return c, nil
}
func (f *consoleLiveFixture) emit(projection string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sources {
		if !slices.Contains(s.Projections, projection) {
			continue
		}
		now := time.Now()
		r := v.Row{ID: fmt.Sprintf("%s:%d", s.ID(), len(f.rows[s.ID()])+1), SourceID: s.ID(), PodUID: s.Pod(), Sequence: uint64(len(f.rows[s.ID()]) + 1), Projection: projection, ObservedAt: now, ReceivedAt: now, ExpiresAt: now.Add(30 * time.Second)}
		switch projection {
		case v.Packet:
			r.Packet = &v.PacketFields{Protocol: "TCP", RemoteIP: "192.0.2.1", RemotePort: 0, Direction: "unknown", WireBytes: 0}
		case v.HTTP:
			r.HTTP = &v.HTTPFields{Method: "GET", Headers: []v.Header{{Name: "content-type", Value: "text/plain"}}, Pairing: "request"}
		case v.Syscall:
			r.Syscall = &v.SyscallFields{PID: 1, Name: "read", Error: false, Paired: false}
		}
		f.rows[s.ID()] = append(f.rows[s.ID()], r)
	}
}
func newConsoleLive(t *testing.T, origin string) (*presentation.AuditedOperations, *consoleLiveFixture) {
	t.Helper()
	f := &consoleLiveFixture{rows: map[string][]v.Row{}, controls: map[string]app.Control{}, keys: map[string]string{}}
	now := time.Now()
	for n, p := range []string{v.Packet, v.HTTP, v.Syscall} {
		id := consoleCaptureID(700 + n)
		b := collector.SourceBinding{RootID: consoleCaptureID(1), AcceptanceID: consoleCaptureID(2), SourceID: id, Fence: consoleCaptureID(3), PodUID: consoleCaptureID(4), NodeUID: consoleCaptureID(5), BootID: consoleCaptureID(6), CollectorPodUID: consoleCaptureID(7), CollectorEpoch: consoleCaptureID(8), PolicyUID: "synthetic-policy", ActionID: p, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}}
		f.sources = append(f.sources, v.Source{Binding: b, Target: authorization.Target{ClusterID: consoleCaptureID(1), NamespaceUID: "ns", WorkloadUID: "workload", PodUID: b.PodUID}, OwnerKind: "policy", OwnerID: b.PolicyUID, State: "Ready", SaveVia: "recordingSave", Projections: []string{p}, Blockers: []string{}, LeaseUntil: now.Add(2 * time.Minute), HardUntil: now.Add(2 * time.Minute), PrivacyUntil: now.Add(2 * time.Minute)})
	}
	m := collector.ManualLiveSource{RootID: consoleCaptureID(1), CaptureID: consoleCaptureID(750), AttemptID: consoleCaptureID(2), ActionID: "finite-packets", WorkID: consoleCaptureID(3), ExecutorPodUID: consoleCaptureID(9), ExecutorEpoch: consoleCaptureID(10), PodUID: consoleCaptureID(4), NodeUID: consoleCaptureID(5), BootID: consoleCaptureID(6), CollectorPodUID: consoleCaptureID(7), CollectorEpoch: consoleCaptureID(8), Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, StartedAt: now, HardUntil: now.Add(2 * time.Minute)}
	f.sources = append(f.sources, v.Source{RootID: m.RootID, Manual: &m, Target: f.sources[0].Target, OwnerKind: "manualSession", OwnerID: m.CaptureID, State: "Ready", SaveVia: "captureOutcome", Projections: []string{v.Packet}, Blockers: []string{}, LeaseUntil: m.HardUntil, HardUntil: m.HardUntil, PrivacyUntil: m.HardUntil})
	key := make([]byte, 32)
	key[0] = 1
	accountKey := make([]byte, 32)
	accountKey[0] = 2
	mac, e := auditapp.NewOperationMAC("fixture", key, "fixture", accountKey)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(mac.Close)
	var next atomic.Int64
	next.Store(1000)
	newID := func() string { return consoleCaptureID(int(next.Add(1))) }
	service, e := app.New(app.Config{RootID: consoleCaptureID(1), OwnerID: consoleCaptureID(9), Keys: mac, Now: time.Now, NewID: newID, Limits: v.DefaultLimits(), MaxWatches: 10, MaxControls: 40}, f, f, f)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(service.Close)
	liveOps, e := presentation.NewLiveOperations(origin, service, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	captures := &consoleSyntheticCaptures{state: "ready"}
	capture, e := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: newID}, captures, captures)
	if e != nil {
		t.Fatal(e)
	}
	base, e := presentation.NewInvestigationOperations(capture, nil)
	if e != nil {
		t.Fatal(e)
	}
	base, e = presentation.NewInvestigationLiveOperations(base, liveOps)
	if e != nil {
		t.Fatal(e)
	}
	out, e := presentation.NewHealthyAuditedOperations(presentation.AuditedOperationsConfig{RootID: consoleCaptureID(1), Retention: time.Hour, NormalConcurrency: 4, ResolutionConcurrency: 2, PerPrincipalConcurrency: 4, NormalPerSecond: 100, ResolutionPerSecond: 100, Now: time.Now, NewID: newID}, base, f, f, mac)
	if e != nil {
		t.Fatal(e)
	}
	return out, f
}

func TestConsoleLiveObservationWithBuiltPackage(t *testing.T) {
	if os.Getenv("ASSERVAT_CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("set ASSERVAT_CONSOLE_BROWSER_TEST=1 after building web/dist")
	}
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	origin := "https://" + server.Listener.Addr().String()
	static, e := console.New(origin, os.DirFS(filepath.Join(root, "web", "dist")))
	if e != nil {
		t.Fatal(e)
	}
	sessions := &consoleSyntheticSessions{origin: origin, state: "revoked", expiresAt: time.Now().Add(2 * time.Minute)}
	sh := browser.SessionHandler{Origin: origin, Issuer: "https://identity.invalid", Sessions: sessions}
	ops, f := newConsoleLive(t, origin)
	bh, e := browser.NewAuditedInvestigationHandler(sh, ops, 4)
	if e != nil {
		t.Fatal(e)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/test/live-event":
			if r.Method != "POST" || r.Header.Get("Origin") != origin {
				w.WriteHeader(403)
				return
			}
			var in struct {
				Projection string `json:"projection"`
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 256)).Decode(&in) != nil || !v.Projection(in.Projection) {
				w.WriteHeader(400)
				return
			}
			f.emit(in.Projection)
			w.WriteHeader(204)
		case strings.HasPrefix(r.URL.Path, "/test/"):
			sessions.control(w, r)
		case r.URL.Path == "/api/v1/session" || strings.HasPrefix(r.URL.Path, "/auth/"):
			sh.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/api/v1/operations/"):
			bh.ServeHTTP(w, r)
		default:
			static.ServeHTTP(w, r)
		}
	})
	server.StartTLS()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", filepath.Join(root, "web/scripts/live-observation-browser.mjs"), origin)
	cmd.Dir = root
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	var output consoleBoundedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Run(); e != nil {
		t.Fatalf("actual React live observation: %v\n%s", e, output.String())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.created != 4 || f.reads < 3 || f.auditBegin != f.auditFinish {
		t.Fatal("unexpected composed effects", f.created, f.reads, f.auditBegin, f.auditFinish)
	}
	for _, c := range f.controls {
		if c.State != "Closed" || c.Spent <= 0 {
			t.Fatal("watch not closed and charged", c)
		}
	}
	t.Log(output.String())
}

type consoleLiveResolver struct{}

func (consoleLiveResolver) Resolve(_ context.Context, token string) (identity.Identity, error) {
	if token != "synthetic-logs-token" {
		return identity.Identity{}, identity.ErrDenied
	}
	now := time.Now()
	return identity.Identity{Principal: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic-developer", ClientID: "mcp", Kind: identity.Human}, Scopes: []string{"evidence:read"}, Groups: []string{"maintainers"}, Policy: identity.Revision{UID: "synthetic-policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}, nil
}
func TestLiveObservationOfficialMCPBoundary(t *testing.T) {
	var handler *mcptransport.Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	ops, f := newConsoleLive(t, server.URL)
	var e error
	handler, e = mcptransport.NewAuditedContextHandler(mcptransport.Config{PublicOrigin: server.URL, Issuer: "https://identity.invalid", Version: "fixture", MaxConcurrent: 4, MaxPerIdentity: 2}, consoleLiveResolver{}, ops)
	if e != nil {
		t.Fatal(e)
	}
	hc := *server.Client()
	hc.Transport = logsMCPBearer{hc.Transport}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	session, e := sdk.NewClient(&sdk.Implementation{Name: "live-fixture", Version: "1"}, nil).Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + mcptransport.Path, HTTPClient: &hc, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	wire, e := contracts.NewInvestigationContracts()
	if e != nil {
		t.Fatal(e)
	}
	invoke := func(name string, input any) json.RawMessage {
		t.Helper()
		out, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: input})
		if err != nil || out.IsError {
			t.Fatal(name, err, out)
		}
		raw, err := json.Marshal(out.StructuredContent)
		if err != nil || wire.ValidateOutput(name, raw) != nil {
			t.Fatalf("invalid %s: %s %v", name, raw, err)
		}
		return raw
	}
	raw := invoke("list_live_sources", map[string]any{"target_ref": map[string]string{"cluster_id": consoleCaptureID(1), "namespace": "payments", "kind": "Deployment", "name": "api"}, "limit": 20})
	var page struct {
		Data v.SourcePage `json:"data"`
	}
	if json.Unmarshal(raw, &page) != nil || len(page.Data.Sources) != 4 {
		t.Fatal(string(raw))
	}
	for n, source := range page.Data.Sources {
		p := source.Projections[0]
		raw = invoke("open_live_watch", v.Open{Handles: []string{page.Data.Sources[n].Handle}, Projection: p, Key: fmt.Sprintf("sdk-%d-%s", n, p)})
		var opened struct {
			Data v.Watch `json:"data"`
		}
		if json.Unmarshal(raw, &opened) != nil || opened.Data.Cursor == nil {
			t.Fatal(string(raw))
		}
		w := opened.Data
		f.emit(p)
		input := v.Read{ID: w.ID, Cursor: *w.Cursor}
		raw = invoke("read_live_watch", input)
		var read struct {
			Data struct {
				Rows  []json.RawMessage `json:"rows"`
				Spent int64             `json:"output_bytes_spent"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &read) != nil || len(read.Data.Rows) != 1 {
			t.Fatal(string(raw))
		}
		f.mu.Lock()
		before := f.reads
		f.mu.Unlock()
		replayed := invoke("read_live_watch", input)
		var replay struct {
			Data struct {
				Rows  []json.RawMessage `json:"rows"`
				Spent int64             `json:"output_bytes_spent"`
			} `json:"data"`
		}
		if json.Unmarshal(replayed, &replay) != nil || len(replay.Data.Rows) != 1 || string(replay.Data.Rows[0]) != string(read.Data.Rows[0]) || replay.Data.Spent <= read.Data.Spent {
			t.Fatal("replay must retain original rows and charge", string(replayed))
		}
		f.mu.Lock()
		if f.reads != before {
			t.Fatal("replay reread source")
		}
		f.mu.Unlock()
		raw = invoke("update_live_watch", v.Update{ID: w.ID, Revision: 1, Key: fmt.Sprintf("pause-%d-%s", n, p), Mode: "Paused"})
		if !strings.Contains(string(raw), `"Paused"`) {
			t.Fatal(string(raw))
		}
		raw = invoke("close_live_watch", map[string]any{"watch_id": w.ID, "expected_revision": 2, "idempotency_key": fmt.Sprintf("close-%d-%s", n, p)})
		if !strings.Contains(string(raw), `"Closed"`) {
			t.Fatal(string(raw))
		}
	}
	t.Log("all three projections and actual manual-source union over official SDK/TLS and real C13/audited C20; same-cursor replay charged without source read; explicit pause/close, synthetic authority and ledger")
}
