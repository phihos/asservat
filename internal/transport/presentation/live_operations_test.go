package presentation

import (
	app "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

type liveBoundary struct {
	source   v.Source
	now      time.Time
	rows     []v.Row
	controls map[string]app.Control
	reads    int
}

func (f *liveBoundary) Inventory(context.Context, app.CurrentIdentity, targets.WorkloadRequest, string, int) ([]v.Source, string, error) {
	return []v.Source{f.source}, "", nil
}
func (f *liveBoundary) Check(context.Context, app.CurrentIdentity, v.Source, string) (v.Source, time.Time, error) {
	return f.source, f.now.Add(5 * time.Second), nil
}
func (f *liveBoundary) Head(context.Context, []v.Source, string) ([]v.Position, error) {
	return []v.Position{{}}, nil
}
func (f *liveBoundary) Read(context.Context, []v.Source, string, []v.Position, int, int, int) (app.Projection, error) {
	f.reads++
	return app.Projection{Rows: f.rows, Positions: []v.Position{{Sequence: 1}}, Sources: []v.SourceStatus{}, Gaps: []v.Gap{}, Examined: 1, Bytes: 100}, nil
}
func (f *liveBoundary) Create(_ context.Context, _ string, c app.Control, _ string) (app.Control, bool, error) {
	f.controls[c.ID] = c
	return c, false, nil
}
func (f *liveBoundary) Change(_ context.Context, c app.Control, _ int64, _ int64) (app.Control, error) {
	f.controls[c.ID] = c
	return c, nil
}
func liveBoundaryFixture(t *testing.T) (*AuditedOperations, *contextOperationFixture, *presentationAuditGate, *liveBoundary) {
	t.Helper()
	a, actor, gate := auditedFixture(t)
	now := a.config.Now()
	id := "11111111-1111-4111-8111-111111111111"
	b := collector.SourceBinding{RootID: id, AcceptanceID: id, SourceID: id, Fence: id, PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, PolicyUID: "policy", ActionID: "packets", Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}}
	f := &liveBoundary{now: now, source: v.Source{Binding: b, Target: authorization.Target{ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: id}, OwnerKind: "policy", OwnerID: "policy", State: "Ready", SaveVia: "recordingSave", Projections: []string{v.Packet}, LeaseUntil: now.Add(30 * time.Second), HardUntil: now.Add(time.Hour), PrivacyUntil: now.Add(time.Hour)}, controls: map[string]app.Control{}}
	n := 100
	newID := func() string { n++; return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
	s, e := app.New(app.Config{RootID: id, OwnerID: id, Keys: a.mac, Now: a.config.Now, NewID: newID, Limits: v.DefaultLimits(), MaxWatches: 10, MaxControls: 40}, f, f, f)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	ops, e := NewLiveOperations(a.PublicOrigin(), s, a.config.Now)
	if e != nil {
		t.Fatal(e)
	}
	base, e := NewInvestigationLiveOperations(a.inner.(*InvestigationOperations), ops)
	if e != nil {
		t.Fatal(e)
	}
	a.inner = base
	a.config.NewID = newID
	return a, actor, gate, f
}
func TestLiveAuditedPublicOpenReadCloseOwnsTransientBytes(t *testing.T) {
	a, actor, gate, f := liveBoundaryFixture(t)
	r, e := a.Call(t.Context(), actor, "list_live_sources", []byte(`{`+wireTarget+`}`))
	if e != nil {
		t.Fatal(e)
	}
	var page struct {
		Data v.SourcePage `json:"data"`
	}
	if json.Unmarshal(r.Body, &page) != nil || len(page.Data.Sources) != 1 {
		t.Fatal(string(r.Body))
	}
	input, _ := json.Marshal(v.Open{Handles: []string{page.Data.Sources[0].Handle}, Projection: v.Packet, Key: "open"})
	r, e = a.Call(t.Context(), actor, "open_live_watch", input)
	if e != nil {
		t.Fatal(e)
	}
	var opened struct {
		Data v.Watch `json:"data"`
	}
	if json.Unmarshal(r.Body, &opened) != nil || opened.Data.Cursor == nil {
		t.Fatal(string(r.Body))
	}
	w := opened.Data
	f.rows = []v.Row{{ID: "source:1", SourceID: f.source.Binding.SourceID, Sequence: 1, ObservedAt: f.now, ReceivedAt: f.now, ExpiresAt: f.now.Add(30 * time.Second), Projection: v.Packet, PodUID: f.source.Target.PodUID, Packet: &v.PacketFields{Protocol: "TCP", RemoteIP: "192.0.2.1", RemotePort: 0, Direction: "unknown", WireBytes: 64}}}
	input, _ = json.Marshal(v.Read{ID: w.ID, Cursor: *w.Cursor})
	r, e = a.Call(t.Context(), actor, "read_live_watch", input)
	if e != nil {
		t.Fatal(e)
	}
	if r.owner == nil || f.reads != 1 || len(gate.outcomes) != 3 || gate.outcomes[2].Effect != "accepted" {
		t.Fatal("missing audited transient owner", f.reads, gate.outcomes)
	}
	if e = r.CheckDisclosure(t.Context()); e != nil {
		t.Fatal(e)
	}
	body := r.Body
	if e = r.Close(t.Context()); e != nil {
		t.Fatal(e)
	}
	for _, b := range body {
		if b != 0 {
			t.Fatal("transient response retained after join")
		}
	}
	input, _ = json.Marshal(v.Update{ID: w.ID, Revision: 1, Key: "close"})
	if _, e = a.Call(t.Context(), actor, "close_live_watch", input); e != nil {
		t.Fatal(e)
	}
	if actor.requests != 0 {
		t.Fatal("live operation acquired evidence")
	}
}
func TestLiveAuditInputBindsFilterAndNoPreAuditSourceReads(t *testing.T) {
	a, actor, gate, f := liveBoundaryFixture(t)
	first := []byte(`{"source_handles":["source"],"projection":"packetMetadata","display_filter":{"all":[{"field":"port","op":"eq","value":0}]},"idempotency_key":"k"}`)
	second := []byte(`{"source_handles":["source"],"projection":"packetMetadata","display_filter":{"all":[{"field":"port","op":"eq","value":1}]},"idempotency_key":"k"}`)
	x, e := a.normalize("open_live_watch", first)
	if e != nil {
		t.Fatal(e)
	}
	y, e := a.normalize("open_live_watch", second)
	if e != nil || string(x) == string(y) {
		t.Fatal("filter omitted from keyed audit input", e)
	}
	gate.beginFail = true
	if _, e = a.Call(t.Context(), actor, "list_live_sources", []byte(`{`+wireTarget+`}`)); e == nil || f.reads != 0 || len(f.controls) != 0 {
		t.Fatal("effect before audit")
	}
}

func (f *liveBoundary) CurrentLive(_ context.Context, c app.Control) error {
	old, ok := f.controls[c.ID]
	if !ok || old.Fence != c.Fence || old.Revision != c.Revision {
		return v.ErrDenied
	}
	return nil
}

func (f *liveBoundary) Resolve(context.Context, app.CurrentIdentity, string, string, string) (v.Source, time.Time, error) {
	return f.source.Clone(), f.now.Add(5 * time.Second), nil
}
