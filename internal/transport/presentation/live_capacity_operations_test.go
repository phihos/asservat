package presentation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
)

type liveCapacityOpsFixture struct {
	now      time.Time
	snapshot collector.LiveRuntimeSnapshot
	err      error
	cluster  string
}

func (f *liveCapacityOpsFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "admin", ClientID: "console", Kind: identity.Human}, Groups: []string{"platform-admins"}, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: f.now, ValidUntil: f.now.Add(30 * time.Second)}, nil
}
func (f *liveCapacityOpsFixture) Read(_ context.Context, _ identities.CurrentIdentity, cluster string) (collector.LiveRuntimeSnapshot, time.Time, error) {
	f.cluster = cluster
	return f.snapshot, f.now.Add(5 * time.Second), f.err
}

func TestLiveCapacityOperationReturnsCanonicalSingleClusterView(t *testing.T) {
	f := &liveCapacityOpsFixture{now: time.Now().UTC().Truncate(time.Microsecond)}
	const cluster = "22222222-3333-4444-8555-666666666666"
	f.snapshot = collector.LiveRuntimeSnapshot{ActiveViewers: 3, ClusterID: cluster, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second), Nodes: 2, RatesComplete: true,
		Live:  &collector.LiveActivity{Cohorts: 3, ScanEvents: 20, ScanBytes: 200, ScanCPUNanos: 3000, DeliveredRows: 4, DeliveredBytes: 400, RefusedAdmissions: 2, LostEvents: 6, DroppedRows: 3, PendingRows: 5},
		Rates: collector.LiveActivityRates{ScanEventsPerSecond: 2.5, ScanBytesPerSecond: 50, ScanCPUNanosPerSecond: 1000, DeliveredRowsPerSecond: 0.5, DeliveredBytesPerSecond: 20, RefusedAdmissionsPerSecond: 1, LostEventsPerSecond: 2, DroppedRowsPerSecond: 0.5}}
	ops, err := NewLiveCapacityOperations("https://asservat.example.invalid", func() time.Time { return f.now }, func() string { return "00000000-0000-4000-8000-000000000042" }, f)
	if err != nil {
		t.Fatal(err)
	}
	routed, err := NewInvestigationLiveCapacityOperations(&InvestigationOperations{origin: "https://asservat.example.invalid"}, ops)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := routed.Call(context.Background(), f, "get_live_capacity", json.RawMessage(`{"cluster_id":"`+cluster+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Body) > contracts.InvestigationOutputLimit {
		t.Fatal("oversized capacity reply", len(reply.Body))
	}
	var out map[string]any
	if json.Unmarshal(reply.Body, &out) != nil || out["status"] != "ok" || f.cluster != cluster {
		t.Fatal(out, f.cluster, err)
	}
	data := out["data"].(map[string]any)
	live := data["live"].(map[string]any)
	rates := data["rates"].(map[string]any)
	if data["active_viewers"] != 3.0 || data["cluster_id"] != cluster || data["rates_complete"] != true || live["scan_events"] != 20.0 || live["scan_cpu_nanos"] != 3000.0 || live["lost_events"] != 6.0 || live["dropped_rows"] != 3.0 || live["pending_rows"] != 5.0 || rates["scan_events_per_second"] != 2.5 || rates["lost_events_per_second"] != 2.0 || rates["dropped_rows_per_second"] != 0.5 || data["fresh_until"] == nil {
		t.Fatal(out)
	}
	forbidden := map[string]bool{"podUID": true, "nodeName": true, "node-uid": true, "sourceID": true, "principal": true, "filter": true, "payload": true, "scanEvents": true}
	var checkKeys func(map[string]any)
	checkKeys = func(object map[string]any) {
		for key, value := range object {
			if forbidden[key] {
				t.Fatal("content label in capacity reply", key)
			}
			if nested, ok := value.(map[string]any); ok {
				checkKeys(nested)
			}
		}
	}
	checkKeys(data)
	tool, ok := ops.Tool("get_live_capacity")
	if !ok || tool.MCP() {
		t.Fatal("administrator operation exposed through MCP", tool)
	}
	f.snapshot.RatesComplete = false
	f.snapshot.RatesUnavailable = 1
	f.snapshot.Rates = collector.LiveActivityRates{}
	reply, err = ops.Call(context.Background(), f, "get_live_capacity", json.RawMessage(`{"cluster_id":"`+cluster+`"}`))
	if err != nil || !strings.Contains(string(reply.Body), "rates are unavailable") {
		t.Fatal("incomplete rates not explained", string(reply.Body), err)
	}
	f.err = identity.ErrDenied
	reply, err = ops.Call(context.Background(), f, "get_live_capacity", json.RawMessage(`{"cluster_id":"`+cluster+`"}`))
	if err != nil || !strings.Contains(string(reply.Body), "AdministratorRequired") || !reply.ValidUntil.Equal(f.now.Add(time.Second)) {
		t.Fatal("authority failure or short error freshness not mapped", string(reply.Body), reply.ValidUntil, err)
	}
	f.err = liveapp.ErrClusterUnknown
	reply, err = ops.Call(context.Background(), f, "get_live_capacity", json.RawMessage(`{"cluster_id":"`+cluster+`"}`))
	if err != nil || !strings.Contains(string(reply.Body), "UnknownCluster") || !reply.ValidUntil.Equal(f.now.Add(time.Second)) {
		t.Fatal("unknown cluster not distinguished", string(reply.Body), reply.ValidUntil, err)
	}
}
