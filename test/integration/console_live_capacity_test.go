package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

type consoleCurrentIdentity struct{ value identity.Identity }

func (c consoleCurrentIdentity) ResolveIdentity(context.Context) (identity.Identity, error) {
	return c.value, nil
}

type consoleLiveCapacity struct{}

func (c *consoleLiveCapacity) Read(_ context.Context, _ app.CurrentIdentity, cluster string) (collector.LiveRuntimeSnapshot, time.Time, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return collector.LiveRuntimeSnapshot{ActiveViewers: 3, ClusterID: cluster, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Nodes: 2, RatesComplete: true,
		Live:  &collector.LiveActivity{Cohorts: 3, ScanEvents: 20, ScanBytes: 200, ScanCPUNanos: 3000, DeliveredRows: 4, DeliveredBytes: 400, RefusedAdmissions: 2, LostEvents: 6, DroppedRows: 3, PendingRows: 5},
		Rates: collector.LiveActivityRates{ScanEventsPerSecond: 2.5, ScanBytesPerSecond: 50, ScanCPUNanosPerSecond: 1000, DeliveredRowsPerSecond: 0.5, DeliveredBytesPerSecond: 20, RefusedAdmissionsPerSecond: 1, LostEventsPerSecond: 2, DroppedRowsPerSecond: 0.5}}, now.Add(5 * time.Second), nil
}

func newConsoleLiveCapacityOperations(t *testing.T, origin string) *presentation.LiveCapacityOperations {
	t.Helper()
	service := &consoleLiveCapacity{}
	operations, err := presentation.NewLiveCapacityOperations(origin, time.Now, func() string { return consoleCaptureID(503) }, service)
	if err != nil {
		t.Fatal(err)
	}
	return operations
}

func TestConsoleLiveCapacityUsesCurrentSessionIdentity(t *testing.T) {
	const origin = "https://asservat.example.invalid"
	sessions := &consoleSyntheticSessions{origin: origin, state: "ready", expiresAt: time.Now().Add(time.Minute)}
	view, err := sessions.Resolve(context.Background(), strings.Repeat("A", 43), false)
	if err != nil {
		t.Fatal(err)
	}
	captureService := &consoleSyntheticCaptures{state: "ready"}
	baseCaptures, err := presentation.NewContextOperationsWithHistory(presentation.ContextOperationsConfig{PublicOrigin: origin, CollectionEnabled: true, Now: time.Now, NewID: func() string { return consoleCaptureID(500) }}, captureService, captureService, &consoleSyntheticHistory{captures: captureService})
	if err != nil {
		t.Fatal(err)
	}
	caseOperations, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: func() string { return consoleCaptureID(501) }}, &consoleSyntheticCases{state: "ready", expiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	base, err := presentation.NewInvestigationOperations(baseCaptures, caseOperations)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := presentation.NewInvestigationLiveCapacityOperations(base, newConsoleLiveCapacityOperations(t, origin))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := operations.Call(context.Background(), consoleCurrentIdentity{view.Identity}, "get_live_capacity", []byte(`{"cluster_id":"00000000-0000-4000-8000-000000000001"}`))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if json.Unmarshal(reply.Body, &out) != nil || out["status"] != "ok" {
		t.Fatal(string(reply.Body))
	}
}
