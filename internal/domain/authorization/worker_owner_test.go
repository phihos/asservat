package authorization

import (
	"encoding/json"
	"testing"
	"time"
)

func TestWorkerOwnerLeaseEqualityPreservesWireIdentity(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	now := time.Now()
	l := WorkerOwnerLease{Request: WorkerOwnerRequest{ID: id, InstallationID: id, SessionID: id, WorkerID: id, PodUID: id, ProcessEpoch: id, Until: now.Add(time.Second)}, Fence: 2, Started: now}
	b, _ := json.Marshal(l)
	var wire WorkerOwnerLease
	if json.Unmarshal(b, &wire) != nil || !l.Equal(wire) {
		t.Fatal("wire roundtrip lost owner")
	}
	wire.Started = wire.Started.In(time.FixedZone("test", 3600))
	if !l.Equal(wire) {
		t.Fatal("location changed instant")
	}
	wire.Fence++
	if l.Equal(wire) {
		t.Fatal("fence ignored")
	}
	wire.Fence--
	wire.Request.Until = wire.Request.Until.Add(time.Nanosecond)
	if l.Equal(wire) {
		t.Fatal("expiry ignored")
	}
}
