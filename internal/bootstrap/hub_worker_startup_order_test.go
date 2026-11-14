package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

// The first-run hub-worker logged one-off failures from children that started
// before the capacity child had made the permission stream and setup rows
// current. They now wait for it.
func TestHubWorkerAwaitCapacityWaitsForStoreID(t *testing.T) {
	w := &hubWorker{config: contracts.HubWorkerConfig{Capacity: &contracts.HubWorkerCapacity{}}, root: context.Background()}
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if w.awaitCapacity(short) {
		t.Fatal("awaitCapacity returned before the capacity child started")
	}
	done := make(chan bool, 1)
	go func() { done <- w.awaitCapacity(context.Background()) }()
	if err := w.publishEvidenceStoreID("30000000-0000-4000-8000-000000000007"); err != nil {
		t.Fatal(err)
	}
	// A repeated equal publication must not close the signal twice.
	if err := w.publishEvidenceStoreID("30000000-0000-4000-8000-000000000007"); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("awaitCapacity refused after the capacity child started")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("awaitCapacity did not observe the capacity start")
	}
	if none := (&hubWorker{}); !none.awaitCapacity(context.Background()) {
		t.Fatal("without a capacity section there is nothing to wait for")
	}
}

func TestHubWorkerCleanupStartsAfterCapacity(t *testing.T) {
	w := cleanupTestWorker()
	w.config.Capacity = &contracts.HubWorkerCapacity{}
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	// The test worker has no inputs, so an open attempt fails at once with a
	// configuration error; waiting instead proves no attempt was made.
	if err := w.runCleanup(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cleanup before capacity: %v, want it to wait", err)
	}
	if err := w.publishEvidenceStoreID("30000000-0000-4000-8000-000000000007"); err != nil {
		t.Fatal(err)
	}
	var config *cleanupConfigError
	if err := w.runCleanup(context.Background()); !errors.As(err, &config) {
		t.Fatalf("cleanup after capacity: %v, want the open attempt", err)
	}
}

func TestPermissionAwaitReadyPollsUntilReady(t *testing.T) {
	calls := 0
	ready := func() bool { calls++; return calls >= 3 }
	if !awaitReady(context.Background(), ready) || calls != 3 {
		t.Fatalf("awaitReady: calls=%d", calls)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if awaitReady(cancelled, func() bool { return false }) {
		t.Fatal("awaitReady reported ready after cancellation")
	}
	if !awaitReady(context.Background(), nil) {
		t.Fatal("a nil prerequisite is ready")
	}
}

type observeRetentionStore struct {
	app.RetentionCheckpointStore
	err error
}

func (s observeRetentionStore) ObserveRetention(context.Context, app.RetentionObservation) error {
	return s.err
}

func TestRetentionRecoveryLoggedOnceAfterFailure(t *testing.T) {
	var out bytes.Buffer
	recovery := &retentionRecovery{out: &out}
	ok := stagedRetentionStore{observeRetentionStore{}, recovery}
	if err := ok.ObserveRetention(context.Background(), app.RetentionObservation{}); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("logged recovery without a failure: %q", out.String())
	}
	recovery.fail()
	failing := stagedRetentionStore{observeRetentionStore{err: errors.New("down")}, recovery}
	if err := failing.ObserveRetention(context.Background(), app.RetentionObservation{}); err == nil {
		t.Fatal("failure hidden")
	}
	if out.Len() != 0 {
		t.Fatalf("a failed observation logged recovery: %q", out.String())
	}
	for range 2 {
		if err := ok.ObserveRetention(context.Background(), app.RetentionObservation{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := out.String(); got != "hub-worker retention: source observation ok\n" {
		t.Fatalf("recovery log %q, want one line", got)
	}
}

func TestContextDeletionRecoveryAfterPrepareFailure(t *testing.T) {
	failed := map[artifact.Location]string{{}: "prepare evidence-store-id (unavailable)"}
	if !contextDeletionRecovered(failed, map[artifact.Location]string{}) {
		t.Fatal("recovery after a failed prepare not reported")
	}
	if contextDeletionRecovered(failed, failed) || contextDeletionRecovered(map[artifact.Location]string{}, map[artifact.Location]string{}) {
		t.Fatal("recovery reported without a change")
	}
}
