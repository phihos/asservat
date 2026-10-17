package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func contextMetadataFixture(t *testing.T) (*contextNativeMetadata, contextNativeMetadataKey, artifact.NativeDownloadMetadata) {
	t.Helper()
	f, cfg, _ := newDownloadResultFixture(t)
	path := nativeLeaseFixture().Operation.Path
	path.TargetClusterID = f.s.Scope.ClusterID
	path.AcquisitionClusterID = f.enrollment.Worker.Intent.Profile.ClusterID
	path.ConnectorClusterID = path.AcquisitionClusterID
	path.WorkerConfiguration = f.enrollment.Worker.Intent.Profile.Configuration
	f.a.Environment.Path = path
	p := artifact.DownloadPreparation{SessionID: f.s.ID, BatchID: "30000000-0000-4000-8000-000000000001", Generation: 1}
	o := ContextDownloadAttachment{SessionID: f.s.ID, Scope: f.s.Scope, State: f.s.State, Found: true, Intent: f.enrollment.Worker.Intent, Worker: &f.enrollment.Worker, Enrollment: &f.enrollment, Preparation: &p, MetadataAttempted: true}
	k, e := contextMetadataKey(f.s, o, f.a)
	if e != nil || !k.valid() {
		t.Fatal("synthetic metadata key", e)
	}
	m := contextDownloadMetadata(cfg.Request, []byte("synthetic context"))
	m.ReadUntil, m.DeleteBy = f.a.AccessUntil, f.a.DeleteBy
	if !(artifact.PreparedDownload{Preparation: p, Scope: k.Scope, Native: m}).Valid() {
		t.Fatal("synthetic metadata")
	}
	return newContextNativeMetadata(func() time.Time { return f.now }), k, m
}

func TestContextMetadataWarmPollsAndActivePinConsumeNoNativeCredits(t *testing.T) {
	c, k, m := contextMetadataFixture(t)
	loads := 0
	load := func(context.Context) (artifact.NativeDownloadMetadata, error) { loads++; return m, nil }
	first, release, e := c.get(context.Background(), k, true, false, load)
	if e != nil || first != m {
		t.Fatal(e)
	}
	release()
	// The worker may now be streaming: warm status needs no competing Observe.
	for i := 0; i < 100; i++ {
		got, release, e := c.get(context.Background(), k, false, false, load)
		if e != nil || got != m {
			t.Fatal(i, e)
		}
		release()
	}
	_, pin, e := c.get(context.Background(), k, false, true, load)
	if e != nil {
		t.Fatal(e)
	}
	for i := 2; i <= contextNativeMetadataSlots+2; i++ {
		other := k
		other.SessionID = fmt.Sprintf("30000000-0000-4000-8000-%012d", i)
		other.Preparation.SessionID = other.SessionID
		other.Binding.DownloadID = other.SessionID
		_, release, e := c.get(context.Background(), other, true, false, load)
		if e != nil {
			t.Fatal(e)
		}
		release()
	}
	if c.entries[k.SessionID] == nil || c.entries[k.SessionID].pins != 1 || len(c.entries) != contextNativeMetadataSlots {
		t.Fatal("active metadata evicted/unbounded")
	}
	before := loads
	_, release, e = c.get(context.Background(), k, false, false, load)
	if e != nil || loads != before {
		t.Fatal("active poll observed worker", e)
	}
	release()
	pin()
	pin()
	if c.entries[k.SessionID].pins != 0 {
		t.Fatal("unjoined/double pin release")
	}
	// Losing this process's cache during a live response cannot admit Observe.
	fresh := newContextNativeMetadata(c.now)
	_, _, e = fresh.get(context.Background(), k, false, false, load)
	if !errors.Is(e, ErrDownloadMetadataUnavailable) || loads != before {
		t.Fatal("cold active response started Observe", e)
	}
}

func TestContextMetadataCoalescesWithoutBorrowingWaiterDeadline(t *testing.T) {
	c, k, m := contextMetadataFixture(t)
	entered, leave := make(chan struct{}), make(chan struct{})
	var loads atomic.Int32
	load := func(ctx context.Context) (artifact.NativeDownloadMetadata, error) {
		loads.Add(1)
		close(entered)
		select {
		case <-leave:
			return m, nil
		case <-ctx.Done():
			return artifact.NativeDownloadMetadata{}, ctx.Err()
		}
	}
	leader := make(chan error, 1)
	go func() {
		_, release, e := c.get(context.Background(), k, true, false, load)
		if release != nil {
			release()
		}
		leader <- e
	}()
	<-entered
	waiter, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, e := c.get(waiter, k, true, false, load); e == nil {
		t.Fatal("cancelled waiter borrowed leader lifetime")
	}
	// A different still-live waiter can use only the same positively joined fact.
	waiting := make(chan error, 1)
	go func() {
		_, release, e := c.get(context.Background(), k, true, false, load)
		if release != nil {
			release()
		}
		waiting <- e
	}()
	close(leave)
	if e := <-leader; e != nil {
		t.Fatal(e)
	}
	if e := <-waiting; e != nil {
		t.Fatal(e)
	}
	if loads.Load() != 1 {
		t.Fatal("duplicate Observe", loads.Load())
	}
}

func TestContextMetadataFailedObservationIsNotAutomaticRetry(t *testing.T) {
	c, k, _ := contextMetadataFixture(t)
	calls := 0
	load := func(context.Context) (artifact.NativeDownloadMetadata, error) {
		calls++
		return artifact.NativeDownloadMetadata{}, artifact.ErrDownloadUnavailable
	}
	for i := 0; i < 20; i++ {
		if _, _, e := c.get(context.Background(), k, true, false, load); e == nil {
			t.Fatal("failed observation became metadata")
		}
	}
	if calls != 1 {
		t.Fatal("polling repeated unknown observation", calls)
	}
}
func TestContextMetadataRejectsDifferentOriginalBindingAndExpiry(t *testing.T) {
	for _, change := range []struct {
		name  string
		alter func(*contextNativeMetadataKey)
	}{
		{"worker", func(k *contextNativeMetadataKey) { k.WorkerID = "30000000-0000-4000-8000-000000000009" }},
		{"batch", func(k *contextNativeMetadataKey) { k.Preparation.BatchID = "30000000-0000-4000-8000-000000000009" }},
		{"key", func(k *contextNativeMetadataKey) { k.PublicKey[0]++ }},
		{"version", func(k *contextNativeMetadataKey) { k.Scope.Version[0]++ }},
		{"path", func(k *contextNativeMetadataKey) { k.Path.WorkerConfiguration.Digest[0]++ }},
		{"deadline", func(k *contextNativeMetadataKey) { k.SessionUntil = k.SessionUntil.Add(time.Second) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			c, k, m := contextMetadataFixture(t)
			calls := 0
			load := func(context.Context) (artifact.NativeDownloadMetadata, error) { calls++; return m, nil }
			_, release, e := c.get(context.Background(), k, true, false, load)
			if e != nil {
				t.Fatal(e)
			}
			release()
			change.alter(&k)
			if _, _, e := c.get(context.Background(), k, true, false, load); e == nil || calls != 1 {
				t.Fatal("replaced original metadata binding", e, calls)
			}
		})
	}
	c, k, m := contextMetadataFixture(t)
	_, release, e := c.get(context.Background(), k, true, true, func(context.Context) (artifact.NativeDownloadMetadata, error) { return m, nil })
	if e != nil {
		t.Fatal(e)
	}
	c.now = func() time.Time { return k.WorkerUntil }
	if _, _, e = c.get(context.Background(), k, true, false, func(context.Context) (artifact.NativeDownloadMetadata, error) {
		t.Fatal("expired metadata reloaded")
		return m, nil
	}); e == nil {
		t.Fatal("expired metadata disclosed")
	}
	if len(c.entries) != 1 {
		t.Fatal("active expired pin released before join")
	}
	release()
	if len(c.entries) != 0 {
		t.Fatal("expired pin retained after join")
	}
}

// The prepare-to-view handoff is exact, single-use and bounded; it never
// substitutes for a different preparation, scope, expired facts or a closed cache.
func TestContextNativeMetadataHandoffExactSingleUse(t *testing.T) {
	f, lookup, _, m := warmContextRuntimeFixture(t)
	key, e := contextMetadataKey(f.s, lookup.value, f.a)
	if e != nil {
		t.Fatal(e)
	}
	c := newContextNativeMetadata(func() time.Time { return f.now })
	p := artifact.PreparedDownload{Preparation: key.Preparation, Scope: key.Scope, Native: m}
	c.handoff(p)
	if got, ok := c.takeHandoff(key); !ok || got != m {
		t.Fatal("exact preparation handoff missing")
	}
	if _, ok := c.takeHandoff(key); ok {
		t.Fatal("handoff reused")
	}
	other := key
	other.Preparation.Generation = 2
	c.handoff(p)
	if _, ok := c.takeHandoff(other); ok {
		t.Fatal("different preparation adopted handoff")
	}
	if _, ok := c.takeHandoff(key); ok {
		t.Fatal("mismatched lookup did not consume stale handoff")
	}
	expired := p
	expired.Native.ReadUntil = f.now
	c.handoff(expired)
	if _, ok := c.takeHandoff(key); ok {
		t.Fatal("expired facts handed off")
	}
	for i := 0; i < contextNativeMetadataSlots; i++ {
		q := p
		q.Preparation.SessionID = fmt.Sprintf("40000000-0000-4000-8000-%012d", i)
		c.handoffs[q.Preparation.SessionID] = q
	}
	c.handoff(p)
	if _, ok := c.handoffs[key.SessionID]; ok {
		t.Fatal("handoff exceeded slot bound")
	}
	clear(c.handoffs)
	c.handoff(p)
	c.close()
	if _, ok := c.takeHandoff(key); ok || len(c.handoffs) != 0 {
		t.Fatal("closed cache retained handoff")
	}
}
