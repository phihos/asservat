package mtls

import (
	"asservat.local/asservat/internal/contracts"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	execution "asservat.local/asservat/internal/domain/execution"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
)

// regionalOperationsFixture is the region's synthetic cluster-local port set.
type regionalOperationsFixture struct {
	t                   *testing.T
	work                value.APIContextWork
	process             contextStartAPIProcess
	captures, stores    int
	resolved            int
	prepared, completed bool
}

func (f *regionalOperationsFixture) ReadAPIProcess(ctx context.Context) (execution.APIProcessObservation, error) {
	return f.process(ctx)
}

// resolution is a complete synthetic API-class resolution of r.
func (f *regionalOperationsFixture) resolution(r targets.Request) targets.PodResolution {
	now := time.Now().UTC()
	return targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: r, Pin: artifact.PinnedPod{Namespace: r.Namespace.Name, NamespaceUID: r.Namespace.UID, Name: r.PodName, UID: r.PodUID, ControllerUID: "replicaset"}, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
}
func (f *regionalOperationsFixture) ResolvePod(_ context.Context, r targets.Request) (targets.PodResolution, error) {
	f.resolved++
	if r.PodName == "replaced" {
		return targets.PodResolution{}, targets.ErrChanged
	}
	return f.resolution(r), nil
}
func (f *regionalOperationsFixture) ResolveWorkload(_ context.Context, r targets.WorkloadRequest) (targets.PodResolution, error) {
	f.resolved++
	w := f.work.Target
	return f.resolution(targets.Request{ClusterID: r.ClusterID, Namespace: configuration.NamespaceRef{Name: r.Namespace, UID: w.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: r.Kind, Name: r.Name, UID: w.WorkloadUID}, PodName: r.Name + "-0", PodUID: w.PodUID}), nil
}
func (f *regionalOperationsFixture) PrepareStart(context.Context, execution.PreparationCheck) (execution.PreparedStart, error) {
	return execution.PreparedStart{ObjectUID: ownerTestID, ResourceVersion: "1"}, nil
}
func (f *regionalOperationsFixture) ReadyStart(context.Context, execution.Request) (execution.Disposition, error) {
	return execution.Disposition{ObjectUID: ownerTestID, ResourceVersion: "2", Phase: execution.Ready}, nil
}
func (f *regionalOperationsFixture) ConsumeStart(context.Context, execution.Request) (execution.Disposition, error) {
	now := time.Now().UTC()
	return execution.Disposition{ObjectUID: ownerTestID, ResourceVersion: "3", Phase: execution.StartCommitted, CommittedAt: now, MayStart: true, ValidUntil: now.Add(2 * time.Second)}, nil
}
func (f *regionalOperationsFixture) LookupStart(context.Context, execution.Request) (execution.Disposition, error) {
	return execution.Disposition{}, execution.ErrUnavailable
}
func (f *regionalOperationsFixture) Capture(context.Context, artifact.PinnedPod) ([]byte, error) {
	f.captures++
	return []byte("synthetic regional context"), nil
}
func (f *regionalOperationsFixture) PrepareContext(context.Context, artifact.ContextExpectation) (evidence.PreparedContext, error) {
	f.prepared = true
	return regionalPrepared{f}, nil
}

type regionalPrepared struct{ f *regionalOperationsFixture }

var regionalCopies = artifact.Copies{{VersionID: "v", ETag: `"d"`, Bytes: 1, SHA256: artifact.Digest{1}}}

func (p regionalPrepared) StoreContext(_ context.Context, native []byte, _, _ time.Time) (artifact.Copies, error) {
	if string(native) != "synthetic regional context" {
		p.f.t.Error("stored other bytes")
	}
	p.f.stores++
	return regionalCopies, nil
}
func (p regionalPrepared) Close() {}
func (p regionalPrepared) CompleteStored() (artifact.ContextWriterCompletion, error) {
	p.f.completed = true
	return artifact.ContextWriterCompletion{Copies: regionalCopies, StoredAt: time.Now().UTC()}, nil
}

// ADR-171 over actual TLS1.3/H2: the hub drives cluster-local operations for
// the verified work; the region binds each to that work, refuses foreign or
// out-of-order operations, and only copy receipts cross the exchange.
func TestContextStartActualHTTP2HubRunOperations(t *testing.T) {
	f := newContextStartTLSFixture(t)
	exchange, stream := f.open(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// The region waits for work first, as in standby; the hub's attach check
	// pulls its fresh source over this exchange (ADR-178).
	expectation := artifact.ContextExpectation{CaptureUID: ownerTestID}
	work, signer, signed, _ := f.work(t, exchange.Receiver(), func(w *value.APIContextWork) {
		w.ExpectationDigest = evidence.ContextExpectationDigest(expectation)
	})
	regional := &regionalOperationsFixture{t: t, work: work, process: f.api}
	local := contextstart.RegionalLocal{Process: regional, Targets: regional, Local: regional, Starts: regional, Output: regional, Collector: regional, Source: f.connector, Now: time.Now}
	regionalDone := make(chan error, 1)
	go func() {
		defer stream.Close()
		regionalDone <- contextstart.ServeRegionalOperations(exchange.Context(), stream, exchange.Receiver(), signer, local, time.Now)
	}()
	attachment, err := f.router.Attach(ctx, f.connector.profile.Binding.ClusterID, ownerTestID)
	if err != nil {
		t.Fatal(err)
	}
	defer attachment.Close()
	if _, err = attachment.Receiver(ctx); err != nil {
		t.Fatal(err)
	}
	target := targets.Request{ClusterID: work.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: "app", UID: work.Target.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "app", UID: work.Target.WorkloadUID}, PodName: "app-0", PodUID: work.Target.PodUID}
	binding := execution.Binding{CaptureID: work.CaptureID, AttemptID: work.AttemptID, ClusterID: work.Target.ClusterID, PodUID: work.Target.PodUID, ScopeDigest: work.ScopeDigest, BudgetDigest: work.BudgetDigest}
	state, err := attachment.Run(work, signed, func(ctx context.Context, ops *contextstart.HubOperations) (string, error) {
		resolved, err := ops.ResolvePod(ctx, target)
		if err != nil || resolved.Pin.UID != target.PodUID {
			return "", errors.Join(errors.New("resolve"), err)
		}
		if _, err = ops.ReadAPIProcess(ctx); err != nil {
			return "", err
		}
		foreign := binding
		foreign.CaptureID = "55000000-0000-4000-8000-0000000000ff"
		if _, err = ops.PrepareStart(ctx, execution.PreparationCheck{Binding: foreign}); !errors.Is(err, execution.ErrDenied) {
			return "", errors.New("foreign capture start accepted")
		}
		if _, err = ops.PrepareStart(ctx, execution.PreparationCheck{Binding: binding}); err != nil {
			return "", err
		}
		prepared, err := ops.PrepareContext(ctx, expectation)
		if err != nil {
			return "", err
		}
		acquirer := prepared.(evidence.ContextAcquirer)
		if _, _, err = acquirer.AcquireContext(ctx, resolved.Pin, time.Now(), time.Now().Add(time.Second)); !errors.Is(err, execution.ErrDenied) {
			return "", errors.New("acquired before the start committed")
		}
		committed, err := ops.ConsumeStart(ctx, execution.Request{Binding: binding, ObjectUID: ownerTestID})
		if err != nil || !committed.MayStart {
			return "", errors.Join(errors.New("consume"), err)
		}
		if _, err = prepared.StoreContext(ctx, []byte("hub bytes"), time.Now(), time.Now()); err == nil {
			return "", errors.New("hub stored native bytes")
		}
		acquired, copies, err := acquirer.AcquireContext(ctx, resolved.Pin, time.Now().UTC(), committed.ValidUntil)
		if err != nil || acquired.IsZero() || copies != regionalCopies {
			return "", errors.Join(errors.New("acquire"), err)
		}
		completion, err := prepared.(evidence.StoredContextCloser).CompleteStored()
		if err != nil || completion.Copies != regionalCopies {
			return "", errors.Join(errors.New("complete"), err)
		}
		return "StoredPendingVerification", nil
	})
	if err != nil || state != "StoredPendingVerification" {
		t.Fatalf("hub-run operations: state=%q err=%v", state, err)
	}
	if err = <-regionalDone; err != nil {
		t.Fatal("regional operations", err)
	}
	if regional.captures != 1 || regional.stores != 1 || !regional.prepared || !regional.completed || f.dials.Load() != 1 {
		t.Fatal("regional effects", regional.captures, regional.stores, regional.prepared, regional.completed)
	}
}

// ADR-172: the regional client dials only its pinned endpoint with the exact
// owner name, reads no route and authenticates through the given authenticator.
func TestContextStartRegionalClientDialsPinnedEndpointWithExactName(t *testing.T) {
	f := newContextStartTLSFixture(t)
	const pinned = "198.51.100.7:31444"
	client, err := NewRegionalContextStartClient(context.Background(), f.rootID, f.pool, f.roots, pinned, f.owners, f.credential, f.api, 1, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	var dials int
	client.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials++
		if address != pinned {
			t.Error("dialed an address other than the pinned endpoint", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, f.listener)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	exchange, err := client.Open(ctx, f.owner)
	if err != nil {
		t.Fatal("pinned-endpoint open", err)
	}
	defer exchange.Close()
	if !exchange.Receiver().Valid(time.Now()) || exchange.Receiver().Channel.Hub != f.owner || dials != 1 {
		t.Fatal("pinned-endpoint exchange", dials)
	}
	for _, bad := range []string{"", "no-port", "host:0", "a/b:1"} {
		if _, err := NewRegionalContextStartClient(context.Background(), f.rootID, f.pool, f.roots, bad, f.owners, f.credential, f.api, 1, time.Now); err == nil {
			t.Fatal("malformed pinned endpoint accepted", bad)
		}
	}
}

// blockingRegion is a regional port set whose process read blocks until its
// context ends, then reports a positive result.
type blockingRegion struct {
	*regionalOperationsFixture
	entered, joined chan struct{}
	deadline        time.Time
}

func (b *blockingRegion) ReadAPIProcess(ctx context.Context) (execution.APIProcessObservation, error) {
	if d, ok := ctx.Deadline(); ok {
		b.deadline = d
	}
	close(b.entered)
	<-ctx.Done()
	close(b.joined)
	// A positive answer after cancellation must never become timely authority.
	return b.regionalOperationsFixture.ReadAPIProcess(context.Background())
}

func blockingOperationExchange(t *testing.T, mutate func(*value.APIContextWork)) (*contextStartTLSFixture, *ContextStartExchange, *contextstart.Attachment, value.APIContextWork, []byte, *blockingRegion, chan error) {
	t.Helper()
	f := newContextStartTLSFixture(t)
	exchange, stream := f.open(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	var mutators []func(*value.APIContextWork)
	if mutate != nil {
		mutators = append(mutators, mutate)
	}
	work, signer, signed, _ := f.work(t, exchange.Receiver(), mutators...)
	region := &blockingRegion{regionalOperationsFixture: &regionalOperationsFixture{t: t, work: work, process: f.api}, entered: make(chan struct{}), joined: make(chan struct{})}
	local := contextstart.RegionalLocal{Process: region, Targets: region, Local: region, Starts: region, Output: region, Collector: region, Source: f.connector, Now: time.Now}
	regionalDone := make(chan error, 1)
	go func() {
		defer stream.Close()
		regionalDone <- contextstart.ServeRegionalOperations(exchange.Context(), stream, exchange.Receiver(), signer, local, time.Now)
	}()
	attachment, err := f.router.Attach(ctx, f.connector.profile.Binding.ClusterID, ownerTestID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(attachment.Close)
	if _, err = attachment.Receiver(ctx); err != nil {
		t.Fatal(err)
	}
	return f, exchange, attachment, work, signed, region, regionalDone
}

func readProcessRun(ctx context.Context, ops *contextstart.HubOperations) (string, error) {
	if _, err := ops.ReadAPIProcess(ctx); err != nil {
		return "Unavailable", err
	}
	return "StoredPendingVerification", nil
}

// Owner cancellation interrupts and joins a blocked regional operation; the
// unknown conversation is neither reported as success nor replayed.
func TestContextStartActualHTTP2OwnerCancellationJoinsBlockedOperation(t *testing.T) {
	f, _, attachment, work, signed, region, regionalDone := blockingOperationExchange(t, nil)
	ran := make(chan error, 1)
	go func() { _, e := attachment.Run(work, signed, readProcessRun); ran <- e }()
	select {
	case <-region.entered:
	case <-time.After(time.Second):
		t.Fatal("regional operation not entered")
	}
	attachment.Close()
	select {
	case <-region.joined:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancellation did not reach the blocked regional operation")
	}
	if err := <-ran; err == nil {
		t.Fatal("canceled conversation reported success")
	}
	if err := <-regionalDone; err == nil {
		t.Fatal("canceled regional conversation reported delivery")
	}
	if f.requests.Load() != 1 {
		t.Fatal("unknown conversation was replayed")
	}
}

// The original signed work deadline bounds every regional operation; a late
// positive regional result cannot produce a hub result or a second attempt.
func TestContextStartActualHTTP2OriginalWorkExpiryRejectsLateOperationResult(t *testing.T) {
	var notAfter time.Time
	f, _, attachment, work, signed, region, regionalDone := blockingOperationExchange(t, func(w *value.APIContextWork) {
		w.NotAfter = time.Now().UTC().Truncate(time.Microsecond).Add(250 * time.Millisecond)
		notAfter = w.NotAfter
	})
	state, err := attachment.Run(work, signed, readProcessRun)
	if err == nil || state != "" {
		t.Fatalf("late result disclosed: state=%q error=%v", state, err)
	}
	select {
	case <-region.joined:
	case <-time.After(time.Second):
		t.Fatal("original work deadline failed to join the regional operation")
	}
	if region.deadline.IsZero() || region.deadline.After(notAfter) {
		t.Fatal("regional operation lost the original signed work cutoff")
	}
	if err = <-regionalDone; err == nil {
		t.Fatal("late positive regional result accepted")
	}
	if f.requests.Load() != 1 || f.dials.Load() != 1 {
		t.Fatal("expiry retried the connection")
	}
}

// Closing the regional exchange (actual H2 EOF) ends the hub's blocked
// operation; no reply or receipt follows.
func TestContextStartActualHTTP2EOFJoinsBlockedOperation(t *testing.T) {
	f, exchange, attachment, work, signed, region, regionalDone := blockingOperationExchange(t, nil)
	ran := make(chan error, 1)
	go func() { _, e := attachment.Run(work, signed, readProcessRun); ran <- e }()
	select {
	case <-region.entered:
	case <-time.After(time.Second):
		t.Fatal("regional operation not entered")
	}
	exchange.Close()
	select {
	case <-region.joined:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("actual H2 EOF did not join the regional operation")
	}
	if err := <-ran; err == nil {
		t.Fatal("hub run succeeded after stream termination")
	}
	if err := <-regionalDone; err == nil {
		t.Fatal("regional reply obtained a receipt after EOF")
	}
	if f.requests.Load() != 1 || f.dials.Load() != 1 {
		t.Fatal("unknown delivery reconnected")
	}
}

// ADR-179 over actual TLS1.3/H2: the hub's pre-work target queries are answered
// while the region waits; a closed failure keeps the exchange, and the same
// standby then serves the work. A query beyond the budget has no standby.
func TestContextStartActualHTTP2TargetQueriesKeepTheStandby(t *testing.T) {
	f := newContextStartTLSFixture(t)
	regional := &regionalOperationsFixture{t: t, process: f.api}
	f.targets = regional
	exchange, stream := f.open(t)
	signer := f.workSigner(t, exchange.Receiver())
	// Queries have target facts but create no signed effect work.
	target := authorization.Target{ClusterID: exchange.Receiver().Channel.Connector.Binding.ClusterID, NamespaceUID: ownerTestID, WorkloadUID: ownerTestID, PodUID: ownerTestID}
	regional.work.Target = target
	local := contextstart.RegionalLocal{Process: regional, Targets: regional, Local: regional, Starts: regional, Output: regional, Collector: regional, Source: f.connector, Now: time.Now}
	regionalDone := make(chan error, 1)
	go func() {
		defer stream.Close()
		regionalDone <- contextstart.ServeRegionalOperations(exchange.Context(), stream, exchange.Receiver(), signer, local, time.Now)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	hub := contextstart.Targets{Router: f.router, Now: time.Now}
	cluster := target.ClusterID
	resolved, err := hub.ResolveWorkload(ctx, targets.WorkloadRequest{ClusterID: cluster, Namespace: "app", Kind: "Deployment", Name: "app"})
	if err != nil || resolved.Request.PodName != "app-0" || resolved.Target() != target || resolved.FreshUntil.After(exchange.Receiver().ValidUntil.Add(time.Second)) {
		t.Fatal("workload query", err, resolved)
	}
	again, err := hub.ResolvePod(ctx, resolved.Request)
	if err != nil || again.Request != resolved.Request {
		t.Fatal("pod query", err)
	}
	replaced := resolved.Request
	replaced.PodName = "replaced"
	if _, err = hub.ResolvePod(ctx, replaced); !errors.Is(err, targets.ErrChanged) {
		t.Fatal("closed regional failure", err)
	}
	if _, err = hub.ResolvePod(ctx, targets.Request{}); !errors.Is(err, targets.ErrInvalid) {
		t.Fatal("invalid request reached the region", err)
	}
	for i := 4; i <= contracts.APIContextMaximumQueries; i++ {
		if _, err = hub.ResolvePod(ctx, resolved.Request); err != nil {
			t.Fatal("query within the budget", i, err)
		}
	}
	if _, err = hub.ResolvePod(ctx, resolved.Request); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("query beyond the exchange budget", err)
	}
	if regional.resolved != contracts.APIContextMaximumQueries {
		t.Fatal("region answered", regional.resolved)
	}
	// Model CI scheduling/query time crossing the fixture's original two-second
	// work lifetime while the existing five-second standby is still alive.
	time.Sleep(2100 * time.Millisecond)
	// Issue the first work only after queries. Its original two-second lifetime
	// is unchanged and remains bounded by this original receiver.
	work, _, signed, _ := f.workWithSigner(t, exchange.Receiver(), signer)
	attachment, err := f.router.Attach(ctx, cluster, ownerTestID)
	if err != nil {
		t.Fatal("standby consumed by queries", err)
	}
	defer attachment.Close()
	if _, err = attachment.Receiver(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := attachment.Run(work, signed, func(ctx context.Context, ops *contextstart.HubOperations) (string, error) {
		if _, err := ops.ResolvePod(ctx, resolved.Request); err != nil {
			return "", err
		}
		return "Unavailable", nil
	})
	if err != nil || state != "Unavailable" {
		t.Fatalf("work after queries: state=%q err=%v", state, err)
	}
	if err = <-regionalDone; err != nil {
		t.Fatal("regional operations", err)
	}
	if _, err = hub.ResolvePod(ctx, resolved.Request); err == nil {
		t.Fatal("query reached a finished exchange")
	}
}
