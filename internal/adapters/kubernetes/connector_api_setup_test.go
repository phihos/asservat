package kubernetes

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	value "asservat.local/asservat/internal/domain/fleet"
)

// These fixtures exercise only the setup owner's state and join boundary. The
// completed native proof and closing callback are explicit synthetic inputs;
// they do not qualify native guards, credentials or installed availability.
func connectorSetupStateFixture(t *testing.T) (*connectorAPISetup, *atomic.Int64) {
	t.Helper()
	start := time.Now().UTC()
	clock := &atomic.Int64{}
	clock.Store(start.UnixNano())
	proof := connectorCachedProof(t, start)
	proof.source = value.ConnectorIdentitySource{Observation: proof.proof.Configuration, Roles: value.ConnectorIdentityRoles{Source: "source", Journal: "journal", Acknowledgement: "ack", Cleanup: "cleanup", Verifier: "verifier", Finalizer: "finalizer"}}
	proof.generation = 7
	credentials := &mtls.ConnectorProcessCredentials{}
	guard := &ConnectorAPIExecutionProtection{credentials: credentials, attester: &ConnectorProcessAttester{client: &PermissionClient{now: func() time.Time { return time.Unix(0, clock.Load()).UTC() }}}, reuse: connectorAPIProofState{generation: proof.generation}}
	process := &ConnectorAPIExecutionProcess{guard: guard, parent: context.Background(), connector: proof.proof.Process}
	root, cancel := context.WithDeadline(context.Background(), proof.validUntil)
	op := &connectorAPISetup{process: process, credentials: credentials, root: root, cancel: cancel, proof: proof, stopParent: func() bool { return true }}
	op.finishNative = func(_ context.Context, p connectorAPIProof) (connectorAPIProof, error) { return p, nil }
	t.Cleanup(op.Close)
	return op, clock
}

func TestConnectorAPISetupOriginalSourceAndSingleClose(t *testing.T) {
	op, _ := connectorSetupStateFixture(t)
	var calls int
	op.finishNative = func(_ context.Context, p connectorAPIProof) (connectorAPIProof, error) { calls++; return p, nil }
	if err := op.Finish(context.Background()); err == nil || calls != 0 {
		t.Fatal("native close ran without the original source frame")
	}
	ctx, cancel := context.WithDeadline(context.Background(), op.proof.observedAt.Add(time.Second))
	defer cancel()
	source, err := op.Source(ctx)
	if err != nil || source.Observation.ObservedAt != op.proof.source.Observation.ObservedAt || source.Observation.FreshUntil.After(op.proof.observedAt.Add(time.Second)) {
		t.Fatal("source frame changed original/caller bounds", err)
	}
	source.Observation.Profile.ClientIssuerRoots[0][0] = 88
	if op.proof.source.Observation.Profile.ClientIssuerRoots[0][0] != 1 {
		t.Fatal("source reply aliases native proof")
	}
	if _, err := op.Source(ctx); err == nil {
		t.Fatal("source frame repeated")
	}
	if err := op.Finish(ctx); err != nil || calls != 1 || !op.finished || op.proof.validUntil.After(source.Observation.FreshUntil) {
		t.Fatal("original native close", err, calls)
	}
	if err := op.Finish(ctx); err == nil || calls != 1 {
		t.Fatal("native close replay performed I/O")
	}
	op.Close()
	if _, err := op.Source(ctx); err == nil || op.currentLocked(ctx) {
		t.Fatal("closed setup owner stayed usable")
	}
}

func TestConnectorAPISetupLateCloseCannotPublish(t *testing.T) {
	for _, mode := range []string{"known-generation", "parent-cancelled", "caller-cancelled", "expired", "shorter-caller-expired", "renewed-start", "renewed-end"} {
		t.Run(mode, func(t *testing.T) {
			op, clock := connectorSetupStateFixture(t)
			parent, stopParent := context.WithCancel(context.Background())
			defer stopParent()
			op.process.parent = parent
			ctx, cancel := context.WithDeadline(context.Background(), op.proof.observedAt.Add(time.Second))
			defer cancel()
			if _, err := op.Source(ctx); err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			op.finishNative = func(_ context.Context, p connectorAPIProof) (connectorAPIProof, error) {
				close(entered)
				<-release
				if mode == "renewed-start" {
					p.observedAt = p.observedAt.Add(time.Nanosecond)
				}
				if mode == "renewed-end" {
					p.validUntil = p.validUntil.Add(time.Nanosecond)
				}
				return p, nil
			}
			result := make(chan error, 1)
			go func() { result <- op.Finish(ctx) }()
			<-entered
			switch mode {
			case "known-generation":
				op.process.guard.reuse.invalidate()
			case "parent-cancelled":
				stopParent()
			case "caller-cancelled":
				cancel()
			case "expired":
				clock.Store(op.proof.validUntil.UnixNano())
			case "shorter-caller-expired":
				// The native clock has reached the caller cutoff even if its
				// cancellation callback has not run. Finish must refuse now.
				clock.Store(op.proof.observedAt.Add(time.Second).UnixNano())
			}
			close(release)
			if err := <-result; err == nil || op.finished || !op.closed {
				t.Fatal("late closing proof published positive setup", err)
			}
		})
	}
}

func TestConnectorAPISetupCloseJoinsNativeWork(t *testing.T) {
	op, _ := connectorSetupStateFixture(t)
	if _, err := op.Source(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	op.finishNative = func(ctx context.Context, p connectorAPIProof) (connectorAPIProof, error) {
		close(entered)
		<-ctx.Done()
		<-release
		return p, nil
	}
	result := make(chan error, 1)
	go func() { result <- op.Finish(context.Background()) }()
	<-entered
	closed := make(chan struct{})
	go func() { op.Close(); close(closed) }()
	<-op.root.Done()
	select {
	case <-closed:
		t.Fatal("setup close released blocked native work")
	default:
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("closed setup accepted late native result")
	}
	<-closed
}

func TestConnectorAPISetupBeginPreservesParentCancellation(t *testing.T) {
	op, _ := connectorSetupStateFixture(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	op.process.parent = parent
	op.process.guard.reuse.flight = &connectorAPIProofFlight{done: make(chan struct{})}
	waiting := &connectorProofWaitContext{Context: context.Background(), waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		setup, err := op.process.BeginAPIContextSetup(waiting, op.credentials)
		if setup != nil {
			setup.Close()
		}
		result <- err
	}()
	<-waiting.waiting
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled parent obtained a setup proof")
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not interrupt blocked initial proof")
	}
}
