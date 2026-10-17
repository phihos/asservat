package kubernetes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func lifecycleNativeFixture(t *testing.T) (*connectorOperationFixture, *ConnectorLifecycleReader, app.ConnectorLifecycleRequest, context.Context) {
	t.Helper()
	f := newConnectorOperationFixture(t)
	reader, err := NewConnectorLifecycleReader(f.reader.client, f.reader.source, f.reader.guard, connectorTokenFunc(func(context.Context) ([]byte, error) { return bytes.Clone(f.token), nil }))
	if err != nil {
		t.Fatal(err)
	}
	csr := func() []byte {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		out, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	start := f.base.start
	r := app.ConnectorLifecycleRequest{Binding: value.ConnectorLifecycleBinding{ID: ownerID(80), Purpose: value.ConnectorLifecycleEnroll, Process: f.process, RequestedAt: start, NotAfter: start.Add(5 * time.Second)}, Request: value.ConnectorProcessRequest{Process: f.process, ClientCSRDER: csr(), ServerCSRDER: csr()}}
	ctx, cancel := context.WithDeadline(context.Background(), r.Binding.NotAfter)
	t.Cleanup(cancel)
	return f, reader, r, ctx
}

func lifecycleRead(t *testing.T, op app.ConnectorLifecycleOperation, ctx context.Context, phase value.ConnectorLifecyclePhase) value.ConnectorLifecycleObservation {
	t.Helper()
	out, err := op.Read(ctx, phase)
	if err != nil {
		t.Fatal("native lifecycle phase", phase, err)
	}
	return out
}

func TestConnectorLifecycleNativeOwnsOriginalAndIndependentFinal(t *testing.T) {
	f, reader, r, ctx := lifecycleNativeFixture(t)
	client, _ := mtls.EnrollmentKey(r.Request.ClientCSRDER)
	server, _ := mtls.EnrollmentKey(r.Request.ServerCSRDER)
	op, err := reader.BeginConnectorLifecycle(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	// Mutating caller buffers after Begin cannot select another process key.
	r.Request.ClientCSRDER[0] ^= 1
	r.Request.ServerCSRDER[0] ^= 1
	first := lifecycleRead(t, op, ctx, value.ConnectorLifecycleInitial)
	if first.Original.ClientKeyDigest != client || first.Original.ServerKeyDigest != server || f.base.observer.Load() != 22 || f.base.probe.Load() != 6 {
		t.Fatalf("first actual key/bracket/count mismatch observer=%d probe=%d", f.base.observer.Load(), f.base.probe.Load())
	}
	prior := first
	for _, phase := range []value.ConnectorLifecyclePhase{value.ConnectorLifecycleBeforeEffect, value.ConnectorLifecycleBeforeActivation, value.ConnectorLifecycleFinal} {
		f.base.clock.Store(f.base.start.Add(time.Duration(phase) * time.Millisecond).UnixNano())
		next := lifecycleRead(t, op, ctx, phase)
		if !next.Continues(prior) || !next.Original.ObservedAt.Equal(first.Original.ObservedAt) || !next.Original.FreshUntil.Equal(first.Original.FreshUntil) || !next.Source.Observation.ObservedAt.Equal(f.base.start.Add(time.Duration(phase)*time.Millisecond)) {
			t.Fatal("native or value dates relabeled", phase)
		}
		if phase == value.ConnectorLifecycleFinal && (next.FinalProof == nil || !next.FinalProof.ObservedAt.Equal(next.Source.Observation.ObservedAt)) {
			t.Fatal("final proof lacks actual later observation")
		}
		prior = next
	}
	if f.base.observer.Load() != 68 || f.base.probe.Load() != 12 || f.reviews.Load() != 6 {
		t.Fatalf("complete actual count observer=%d probe=%d tokenreviews=%d", f.base.observer.Load(), f.base.probe.Load(), f.reviews.Load())
	}
	before := f.base.observer.Load()
	if _, err := op.Read(ctx, value.ConnectorLifecycleFinal); err == nil || f.base.observer.Load() != before {
		t.Fatal("final phase replay performed I/O")
	}
}

func TestConnectorLifecycleNativeKnownChangePermanentlyCloses(t *testing.T) {
	for _, mode := range []string{"source-roles", "source-backing", "source-revision", "source-guard", "workload-guard", "account", "pod", "replica", "deployment", "token", "cancel", "clock-rollback", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			f, reader, r, ctx := lifecycleNativeFixture(t)
			op, err := reader.BeginConnectorLifecycle(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(op.Close)
			lifecycleRead(t, op, ctx, value.ConnectorLifecycleInitial)
			f.mu.Lock()
			f.base.mu.Lock()
			switch mode {
			case "source-roles":
				f.wire["roles"].(map[string]any)["source"] = "changed_source"
			case "source-backing":
				b := f.wire["backing"].(app.ConnectorIdentityBacking)
				b.Policy.BackingRevision++
				f.wire["backing"] = b
			case "source-revision":
				f.wire["revision"] = 2
			case "source-guard":
				f.missing = true
			case "workload-guard":
				f.base.policy.UID = types.UID(ownerID(91))
			case "account":
				f.base.v.sa.UID = types.UID(ownerID(91))
			case "pod":
				f.base.v.pod.Spec.Containers[0].Args = []string{"changed"}
			case "replica":
				f.base.v.rs.UID = types.UID(ownerID(91))
			case "deployment":
				f.base.v.deploy.Spec.Template.Spec.Containers[0].Args = []string{"changed"}
			case "token":
				f.revoke = true
			case "clock-rollback":
				f.base.clock.Store(f.base.start.Add(-time.Nanosecond).UnixNano())
			case "expiry":
				f.base.clock.Store(r.Binding.NotAfter.UnixNano())
			}
			f.base.mu.Unlock()
			f.mu.Unlock()
			if mode == "cancel" {
				call, cancel := context.WithCancel(ctx)
				cancel()
				ctx = call
			}
			if _, err := op.Read(ctx, value.ConnectorLifecycleBeforeEffect); err == nil {
				t.Fatal("known changed native phase accepted")
			}
			f.base.clock.Store(f.base.start.Add(time.Millisecond).UnixNano())
			before := f.base.observer.Load()
			if _, err := op.Read(context.Background(), value.ConnectorLifecycleBeforeEffect); err == nil || f.base.observer.Load() != before {
				t.Fatal("terminal phase became reusable")
			}
		})
	}
}

func TestConnectorLifecycleNativeFinalDenialAndSourceMutation(t *testing.T) {
	for _, mode := range []string{"source-denial", "workload-denial", "source-during-denial", "pod"} {
		t.Run(mode, func(t *testing.T) {
			f, reader, r, ctx := lifecycleNativeFixture(t)
			op, err := reader.BeginConnectorLifecycle(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(op.Close)
			for _, phase := range []value.ConnectorLifecyclePhase{value.ConnectorLifecycleInitial, value.ConnectorLifecycleBeforeEffect, value.ConnectorLifecycleBeforeActivation} {
				lifecycleRead(t, op, ctx, phase)
			}
			f.mu.Lock()
			f.base.mu.Lock()
			switch mode {
			case "source-denial":
				f.accept = true
			case "workload-denial":
				f.base.accept = true
			case "source-during-denial":
				// This fixture changes after the fifth source GET, while the
				// final denied UPDATE is returning its original old body.
				f.mutateDuringFinalGuard = true
			case "pod":
				f.base.v.pod.Spec.Containers[0].Args = []string{"changed"}
			}
			f.base.mu.Unlock()
			f.mu.Unlock()
			if _, err := op.Read(ctx, value.ConnectorLifecycleFinal); err == nil {
				t.Fatal("final native change released successful result")
			}
		})
	}
}

func TestConnectorLifecycleNativeStatusAndShrinkingOriginalDeadline(t *testing.T) {
	f, reader, r, ctx := lifecycleNativeFixture(t)
	op, err := reader.BeginConnectorLifecycle(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	first := lifecycleRead(t, op, ctx, value.ConnectorLifecycleInitial)
	f.base.mu.Lock()
	f.base.v.pod.ResourceVersion = "200"
	f.base.v.pod.Status.Phase = core.PodPending
	f.base.v.rs.ResourceVersion = "201"
	f.base.v.deploy.ResourceVersion = "202"
	f.base.mu.Unlock()
	until := r.Binding.NotAfter.Add(-time.Second)
	short, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	next := lifecycleRead(t, op, short, value.ConnectorLifecycleBeforeActivation)
	if !next.Until.Equal(until) || !next.Original.FreshUntil.Equal(first.Original.FreshUntil) || !next.Source.Observation.ObservedAt.Equal(first.Source.Observation.ObservedAt) {
		t.Fatal("equal observation start or original/current dates mishandled")
	}
	final := lifecycleRead(t, op, ctx, value.ConnectorLifecycleFinal)
	if !final.Until.Equal(until) || final.FinalProof == nil || final.FinalProof.FreshUntil.After(until) {
		t.Fatal("later caller restored original longer cap")
	}
}

func TestConnectorLifecycleNativeParallelReadAndCloseJoin(t *testing.T) {
	f, reader, r, ctx := lifecycleNativeFixture(t)
	op, err := reader.BeginConnectorLifecycle(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	f.mu.Lock()
	f.block, f.entered, f.exited = true, make(chan struct{}), make(chan struct{})
	f.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, err := op.Read(ctx, value.ConnectorLifecycleInitial); done <- err }()
	select {
	case <-f.entered:
	case <-ctx.Done():
		t.Fatal("initial native read did not enter")
	}
	if _, err := op.Read(ctx, value.ConnectorLifecycleInitial); err == nil {
		t.Fatal("parallel phase admitted")
	}
	op.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled original phase succeeded")
		}
	case <-ctx.Done():
		t.Fatal("original Read did not return after joined Close")
	}
	select {
	case <-f.exited:
	case <-ctx.Done():
		t.Fatal("native cancelled request did not exit")
	}
}
