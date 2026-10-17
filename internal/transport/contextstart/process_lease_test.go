package contextstart

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
)

// leaseLocal counts process reads and records which start variant ran.
type leaseLocal struct {
	countingLocal
	process            value.APIProcessObservation
	reads              int
	plain, observed    int
	observedProcess    value.APIProcessObservation
	implementsObserved bool
}

func (l *leaseLocal) ReadAPIProcess(context.Context) (value.APIProcessObservation, error) {
	l.reads++
	return l.process, nil
}
func (l *leaseLocal) PrepareStart(context.Context, value.PreparationCheck) (value.PreparedStart, error) {
	l.plain++
	return value.PreparedStart{}, nil
}
func (l *leaseLocal) ReadyStart(context.Context, value.Request) (value.Disposition, error) {
	l.plain++
	return value.Disposition{}, nil
}

type observedLeaseLocal struct{ *leaseLocal }

func (l observedLeaseLocal) PrepareObservedStart(_ context.Context, _ value.PreparationCheck, p value.APIProcessObservation) (value.PreparedStart, error) {
	l.observed++
	l.observedProcess = p
	return value.PreparedStart{}, nil
}
func (l observedLeaseLocal) ReadyObservedStart(_ context.Context, _ value.Request, p value.APIProcessObservation) (value.Disposition, error) {
	l.observed++
	l.observedProcess = p
	return value.Disposition{}, nil
}

// ADR-173: one complete process observation serves every operation of one
// verified work until its original deadline, and is never renewed.
func TestRegionalSessionReusesOneProcessObservationPerWork(t *testing.T) {
	w := workFixture().Work
	now := time.Now().UTC().Truncate(time.Microsecond)
	clock := now
	id := func(n string) string { return "00000000-0000-4000-8000-0000000000" + n }
	process := value.APIProcessObservation{Binding: value.APIProcessBinding{InstallationID: id("01"), ClusterID: w.Target.ClusterID, IssuerEpoch: id("03"), NamespaceUID: id("13"), AccountUID: id("14"), PodUID: id("08"), ProcessEpoch: id("15"), StartupDigest: artifact.Digest{2}, ImageDigest: artifact.Digest{3}}, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}
	binding := value.Binding{ExecutionClass: artifact.ContextAPIExecution, OperationID: id("30"), CaptureID: w.CaptureID, ActionID: "pod-status", AttemptID: w.AttemptID, ClusterID: w.Target.ClusterID, IssuerEpoch: id("03"), PodUID: w.Target.PodUID, ExecutorPodUID: id("08"), ExecutorAccountUID: id("14"), CollectorEpoch: id("15"), ScopeDigest: w.ScopeDigest, NativeBytes: artifact.MaxContextBytes, NotBefore: now, NotAfter: now.Add(5 * time.Second)}
	op := func(method string, body any) contracts.APIContextOperation {
		b, _ := json.Marshal(body)
		if body == nil {
			b = []byte(`{}`)
		}
		return contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: method, Body: b}
	}
	for _, implements := range []bool{true, false} {
		l := &leaseLocal{process: process}
		local := l.countingLocal.local()
		local.Process, local.Now = l, func() time.Time { return clock }
		local.Local = l
		if implements {
			local.Local = observedLeaseLocal{l}
		}
		clock = now
		s := &regionalSession{local: local, work: w}
		ctx := context.Background()
		for range 3 {
			out, err := s.handle(ctx, op(opReadProcess, nil))
			if err != nil || out.(value.APIProcessObservation) != process {
				t.Fatal("work observation not returned unchanged", err)
			}
		}
		if l.reads != 1 {
			t.Fatalf("process read %d times within one original interval", l.reads)
		}
		if _, err := s.handle(ctx, op(opPrepareStart, value.PreparationCheck{Binding: binding, CheckedAt: now, ValidUntil: process.ValidUntil, MayCreate: true})); err != nil {
			t.Fatal(err)
		}
		if _, err := s.handle(ctx, op(opReadyStart, value.Request{Binding: binding, ObjectUID: id("31"), CheckedAt: now, ValidUntil: process.ValidUntil})); err != nil {
			t.Fatal(err)
		}
		if implements && (l.observed != 2 || l.plain != 0 || l.observedProcess != process) {
			t.Fatal("observed start variant not used with the work observation")
		}
		if !implements && (l.plain != 2 || l.observed != 0) {
			t.Fatal("plain start port not used")
		}
		// After the original deadline the observation is never renewed: a new
		// complete read replaces it, and starts no longer use the old one.
		clock = process.ValidUntil
		if _, err := s.handle(ctx, op(opReadProcess, nil)); err != nil || l.reads != 2 {
			t.Fatal("expired observation reused", l.reads, err)
		}
		if s.observed(binding) {
			t.Fatal("expired read accepted as the work observation")
		}
		// A start for a different executor process never uses the observation.
		clock = now
		s.process = &process
		other := binding
		other.CollectorEpoch = id("40")
		if s.observed(other) {
			t.Fatal("observation of another process accepted")
		}
	}
}
