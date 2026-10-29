package contextstart

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type policyRecorderOutput struct {
	fakeRecorderOutput
	policyStarts int
}

func (o *policyRecorderOutput) StartPolicyRecording(_ context.Context, _ artifact.PinnedPod, started, _ time.Time, _ targets.PacketSourceObservation, _ collector.ObservationPermit) (time.Time, error) {
	o.policyStarts++
	return started, nil
}

// The source comes from the local resolver and the expectation from verified
// signed work, independently of the later caller-supplied observation receipt.
func TestPolicyRecordingOperationPinsIndependentWorkAndSource(t *testing.T) {
	id := func(n string) string { return "10000000-0000-4000-8000-0000000000" + n }
	now := time.Now().UTC().Truncate(time.Microsecond)
	program := []planning.BPFInstruction{{Code: 6, K: 65535}}
	e := artifact.ContextExpectation{CaptureUID: id("16"), ActionID: "a0123456789abcdef01234567", PodUID: id("20"), Recording: &artifact.Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: []byte("{}"), Filter: &artifact.RecordingFilter{Expression: "tcp[13] & 2 != 0", Program: []artifact.FilterInstruction{{Code: 6, K: 65535}}}, DurationMillis: 1000, MaxBytes: 64 << 10, Snaplen: artifact.RecordingSnaplen}}
	source := targets.PacketSourceObservation{PodUID: e.PodUID, NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	permit := collector.ObservationPermit{Binding: collector.ObservationBinding{Scope: [32]byte{1}, ProgramDigest: [32]byte(compiler.FilterProgramDigest(program)), ExpectationDigest: [32]byte(evidence.ContextExpectationDigest(e)), AccountingRule: collector.ObservationAccountingRule(), SessionID: id("30"), Fence: id("31"), CaptureID: e.CaptureUID, ActionID: e.ActionID, PodUID: e.PodUID, NodeUID: source.NodeUID, BootID: source.BootID, CollectorPodUID: source.CollectorPodUID, CollectorEpoch: source.CollectorEpoch}, StartedAt: now, SessionUntil: now.Add(4 * time.Second), LeaseUntil: now.Add(4 * time.Second), StartBy: now.Add(2 * time.Second), Duration: time.Second, Sequence: 1, Credit: 1 << 20, BytesPerSecond: 1 << 20}
	pin := artifact.PinnedPod{UID: e.PodUID}
	base := policyRecordingRequest{Pin: pin, Started: now, Until: now.Add(3 * time.Second), Source: source, Permit: permit}
	for _, test := range []struct {
		name   string
		change func(*policyRecordingRequest, *regionalSession)
	}{
		{"valid", func(*policyRecordingRequest, *regionalSession) {}},
		{"source-epoch", func(r *policyRecordingRequest, _ *regionalSession) { r.Source.CollectorEpoch = "replacement" }},
		{"source-cutoff", func(r *policyRecordingRequest, _ *regionalSession) {
			r.Source.FreshUntil = r.Source.FreshUntil.Add(time.Second)
		}},
		{"receipt-epoch", func(r *policyRecordingRequest, _ *regionalSession) { r.Permit.Binding.CollectorEpoch = "replacement" }},
		{"program", func(r *policyRecordingRequest, _ *regionalSession) { r.Permit.Binding.ProgramDigest = [32]byte{9} }},
		{"expectation", func(r *policyRecordingRequest, _ *regionalSession) { r.Permit.Binding.ExpectationDigest = [32]byte{9} }},
		{"capture", func(r *policyRecordingRequest, _ *regionalSession) { r.Permit.Binding.CaptureID = id("40") }},
		{"action", func(r *policyRecordingRequest, _ *regionalSession) { r.Permit.Binding.ActionID = "another" }},
		{"duration", func(r *policyRecordingRequest, _ *regionalSession) { r.Permit.Duration = 2 * time.Second }},
		{"committed-start", func(r *policyRecordingRequest, _ *regionalSession) { r.Started = r.Started.Add(time.Microsecond) }},
		{"expired-start", func(r *policyRecordingRequest, _ *regionalSession) { r.Permit.StartBy = now }},
		{"ordinary-actor", func(_ *policyRecordingRequest, s *regionalSession) { s.work.Actor = workFixture().Work.Actor }},
		{"no-local-source", func(_ *policyRecordingRequest, s *regionalSession) { s.packetSource = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := &policyRecorderOutput{}
			w := workFixture().Work
			w.Actor = authorization.PolicyPrincipal(id("10"), "policy")
			w.CaptureID = e.CaptureUID
			w.ExpectationDigest = evidence.ContextExpectationDigest(e)
			local := (&countingLocal{}).local()
			local.Now = func() time.Time { return now }
			s := &regionalSession{local: local, work: w, prepared: output, resolved: &targets.PodResolution{Pin: pin}, packetSource: &source, expectation: &e, consumed: &value.Disposition{MayStart: true, Phase: value.StartCommitted, CommittedAt: now, ValidUntil: now.Add(3 * time.Second)}}
			r := base
			test.change(&r, s)
			b, _ := json.Marshal(r)
			q := contracts.APIContextOperation{Method: opStartPolicyRecording, Body: b}
			_, err := s.handle(t.Context(), q)
			if test.name == "valid" {
				if err != nil || output.policyStarts != 1 || output.started != 0 {
					t.Fatalf("typed start: %v/%d/%d", err, output.policyStarts, output.started)
				}
				if _, err = s.handle(t.Context(), q); err == nil || output.policyStarts != 1 {
					t.Fatal("replayed dispatch", err)
				}
			} else if err == nil || output.policyStarts != 0 || output.started != 0 {
				t.Fatalf("invalid dispatch: %v/%d/%d", err, output.policyStarts, output.started)
			}
		})
	}
}

type policySourceResolver struct {
	countingLocal
	result      targets.RecorderResolution
	sourceReads int
}

func (r *policySourceResolver) ResolvePacketSource(context.Context, targets.Request) (targets.RecorderResolution, error) {
	r.sourceReads++
	return r.result, nil
}

func TestPolicySourceOperationNeverFallsBackOrRefreshes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, mode := range []string{"valid", "ordinary-actor", "unsupported", "stale", "wrong-target", "missing-source"} {
		t.Run(mode, func(t *testing.T) {
			w := workFixture().Work
			w.Actor = authorization.PolicyPrincipal(w.Channel.Hub.InstallationID, "policy")
			request := targets.Request{ClusterID: w.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: "app", UID: w.Target.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "app", UID: w.Target.WorkloadUID}, PodName: "app-0", PodUID: w.Target.PodUID}
			pin := artifact.PinnedPod{Namespace: "app", NamespaceUID: w.Target.NamespaceUID, Name: request.PodName, UID: request.PodUID, ControllerUID: "rs"}
			source := targets.PacketSourceObservation{PodUID: pin.UID, NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
			resolver := &policySourceResolver{result: targets.RecorderResolution{Target: targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: request, Pin: pin, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Recorder: targets.RecorderAnswer{Outcome: targets.RecorderAvailable, Source: &source}}}
			local := resolver.countingLocal.local()
			local.Targets = resolver
			local.Now = func() time.Time { return now }
			switch mode {
			case "ordinary-actor":
				w.Actor = workFixture().Work.Actor
			case "unsupported":
				local.Targets = &resolver.countingLocal
			case "stale":
				source.FreshUntil = now
			case "wrong-target":
				w.Target.PodUID = "another"
			case "missing-source":
				resolver.result.Recorder.Source = nil
			}
			s := &regionalSession{local: local, work: w}
			b, _ := json.Marshal(request)
			q := contracts.APIContextOperation{Method: opResolvePacketSource, Body: b}
			_, err := s.handle(t.Context(), q)
			if mode != "valid" {
				if err == nil || s.resolved != nil || s.packetSource != nil || resolver.calls != 0 {
					t.Fatal("source refusal fell back", err, resolver.calls)
				}
				return
			}
			if err != nil || s.packetSource == nil || resolver.sourceReads != 1 || resolver.calls != 0 {
				t.Fatal("source resolution", err, resolver.sourceReads, resolver.calls)
			}
			// Resolver-owned aliases cannot rewrite the retained original observation.
			source.CollectorEpoch = "replacement"
			if s.packetSource.CollectorEpoch != "epoch" {
				t.Fatal("source alias changed accepted facts")
			}
			if _, err = s.handle(t.Context(), q); err == nil || resolver.sourceReads != 1 {
				t.Fatal("source refreshed within work", err, resolver.sourceReads)
			}
		})
	}
}
