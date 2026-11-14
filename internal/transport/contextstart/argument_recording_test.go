package contextstart

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/targets"
)

type argumentRecorderOutput struct {
	fakeRecorderOutput
	argumentStarts int
}

func (o *argumentRecorderOutput) StartArgumentRecording(_ context.Context, _ artifact.PinnedPod, started, _ time.Time, _ targets.PacketSourceObservation, _ collector.ArgumentObservationPermit) (time.Time, error) {
	o.argumentStarts++
	return started, o.err
}

type argumentSourceResolver struct {
	countingLocal
	result      targets.RecorderResolution
	sourceReads int
}

func (r *argumentSourceResolver) ResolveArgumentSource(context.Context, targets.Request) (targets.RecorderResolution, error) {
	r.sourceReads++
	return r.result, nil
}
func argumentOperationExpectation(capture, pod string, now time.Time) artifact.ContextExpectation {
	return artifact.ContextExpectation{CaptureUID: capture, ActionID: "a0123456789abcdef01234567", PodUID: pod, NativeType: artifact.SyscallArgumentsArtifact, DataClass: "raw", Registration: artifact.Registration{WriteUntil: now.Add(time.Minute)},
		Recording: &artifact.Recording{Kind: "syscallTrace", Profile: "arguments", Composition: []byte("{}"), DurationMillis: 1000, MaxBytes: 64 << 10,
			Syscalls:  &artifact.RecordingSyscalls{Names: []string{"read", "write"}, MaxEvents: 1000, MaxEventsPerSecond: 100, MaxTrackedThreads: 16},
			Arguments: &artifact.RecordingArguments{ProgramDigest: artifact.Digest{2}, DefinitionDigest: artifact.Digest{3}, AccountingRule: artifact.Digest(collector.ArgumentObservationAccountingRule()), MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxBytesPerSecond: 1 << 20, CaptureBuffers: true}}}
}
func argumentOperationPermit(e artifact.ContextExpectation, s targets.PacketSourceObservation, n time.Time) collector.ArgumentObservationPermit {
	return collector.ArgumentObservationPermit{Binding: collector.ArgumentObservationBinding{Scope: [32]byte{1}, ProgramDigest: [32]byte{2}, DefinitionDigest: [32]byte{3}, ExpectationDigest: [32]byte(evidence.ContextExpectationDigest(e)), AccountingRule: collector.ArgumentObservationAccountingRule(), SessionID: "66666666-6666-4666-8666-666666666666", Fence: "77777777-7777-4777-8777-777777777777", CaptureID: e.CaptureUID, ActionID: e.ActionID, PodUID: e.PodUID, NodeUID: s.NodeUID, BootID: s.BootID, CollectorPodUID: s.CollectorPodUID, CollectorEpoch: s.CollectorEpoch}, StartedAt: n, SessionUntil: n.Add(4 * time.Second), LeaseUntil: n.Add(4 * time.Second), StartBy: n.Add(2 * time.Second), Duration: time.Second, Sequence: 1, EventCredit: 1000, ByteCredit: 1 << 20, EventsPerSecond: 100, BytesPerSecond: 1 << 20, MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxTrackedThreads: 16, CaptureBuffers: true}
}
func TestArgumentSourceOperationNeverFallsBackOrRefreshes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, mode := range []string{"exact", "unsupported", "stale", "wrong-target", "missing-source"} {
		t.Run(mode, func(t *testing.T) {
			w := workFixture().Work
			r := targets.Request{ClusterID: w.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: "app", UID: w.Target.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "app", UID: w.Target.WorkloadUID}, PodName: "app-0", PodUID: w.Target.PodUID}
			source := targets.PacketSourceObservation{PodUID: r.PodUID, NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
			resolver := &argumentSourceResolver{result: targets.RecorderResolution{Target: targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: r, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: r.Namespace.UID, Name: r.PodName, UID: r.PodUID, ControllerUID: "rs"}, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Recorder: targets.RecorderAnswer{Outcome: targets.RecorderAvailable, Source: &source}}}
			local := resolver.countingLocal.local()
			local.Targets = resolver
			local.Now = func() time.Time { return now }
			switch mode {
			case "unsupported":
				local.Targets = &resolver.countingLocal
			case "stale":
				source.FreshUntil = now
			case "wrong-target":
				w.Target.PodUID = "other"
			case "missing-source":
				resolver.result.Recorder.Source = nil
			}
			s := &regionalSession{local: local, work: w}
			body, _ := json.Marshal(r)
			q := contracts.APIContextOperation{Method: opResolveArgumentSource, Body: body}
			_, err := s.handle(t.Context(), q)
			if mode != "exact" {
				if err == nil || s.resolved != nil || s.argumentSource != nil || resolver.calls != 0 {
					t.Fatal("argument source fell back", err)
				}
				return
			}
			if err != nil || s.argumentSource == nil || s.packetSource != nil || resolver.sourceReads != 1 {
				t.Fatal("source not retained distinctly", err)
			}
			source.CollectorEpoch = "replacement"
			if s.argumentSource.CollectorEpoch != "epoch" {
				t.Fatal("source alias changed")
			}
			for _, method := range []string{opResolveArgumentSource, opResolvePacketSource, opResolvePod} {
				if _, err := s.handle(t.Context(), contracts.APIContextOperation{Method: method, Body: body}); err == nil || resolver.sourceReads != 1 || resolver.calls != 0 {
					t.Fatal("source refreshed or fell back", method, err)
				}
			}
		})
	}
}
func TestArgumentStartOperationBindsIndependentWorkSourceAndCommittedStart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, mode := range []string{"exact", "source-epoch", "source-cutoff", "permit-epoch", "program", "definitions", "expectation", "action", "capture", "read-width", "buffers", "byte-rate", "event-rate", "threads", "duration", "deadline", "expired", "no-source", "packet-source", "class", "legacy-start", "packet-start"} {
		t.Run(mode, func(t *testing.T) {
			w := workFixture().Work
			e := argumentOperationExpectation(w.CaptureID, w.Target.PodUID, now)
			w.ExpectationDigest = evidence.ContextExpectationDigest(e)
			source := targets.PacketSourceObservation{PodUID: e.PodUID, NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
			pin := artifact.PinnedPod{UID: e.PodUID}
			request := argumentRecordingRequest{Pin: pin, Started: now, Until: now.Add(3 * time.Second), Source: source, Permit: argumentOperationPermit(e, source, now)}
			output := &argumentRecorderOutput{}
			local := (&countingLocal{}).local()
			local.Now = func() time.Time { return now }
			s := &regionalSession{local: local, work: w, prepared: output, resolved: &targets.PodResolution{Pin: pin}, argumentSource: &source, expectation: &e}
			switch mode {
			case "source-epoch":
				request.Source.CollectorEpoch = "replacement"
			case "source-cutoff":
				request.Source.FreshUntil = request.Source.FreshUntil.Add(time.Second)
			case "permit-epoch":
				request.Permit.Binding.CollectorEpoch = "replacement"
			case "program":
				request.Permit.Binding.ProgramDigest[0]++
			case "definitions":
				request.Permit.Binding.DefinitionDigest[0]++
			case "expectation":
				request.Permit.Binding.ExpectationDigest[0]++
			case "action":
				request.Permit.Binding.ActionID = "other"
			case "capture":
				request.Permit.Binding.CaptureID = "other"
			case "read-width":
				request.Permit.MaxBytesPerEvent++
			case "buffers":
				request.Permit.CaptureBuffers = false
			case "byte-rate":
				request.Permit.BytesPerSecond++
			case "event-rate":
				request.Permit.EventsPerSecond++
			case "threads":
				request.Permit.MaxTrackedThreads++
			case "duration":
				request.Permit.Duration += time.Second
			case "deadline":
				request.Until = s.work.NotAfter.Add(time.Second)
			case "expired":
				request.Permit.StartBy = now
			case "no-source":
				s.argumentSource = nil
			case "packet-source":
				s.packetSource = &source
				s.argumentSource = nil
			case "class":
				e.DataClass = "metadata"
				s.work.ExpectationDigest = evidence.ContextExpectationDigest(e)
				request.Permit.Binding.ExpectationDigest = [32]byte(s.work.ExpectationDigest)
			}
			body, _ := json.Marshal(request)
			q := contracts.APIContextOperation{Method: opStartArgumentRecording, Body: body}
			if mode == "legacy-start" {
				q.Method = opStartRecording
				q.Body, _ = json.Marshal(acquireRequest{pin, now, request.Until})
			}
			if mode == "packet-start" {
				q.Method = opStartPolicyRecording
				q.Body, _ = json.Marshal(policyRecordingRequest{Pin: pin, Started: now, Until: request.Until, Source: source})
			}
			_, err := s.handle(t.Context(), q)
			if mode != "exact" {
				if err == nil || output.argumentStarts != 0 || output.started != 0 || s.acquired {
					t.Fatal("invalid argument dispatch", mode, err)
				}
				return
			}
			if err != nil || output.argumentStarts != 1 || !s.acquired {
				t.Fatal("exact argument start", err)
			}
			if _, err := s.handle(t.Context(), q); err == nil || output.argumentStarts != 1 {
				t.Fatal("repeated start", err)
			}
		})
	}
}
