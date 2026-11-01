package contextstart

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type policyStreamLocal struct {
	*policySourceResolver
	output    *policyRecorderOutput
	committed value.Disposition
}

func (l *policyStreamLocal) PrepareContext(context.Context, artifact.ContextExpectation) (evidence.PreparedContext, error) {
	return l.output, nil
}
func (l *policyStreamLocal) ConsumeStart(context.Context, value.Request) (value.Disposition, error) {
	return l.committed, nil
}

// Actual bounded framing and both operation endpoints, with synthetic verified
// work/start/recorder facts. This does not claim TLS, SQL or signature authority.
func TestFinitePolicySourceAndStartUseOneFramedConversation(t *testing.T) {
	for _, mode := range []string{"exact", "tampered-program"} {
		t.Run(mode, func(t *testing.T) {
			authenticated := workFixture()
			w := authenticated.Work
			n := w.IssuedAt
			w.Actor = authorization.PolicyPrincipal(w.Channel.Hub.InstallationID, "policy")
			request := targets.Request{ClusterID: w.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: "app", UID: w.Target.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "app", UID: w.Target.WorkloadUID}, PodName: "app-0", PodUID: w.Target.PodUID}
			pin := artifact.PinnedPod{Namespace: "app", NamespaceUID: w.Target.NamespaceUID, Name: request.PodName, UID: request.PodUID, ControllerUID: "rs"}
			source := targets.PacketSourceObservation{PodUID: pin.UID, NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
			e := artifact.ContextExpectation{CaptureUID: w.CaptureID, ActionID: "a0123456789abcdef01234567", PodUID: pin.UID, Recording: &artifact.Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: []byte("{}"), Filter: &artifact.RecordingFilter{Expression: "tcp[13] & 2 != 0", Program: []artifact.FilterInstruction{{Code: 6, K: 65535}}}, DurationMillis: 1000, MaxBytes: 64 << 10, Snaplen: artifact.RecordingSnaplen}}
			w.ExpectationDigest = evidence.ContextExpectationDigest(e)
			authenticated.Work = w
			permit := collector.ObservationPermit{Binding: collector.ObservationBinding{Scope: [32]byte{1}, ProgramDigest: [32]byte(compiler.FilterProgramDigest([]planning.BPFInstruction{{Code: 6, K: 65535}})), ExpectationDigest: [32]byte(w.ExpectationDigest), AccountingRule: collector.ObservationAccountingRule(), SessionID: w.Channel.ExchangeID, Fence: w.Channel.Challenge, CaptureID: w.CaptureID, ActionID: e.ActionID, PodUID: pin.UID, NodeUID: source.NodeUID, BootID: source.BootID, CollectorPodUID: source.CollectorPodUID, CollectorEpoch: source.CollectorEpoch}, StartedAt: n, SessionUntil: n.Add(4 * time.Second), LeaseUntil: n.Add(4 * time.Second), StartBy: n.Add(2 * time.Second), Duration: time.Second, Sequence: 1, Credit: 1 << 20, BytesPerSecond: 1 << 20}
			resolver := &policySourceResolver{result: targets.RecorderResolution{Target: targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: request, Pin: pin, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, Recorder: targets.RecorderAnswer{Outcome: targets.RecorderAvailable, Source: &source}}}
			output := &policyRecorderOutput{}
			local := &policyStreamLocal{policySourceResolver: resolver, output: output, committed: value.Disposition{MayStart: true, Phase: value.StartCommitted, CommittedAt: n, ValidUntil: n.Add(3 * time.Second)}}
			ports := resolver.countingLocal.local()
			ports.Targets = local
			ports.Output = local
			ports.Starts = local
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			receiver := fleet.APIContextReceiver{Channel: w.Channel, ObservedAt: n, ValidUntil: w.NotAfter}
			hub, region := historyStreamPair(t, ctx, receiver)
			joined := make(chan error, 1)
			go func() {
				joined <- ServeRegionalOperations(ctx, region, receiver, streamDiagnosticVerifier(func(_ context.Context, signed []byte, got fleet.APIContextReceiver) (fleet.AuthenticatedAPIContextWork, error) {
					if string(signed) != "synthetic-signed-work" || got.Channel != w.Channel {
						return fleet.AuthenticatedAPIContextWork{}, fleet.ErrDenied
					}
					return authenticated, nil
				}), ports, time.Now)
			}()
			state, err := ServeHubOperations(ctx, hub, w, []byte("synthetic-signed-work"), func(call context.Context, ops *HubOperations) (string, error) {
				resolved, err := ops.ResolvePacketSource(call, request)
				if err != nil {
					return "Unavailable", err
				}
				if !resolved.ValidSource(time.Now()) || !samePacketSource(*resolved.Recorder.Source, source) {
					return "Unavailable", value.ErrConflict
				}
				prepared, err := ops.PrepareContext(call, e)
				if err != nil {
					return "Unavailable", err
				}
				defer prepared.Close()
				binding := value.Binding{CaptureID: w.CaptureID, AttemptID: w.AttemptID, ClusterID: w.Target.ClusterID, PodUID: w.Target.PodUID, ScopeDigest: w.ScopeDigest}
				d, err := ops.ConsumeStart(call, value.Request{Binding: binding})
				if err != nil {
					return "Unavailable", err
				}
				sent := permit
				if mode == "tampered-program" {
					sent.Binding.ProgramDigest = [32]byte{9}
				}
				typed := prepared.(evidence.PolicyContextRecorder)
				queued, err := typed.StartPolicyRecording(call, pin, d.CommittedAt, d.ValidUntil, *resolved.Recorder.Source, sent)
				if err != nil {
					return "Unavailable", err
				}
				if !queued.Equal(n) {
					return "Unavailable", value.ErrConflict
				}
				return "Recording", nil
			}, time.Now)
			if mode == "exact" {
				if err != nil || state != "Recording" || output.policyStarts != 1 {
					t.Fatal("typed stream start", state, err, output.policyStarts)
				}
			} else if !errors.Is(err, value.ErrDenied) || state != "Unavailable" || output.policyStarts != 0 {
				t.Fatal("tampered stream dispatch", state, err, output.policyStarts)
			}
			select {
			case err := <-joined:
				if err != nil {
					t.Fatal("regional conversation did not finish", err)
				}
			case <-ctx.Done():
				t.Fatal("regional conversation did not join", ctx.Err())
			}
			if resolver.sourceReads != 1 || resolver.calls != 0 || output.started != 0 {
				t.Fatal("source refresh or ordinary fallback", resolver.sourceReads, resolver.calls, output.started)
			}
		})
	}
}
