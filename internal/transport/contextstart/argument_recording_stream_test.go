package contextstart

import (
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type argumentStreamLocal struct {
	*argumentSourceResolver
	output    *argumentRecorderOutput
	committed value.Disposition
}

func (l *argumentStreamLocal) PrepareContext(context.Context, artifact.ContextExpectation) (evidence.PreparedContext, error) {
	return l.output, nil
}
func (l *argumentStreamLocal) ConsumeStart(context.Context, value.Request) (value.Disposition, error) {
	return l.committed, nil
}

// Actual bounded framing and both operation endpoints, with synthetic verified
// work/start/recorder facts. This does not claim TLS, SQL or signature authority.
func TestFiniteArgumentSourceAndStartUseOneFramedConversation(t *testing.T) {
	for _, mode := range []string{"exact", "tampered-program", "unknown-reply"} {
		t.Run(mode, func(t *testing.T) {
			authenticated := workFixture()
			w := authenticated.Work
			n := w.IssuedAt
			request := targets.Request{ClusterID: w.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: "app", UID: w.Target.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "app", UID: w.Target.WorkloadUID}, PodName: "app-0", PodUID: w.Target.PodUID}
			pin := artifact.PinnedPod{Namespace: "app", NamespaceUID: w.Target.NamespaceUID, Name: request.PodName, UID: request.PodUID, ControllerUID: "rs"}
			source := targets.PacketSourceObservation{PodUID: pin.UID, NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
			e := argumentOperationExpectation(w.CaptureID, pin.UID, n)
			w.ExpectationDigest = evidence.ContextExpectationDigest(e)
			authenticated.Work = w
			permit := argumentOperationPermit(e, source, n)
			resolver := &argumentSourceResolver{result: targets.RecorderResolution{Target: targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: request, Pin: pin, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, Recorder: targets.RecorderAnswer{Outcome: targets.RecorderAvailable, Source: &source}}}
			output := &argumentRecorderOutput{}
			if mode == "unknown-reply" {
				output.err = value.ErrUnavailable
			}
			local := &argumentStreamLocal{argumentSourceResolver: resolver, output: output, committed: value.Disposition{MayStart: true, Phase: value.StartCommitted, CommittedAt: n, ValidUntil: n.Add(3 * time.Second)}}
			ports := resolver.countingLocal.local()
			ports.Targets = local
			ports.Output = local
			ports.Starts = local
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			receiver := fleet.APIContextReceiver{Channel: w.Channel, Window: identity.Check(n, identity.Recheck).Narrow(w.NotAfter)}
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
				resolved, err := ops.ResolveArgumentSource(call, request)
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
				typed := prepared.(evidence.ArgumentContextRecorder)
				queued, err := typed.StartArgumentRecording(call, pin, d.CommittedAt, d.ValidUntil, *resolved.Recorder.Source, sent)
				if mode == "unknown-reply" {
					if !errors.Is(err, value.ErrUnavailable) {
						return "Unavailable", value.ErrConflict
					}
					if _, again := typed.StartArgumentRecording(call, pin, d.CommittedAt, d.ValidUntil, *resolved.Recorder.Source, sent); !errors.Is(again, value.ErrDenied) {
						return "Unavailable", value.ErrConflict
					}
					return "Unavailable", err
				}
				if err != nil {
					return "Unavailable", err
				}
				if !queued.Equal(n) {
					return "Unavailable", value.ErrConflict
				}
				return "Recording", nil
			}, time.Now)
			if mode == "exact" {
				if err != nil || state != "Recording" || output.argumentStarts != 1 {
					t.Fatal("typed stream start", state, err, output.argumentStarts)
				}
			} else if mode == "unknown-reply" {
				if !errors.Is(err, value.ErrUnavailable) || output.argumentStarts != 1 {
					t.Fatal("uncertain start repeated", err, output.argumentStarts)
				}
			} else if !errors.Is(err, value.ErrDenied) || state != "Unavailable" || output.argumentStarts != 0 {
				t.Fatal("tampered stream dispatch", state, err, output.argumentStarts)
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
