package evidence

import (
	"context"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type packetApprovedReadFixture struct {
	calls  int
	result query.ProjectionResult
}

func (r *packetApprovedReadFixture) ReadApprovedContext(_ context.Context, s NativeContextSource, o value.NativeOperation, scope query.ContextProjectionScope, until time.Time) (query.ProjectionResult, error) {
	r.calls++
	return r.result, nil
}

// This is the actual installed worker receiver constructor/entry point. Adapter-
// only projection tests do not exercise its separate closed source gate.
func TestPacketSummaryActualRegionalApprovedReceiver(t *testing.T) {
	for _, mode := range []string{"metadata", "raw-source", "different-pod"} {
		t.Run(mode, func(t *testing.T) {
			source, scope, _ := packetReadFixture(t)
			o := nativeLeaseFixture().Operation
			now := time.Now()
			o.Kind = value.NativeProjection
			o.Reference = value.NativeReference{InstallationID: scope.RootID, QueryID: scope.RootID, WorkerID: scope.RootID, OperationID: scope.RootID, Fence: 1}
			o.WorkerPodUID = scope.RootID
			o.SourceVersion = scope.Version
			o.StartedAt, o.Until = now, now.Add(3*time.Second)
			o.Processing.Location = source.Expectation.Registration.Location
			o.Processing.CaptureID = scope.CaptureID
			o.Processing.ObservedAt, o.Processing.ValidUntil = now, o.Until
			o.Path.StoreID, o.Path.TargetClusterID = source.Expectation.Registration.StoreID, scope.ClusterID
			reader := &packetApprovedReadFixture{result: query.ProjectionResult{PacketSummary: &query.PacketSummary{CaptureMode: "networkHeaders", DropReporting: "unavailable", Conversations: []query.PacketConversation{}}}}
			worker := value.WorkerCredentialTarget{InstallationID: scope.RootID, QueryID: scope.RootID, WorkerID: scope.RootID, PodUID: scope.RootID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
			ctx, cancel := context.WithDeadline(t.Context(), o.Until)
			defer cancel()
			r, err := NewRegionalApprovedResult(ctx, worker, reader, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				r.Close()
				if err := r.Wait(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			if mode == "raw-source" {
				source.Expectation.Recording = source.Expectation.Recording.Clone()
				source.Expectation.NativeType, source.Expectation.DataClass = artifact.RawPCAPNGArtifact, "raw"
				source.Expectation.Recording.Profile = "rawPackets"
				if !source.Valid(scope.Version) {
					t.Fatal("raw negative must use a valid published raw source")
				}
			}
			if mode == "different-pod" {
				scope.PodUID = "33333333-3333-4333-8333-333333333333"
			}
			result, err := r.ReadApproved(ctx, o, source, scope)
			if mode != "metadata" {
				if err == nil || result.PacketSummary != nil || reader.calls != 0 {
					t.Fatal("fresh receiver accepted mismatched source", mode, reader.calls, err)
				}
				return
			}
			if err != nil || !result.Valid(scope) || reader.calls != 1 {
				t.Fatalf("actual receiver rejected metadata packet before installed reader: calls=%d err=%v", reader.calls, err)
			}
			if _, err = r.ReadApproved(ctx, o, source, scope); err == nil || reader.calls != 1 {
				t.Fatal("same regional batch replayed reader")
			}

		})
	}
}
