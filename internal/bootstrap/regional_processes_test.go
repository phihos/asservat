package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/planning"
)

type processQueue struct {
	profileQueue
	cancels int
}

func (q *processQueue) NodeByName(name string) (delivery.NodeView, bool) {
	v, ok := q.profileQueue.NodeByName(name)
	v.Report.Mechanisms = []collector.Availability{{Mechanism: collector.MechanismProcesses, Prerequisites: true, Adapter: collector.AdapterAvailable}}
	return v, ok
}
func (q *processQueue) EnqueueProcesses(_ context.Context, p collector.ProcessCapture, until time.Time) (collector.Work, error) {
	w := collector.Work{ID: "33333333-3333-4333-8333-333333333333", Sequence: 1, Kind: collector.WorkProcesses, Processes: &p, NotAfter: until}
	q.profiles = append(q.profiles, w)
	return w, nil
}
func (q *processQueue) EnqueueProcessCancel(context.Context, string, string, string, time.Time) (collector.Work, error) {
	q.cancels++
	return collector.Work{}, nil
}

func processHolderFixture(t *testing.T) (*ConnectorRecordings, *processQueue, artifact.ContextExpectation, artifact.PinnedPod, time.Time) {
	t.Helper()
	h, q, reader, base, _, now := profileHolderFixture(t)
	e := profileWriterExpectation(t, base, now)
	in, compiledAt := publicArgumentPlanInput(t, []string{"write"})
	in.Retention.EvidenceType = "processSnapshot"
	in.NodeRecorder = true
	in.Composition = planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "inventory", Profile: planning.ProfileRef{Catalog: "builtin", Name: "inspect-processes", Version: "v1"}}}, MaxTotalBytes: artifact.ProcessNativeLimit, MaxDuration: "10s"}
	plan, err := compiler.CompileRecorder(in, nil, compiledAt)
	if err != nil {
		t.Fatal(err)
	}
	frozen, _ := json.Marshal(planning.ProcessesContext{Composition: in.Composition})
	e.Profile = nil
	e.NativeType = artifact.ProcessesArtifact
	e.DataClass = "metadata"
	e.ActionID = plan.Actions[0].ID
	e.Registration.NativeLimit = artifact.ProcessNativeLimit
	e.Processes = &artifact.ProcessCapture{ActionID: e.ActionID, Mode: artifact.ProcessAll, TimeoutMillis: 5000, MaxNativeBytes: artifact.ProcessNativeLimit, Composition: frozen}
	if err := e.Validate(); err != nil {
		t.Fatal("process holder fixture", err)
	}
	queue := &processQueue{profileQueue: *q}
	h.nodes = queue
	return h, queue, e, reader.plan.Pin, now
}

func TestProcessStopFencesLateStartAndRequiresJoinedSource(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-dispatch", false: "blocked-source"}[before], func(t *testing.T) {
			h, q, e, pin, now := processHolderFixture(t)
			stop := collector.ProcessStop{RootID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, WriterPodUID: e.CaptureUID, WriterEpoch: e.CaptureUID, ExpectationDigest: evidence.ContextExpectationDigest(e), WriteUntil: e.Registration.WriteUntil}
			p := h.PrepareProcesses(&objectstore.PreparedArtifact{}, e)
			if !before {
				if _, err := p.StartProcesses(t.Context(), pin, now, now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.CancelProcesses(t.Context(), stop); err != nil {
				t.Fatal(err)
			}
			work := fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: stop.ExpectationDigest}
			if before {
				if _, err := p.StartProcesses(t.Context(), pin, now, now.Add(time.Second)); err == nil || len(q.profiles) != 0 {
					t.Fatal("stopped source started")
				}
			} else {
				out, err := h.Collect(work)
				if err != nil || out.State != evidence.RecordingPending || q.cancels != 1 {
					t.Fatal("queued stop claimed positive source join", out, err)
				}
				r := collector.ProcessResult{WorkID: q.profiles[0].ID, CaptureID: e.CaptureUID, PodUID: e.PodUID, NodeUID: q.node.NodeUID, NodeBootID: q.node.BootID, ExpectationDigest: stop.ExpectationDigest, StartedAt: now, CompletedAt: now, Failure: collector.ReasonCaptureFailed}
				if err := h.DeliverProcesses(t.Context(), q.node, r, bytes.NewReader(nil)); err != nil {
					t.Fatal(err)
				}
			}
			out, err := h.Collect(work)
			if err != nil || out.State != evidence.RecordingCancelled || out.ProcessesCancellation == nil || out.ProfileCancellation != nil || !out.Valid(e.Registration) {
				t.Fatal("typed source/writer join missing", out, err)
			}
			wrong := stop
			wrong.WriterEpoch = "22222222-2222-4222-8222-222222222222"
			if h.CancelProcesses(t.Context(), wrong) == nil {
				t.Fatal("replacement writer inherited cancellation")
			}
		})
	}
}
