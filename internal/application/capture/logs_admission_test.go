package capture

import (
	"context"
	"errors"
	"testing"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type logsNoNodeRecorders struct {
	availableRecording
	calls int
}

func (r *logsNoNodeRecorders) ResolvePacketRecorder(context.Context, targets.Request) (targets.PodResolution, error) {
	r.calls++
	return targets.PodResolution{}, targets.ErrUnsupported
}

func TestLogsPreviewAndAdmissionNeedNoNodeOrImplicitRawCollectionReview(t *testing.T) {
	base := newInvestigationFixture()
	f := &retainedRecording{investigationFixture: base}
	base.target.NodeUID, base.target.NodeBootID, base.target.Pin.NodeName = "", "", ""
	base.target.ExecutionClass, base.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	base.svc.Previews, base.svc.Admission = f, f
	// Actual API deployments may have node recorders too; logs must still use
	// ordinary exact Pod resolution, not a packet-recorder availability path.
	recorders := &logsNoNodeRecorders{availableRecording: availableRecording{base}}
	base.svc.Recorders = recorders
	c := planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "logs", Profile: planning.ProfileRef{Catalog: "builtin", Name: "finite-logs", Version: "v1"}}}, MaxTotalBytes: 10 << 20, MaxDuration: "10s"}
	preview, err := base.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(&c))
	if err != nil || !preview.Recordable || preview.Plan.Approval != nil {
		t.Fatal("ordinary logs preview invented review/node requirement", err)
	}
	if _, err := f.request(t, preview.Preview, "logs-original"); !errors.Is(err, reachedRecordingAdmission) || len(f.seen) != 1 {
		t.Fatal("logs did not reach actual admission boundary", err)
	}
	a := f.seen[0]
	logs, _, err := compiler.LogsForContext(a.Plan)
	if err != nil || a.Plan.Input.Logs == nil || a.Plan.Input.Recorder != nil || a.Registration.NativeLimit != logs.MaxNativeBytes || logs.Streams != "combined" || logs.BeforeMillis != 10000 || logs.AfterMillis != 0 || a.Plan.ScopeDigest != preview.Preview.ScopeDigest {
		t.Fatal("logs accepted plan lost exact reviewed bounds", err)
	}
	if a.Plan.Input.Target.ExecutionClass != artifact.ContextAPIExecution || a.Plan.Input.Target.NodeUID != "" {
		t.Fatal("logs invented node identity")
	}
	if recorders.calls != 0 {
		t.Fatal("logs called node-recorder resolver")
	}
}
