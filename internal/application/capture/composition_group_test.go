package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type bothRecorders struct{ availableRecording }

func (b bothRecorders) ResolveSyscallRecorder(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	return b.ResolvePacketRecorder(ctx, r)
}
func (bothRecorders) SyscallRecorder(context.Context, targets.PodResolution) error { return nil }

// mixedComposition is the native manual-mixed focus's request.
func mixedComposition() *planning.ProfileComposition {
	c := networkComposition(planning.ProfileEdit{ActionID: "sample", Field: "packetFilter", Text: "tcp port 8080"}, planning.ProfileEdit{ActionID: "sample", Field: "packetAfter", Text: "5s"}, planning.ProfileEdit{ActionID: "sample", Field: "actionTimeout", Text: "15s"})
	c.Components = append(c.Components, planning.ProfileComponent{ID: "calls", Profile: planning.ProfileRef{Catalog: "builtin", Name: "syscall-activity", Version: "v1"}, Edits: []planning.ProfileEdit{
		{ActionID: "syscalls", Field: "actionExecutionMode", Text: "onTrigger"}, {ActionID: "syscalls", Field: "syscallBefore", Text: "0s"}, {ActionID: "syscalls", Field: "syscallAfter", Text: "5s"}, {ActionID: "syscalls", Field: "actionTimeout", Text: "15s"}}})
	c.MaxTotalBytes, c.MaxDuration = 32<<20, "15s"
	return c
}

// ADR-276: a manual packet + syscall composition previews as one reviewed
// group with one single-recording child per component.
func TestMixedCompositionPreviewsAsGroup(t *testing.T) {
	f := newInvestigationFixture()
	f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
	f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	f.svc.Recorders, f.svc.Filters = bothRecorders{availableRecording{f}}, &stubFilters{}
	f.svc.ReportPreviewFailure = func(stage string) { t.Log("stage", stage) }
	f.svc.Approvals = fixedApprovalSettings{policy: identity.Policy{Revision: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}, Issuer: f.actor.Issuer, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"dev-team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute, RequireRecordingApproval: true}}
	r, err := f.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(mixedComposition()))
	if err != nil {
		t.Fatal(err, errors.Unwrap(err))
	}
	g := r.Preview.CompositionGroup
	if r.Plan.Approval == nil || !r.Recordable || g == nil || len(g.Children) != 2 || len(r.Plan.Actions) != 2 || len(r.Assessment.Actions) != 2 || g.Children[0].ScopeDigest == g.Children[1].ScopeDigest {
		t.Fatalf("group preview %+v", r.Preview.CompositionGroup)
	}
}
