package capture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
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

// Argument permits currently bind one ad hoc capture grant. A group grant is
// bound to its parent. Refuse the unsupported composition explicitly before
// assessment or persistence, rather than depending on a later rules mismatch.
func TestArgumentCompositionGroupRefusedBeforePersistence(t *testing.T) {
	for _, order := range []string{"packet-first", "arguments-first"} {
		t.Run(order, func(t *testing.T) {
			f := newInvestigationFixture()
			f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
			f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
			f.svc.Recorders, f.svc.Filters = bothRecorders{availableRecording{f}}, &approvalArgumentCompiler{}
			f.svc.ReportPreviewFailure = func(stage string) { t.Log("stage", stage) }
			f.svc.Approvals = fixedApprovalSettings{policy: identity.Policy{Revision: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}, Issuer: f.actor.Issuer, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"dev-team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute, RequireRecordingApproval: true}}
			raw, err := os.ReadFile("../planning/profiles/syscall-activity-v1.json")
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err = json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			doc["name"] = "group-arguments"
			a := doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)
			a["impact"], a["executionMode"] = "sensitiveRead", "onTrigger"
			params := a["parameters"].(map[string]any)
			params["mode"], params["before"], params["after"] = "arguments", "0s", "3s"
			params["syscalls"] = map[string]any{"mode": "include", "names": []string{"read", "write"}}
			params["arguments"] = map[string]any{"maxBytesPerEvent": 128, "captureBuffers": false}
			raw, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			ref := planning.ProfileRef{Catalog: "namespace", Name: "group-arguments", Version: "v1"}
			f.svc.Profiles = &catalogFixture{profiles: []planning.CatalogProfile{{Ref: ref, SourceClusterID: fixtureID(4), SourceNamespaceUID: "ns", SourceUID: "argument-profile", Document: raw, Enabled: true}}}
			c := mixedComposition()
			c.MaxDuration = "30s"
			c.Components[1] = planning.ProfileComponent{ID: "calls", Profile: ref}
			if order == "arguments-first" {
				c.Components[0], c.Components[1] = c.Components[1], c.Components[0]
			}
			got, err := f.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(c))
			var failure *contextPreviewFailure
			if !errors.Is(err, value.ErrInvalid) || !errors.As(err, &failure) || failure.stage != "composition/arguments" {
				t.Logf("cause: %+v", errors.Unwrap(err))
				t.Fatalf("unsupported argument group advertised: recordable=%v, error=%v, failure=%+v", got.Recordable, err, failure)
			}
			if got.Recordable || len(f.previews) != 0 || f.admissions.Load() != 0 {
				t.Fatal("unsupported group persisted or admitted")
			}
		})
	}
}
