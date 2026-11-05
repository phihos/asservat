package capture

import (
	compiler "asservat.local/asservat/internal/application/planning"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type bothRecorders struct{ availableRecording }

type logsGroupAdmission struct {
	*retainedRecording
	groups []value.RecordingSaveGroupAdmission
}

func (f *logsGroupAdmission) AdmitRecordingCompositionGroup(_ context.Context, a value.RecordingSaveGroupAdmission) (value.Accepted, error) {
	f.groups = append(f.groups, a)
	return value.Accepted{}, reachedRecordingAdmission
}

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

func TestLogsAndMetadataRecordersShareOneGroupReview(t *testing.T) {
	for _, mode := range []struct {
		name                string
		required, sensitive bool
	}{{name: "ordinary"}, {name: "protected", required: true}, {name: "authored-sensitive", sensitive: true}} {
		required, reviewed := mode.required, mode.required || mode.sensitive
		t.Run(mode.name, func(t *testing.T) {
			f := newInvestigationFixture()
			admission := &logsGroupAdmission{retainedRecording: &retainedRecording{investigationFixture: f}}
			f.svc.Previews, f.svc.Admission = admission, admission
			f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
			f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
			f.svc.Recorders, f.svc.Filters = bothRecorders{availableRecording{f}}, &stubFilters{}
			f.svc.ReportPreviewFailure = func(stage string) { t.Log("stage", stage) }
			f.svc.Approvals = fixedApprovalSettings{policy: identity.Policy{Revision: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}, Issuer: f.actor.Issuer, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"dev-team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute, RequireRecordingApproval: required}}
			c := mixedComposition()
			c.MaxTotalBytes = 64 << 20
			c.Components = append(c.Components, planning.ProfileComponent{ID: "logs", Profile: planning.ProfileRef{Catalog: "builtin", Name: "finite-logs", Version: "v1"}})
			if mode.sensitive {
				raw, err := os.ReadFile("../planning/profiles/finite-logs-v1.json")
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				if json.Unmarshal(raw, &doc) != nil {
					t.Fatal("logs profile")
				}
				doc["name"] = "sensitive-logs"
				doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)["impact"] = "sensitiveRead"
				raw, _ = json.Marshal(doc)
				ref := planning.ProfileRef{Catalog: "namespace", Name: "sensitive-logs", Version: "v1"}
				c.Components[2].Profile = ref
				f.svc.Profiles = &catalogFixture{profiles: []planning.CatalogProfile{{Ref: ref, SourceClusterID: f.target.Request.ClusterID, SourceNamespaceUID: f.target.Request.Namespace.UID, SourceUID: "sensitive-logs-source", Enabled: true, Document: raw}}}
			}
			r, err := f.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(c))
			if err != nil {
				t.Fatal("logs group preview", err)
			}
			if !r.Recordable || r.Preview.CompositionGroup == nil || len(r.Preview.CompositionGroup.Children) != 3 || len(r.Plan.Actions) != 3 || len(r.Assessment.Actions) != 3 || (r.Plan.Approval != nil) != reviewed || r.Preview.AssessmentRulesDigest != compiler.RecorderAssessmentRulesFor(r.Plan.Actions) || r.Assessment.RulesDigest != r.Preview.AssessmentRulesDigest {
				t.Fatal("mixed group lost combined review")
			}
			for n, child := range r.Preview.CompositionGroup.Children {
				actions, approval, err := compiler.RecorderScopeSummary(child.CanonicalScope)
				if err != nil || len(actions) != 1 || (approval != nil) != reviewed {
					t.Fatal("child scope changed", n, err)
				}
				if actions[0].Kind == "logs" && (actions[0].MaxBytes != 10<<20 || actions[0].Before != "10s" || actions[0].LogStream != "both") {
					t.Fatal("logs limits changed in group")
				}
			}
			var access *authorization.ResultAccess
			if reviewed {
				grants := &fakeGrants{}
				f.svc.Grants = grants
				for _, a := range r.Plan.Actions {
					if a.Kind == "logs" {
						access = &authorization.ResultAccess{ActionIDs: []string{a.ID}, Operations: []string{authorization.GrantDownloadOperation}, ClientIDs: []string{"console"}, MaxArtifacts: 1, MaxBytes: 10 << 20, MaxOperations: 4, NotAfter: f.now.Add(time.Hour)}
					}
				}
				if _, err := f.svc.RequestWithResultAccess(t.Context(), f.source(t, t.Context()), r.Preview.ID, "mixed-logs", access); !errors.Is(err, authorization.ErrApprovalRequired) || len(grants.requests) != 1 || len(admission.groups) != 0 {
					t.Fatal("combined review bypassed", err)
				}
				if grants.requests[0].DataClass != "raw" || len(grants.requests[0].Review.Actions) != 3 {
					t.Fatal("parent review omitted raw logs or siblings")
				}
				grants.covering = nil
				grants.grant.ExpiresAt = f.now.Add(90 * time.Second)
			}
			if _, err := f.svc.RequestWithResultAccess(t.Context(), f.source(t, t.Context()), r.Preview.ID, "mixed-logs", access); !errors.Is(err, reachedRecordingAdmission) || len(admission.groups) != 1 {
				t.Fatal("mixed typed children did not reach atomic admission", err)
			}
			group := admission.groups[0]
			if len(group.Children) != 3 {
				t.Fatal("partial group admission")
			}
			for n, child := range group.Children {
				if !ReviewedCompositionGroupChild(group.Preview, n, child) || !child.Registration.AnchorAt.Equal(group.Children[0].Registration.AnchorAt) {
					t.Fatal("child lost original common admission anchor", n)
				}
				if child.Plan.Input.Logs != nil && child.Registration.NativeLimit != 10<<20 {
					t.Fatal("logs inherited recorder eight MiB cap")
				}
			}
		})
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
