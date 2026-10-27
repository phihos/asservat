package presentation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// recorderFixture compiles the real plan and assessment from the decoded
// composition; target, eligibility and retention facts are synthetic.
type recorderFixture struct {
	*contextOperationFixture
	composition *planning.ProfileComposition
	compileErr  error
	access      *authorization.ResultAccess
}

type oneInstruction struct{}

func (oneInstruction) CompileFilter(string) (planning.CompiledFilter, error) {
	return planning.CompiledFilter{LinkType: planning.FilterLinkType, Snaplen: planning.FilterSnaplen, Program: []planning.BPFInstruction{{Code: 0x6, K: 65535}}}, nil
}

func (f *recorderFixture) PreviewComposition(_ context.Context, _ identities.CurrentIdentity, in value.ContextIntent) (app.RecorderPreviewResult, error) {
	f.composition = in.Composition
	now := f.i.VerifiedAt
	target := targets.PodResolution{Request: targets.Request{ClusterID: in.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: in.Target.Namespace, UID: "ns"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: in.Target.Namespace, NamespaceUID: "ns", Name: "api-a", UID: "pod", NodeName: "worker", ControllerUID: "rs"}, NodeUID: "node", NodeBootID: "00000000-0000-4000-8000-000000000006", PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	evidence, err := compiler.RecorderEvidenceType(*in.Composition)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	r, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "set", Generation: 1, Digest: [32]byte{7}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: evidence, AnchorAt: now}, now)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	plan, err := compiler.CompileRecorder(planning.RecorderInput{CaptureID: "00000000-0000-4000-8000-000000000045", Executor: f.i.Principal, Target: target, Composition: *in.Composition, Retention: r, Deadline: now.Add(time.Minute)}, oneInstruction{}, now)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	a, err := compiler.AssessRecorder(plan, "00000000-0000-4000-8000-000000000161", now)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	p := value.ContextPreview{ID: "00000000-0000-4000-8000-000000000020", Intent: in, Deadline: now.Add(5 * time.Minute), ScopeDigest: plan.ScopeDigest, Target: target.Request}
	return app.RecorderPreviewResult{Preview: p, Plan: plan, Assessment: a, ValidUntil: f.metadataUntil}, f.compileErr
}

func recorderOperations(t *testing.T, enabled bool) (*ContextOperations, *recorderFixture) {
	t.Helper()
	base, f := operationFixture(t, enabled)
	r := &recorderFixture{contextOperationFixture: f}
	s, err := NewContextOperations(base.config, r, r)
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}

const wireComposition = `{` + wireTarget + `,"requested_retention_seconds":3600,"profile_composition":{"components":[{"id":"net","profileRef":{"catalog":"builtin","name":"network-connections","version":"v1"},"overrides":[{"actionID":"sample","field":"packetFilter","value":"tcp port 8080"},{"actionID":"sample","field":"packetRing","value":{"maxAge":"40s","maxBytes":16777216,"segmentBytes":4194304,"maxSegments":4,"medium":"memory"}},{"actionID":"sample","field":"actionExecutionMode","value":"ongoing"}]}],"maxTotalBytes":16777216,"maxDuration":"20s"}}`

func TestCompositionPreviewWire(t *testing.T) {
	s, f := recorderOperations(t, true)
	reply, err := s.Call(t.Context(), f, "preview_capture", []byte(wireComposition))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		DataClass string `json:"data_class"`
		Status    string `json:"status"`
		Data      struct {
			CaptureEnabled bool               `json:"capture_enabled"`
			Blockers       []OperationBlocker `json:"blockers"`
			Warnings       []string           `json:"warnings"`
			MaxBytes       int64              `json:"max_bytes"`
			Lifecycle      struct {
				Actions []map[string]string `json:"actions"`
			} `json:"lifecycle_plan"`
			Composition struct {
				Authored struct {
					Components []struct {
						Overrides []map[string]any `json:"overrides"`
					} `json:"components"`
				} `json:"authored"`
				ActionMap []map[string]any `json:"actionMap"`
			} `json:"profile_composition"`
			Assessment CaptureAssessment `json:"capture_assessment"`
			Preset     *PresetReference  `json:"preset_ref"`
		} `json:"data"`
	}
	if err := json.Unmarshal(reply.Body, &out); err != nil {
		t.Fatal(err)
	}
	d := out.Data
	if out.Status != "ok" || out.DataClass != "extract" || d.CaptureEnabled || len(d.Blockers) != 1 || d.Blockers[0].Code != "RecorderUnavailable" || d.Preset != nil || d.MaxBytes != 16<<20 {
		t.Fatalf("composition preview: %s", reply.Body)
	}
	if len(d.Lifecycle.Actions) != 1 || d.Lifecycle.Actions[0]["activation"] != "manualSession" || d.Lifecycle.Actions[0]["requestedBefore"] != "30s" || len(d.Composition.ActionMap) != 1 || len(d.Composition.Authored.Components[0].Overrides) != 3 {
		t.Fatalf("lifecycle/provenance: %s", reply.Body)
	}
	if d.Assessment.Actions[0].Retention.AnchorRule != "submissionPreparation" || d.Assessment.Scope.ObservationPods != 1 || !strings.Contains(strings.Join(d.Warnings, "\n"), "no history before the request") {
		t.Fatalf("assessment/warnings: %s", reply.Body)
	}
	if len(reply.Body) > 24<<10 {
		t.Fatalf("composition preview reply %d bytes exceeds the 24 KiB result budget", len(reply.Body))
	}
	if f.composition == nil || f.composition.Components[0].Edits[1].Ring == nil || f.composition.Components[0].Edits[1].Ring.MaxAge != "40s" {
		t.Fatal("typed ring edit not decoded")
	}
	// With collection disabled the CollectionDisabled blocker is added.
	s, f = recorderOperations(t, false)
	reply, err = s.Call(t.Context(), f, "preview_capture", []byte(wireComposition))
	if err != nil || !strings.Contains(string(reply.Body), `"CollectionDisabled"`) || !strings.Contains(string(reply.Body), `"RecorderUnavailable"`) {
		t.Fatalf("disabled: %v %s", err, reply.Body)
	}
}

func TestCompositionRefusalsAndRequestWire(t *testing.T) {
	s, f := recorderOperations(t, true)
	// ADR-249: a raw byte predicate compiles into a reviewable plan that
	// needs an individual approval before the recorder blocker.
	raw := strings.Replace(wireComposition, `"tcp port 8080"`, `"tcp[13] & 2 != 0"`, 1)
	reply, err := s.Call(t.Context(), f, "preview_capture", []byte(raw))
	var approval struct {
		Status string `json:"status"`
		Data   struct {
			ApprovalRequired bool               `json:"approval_required"`
			Blockers         []OperationBlocker `json:"blockers"`
			Warnings         []string           `json:"warnings"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(reply.Body, &approval) != nil || approval.Status != "ok" || !approval.Data.ApprovalRequired || len(approval.Data.Blockers) != 2 || approval.Data.Blockers[0].Code != "ApprovalRequired" || approval.Data.Blockers[0].ResponsibleRole != "approver" || approval.Data.Blockers[1].Code != "RecorderUnavailable" || !strings.Contains(strings.Join(approval.Data.Warnings, "\n"), "observation limits") {
		t.Fatalf("raw byte predicate: %v %s", err, reply.Body)
	}
	unexposed := strings.Replace(wireComposition, `"field":"packetFilter","value":"tcp port 8080"`, `"field":"actionMaxBytes","value":1024`, 1)
	reply, err = s.Call(t.Context(), f, "preview_capture", []byte(unexposed))
	if err != nil || !strings.Contains(string(reply.Body), `"code":"InvalidComposition"`) || !strings.Contains(string(reply.Body), "does not expose actionMaxBytes") {
		t.Fatalf("unexposed: %v %s", err, reply.Body)
	}
	// Schema subset: sharing, a second component and peer edits are not accepted.
	for name, bad := range map[string]string{
		"sharing":  strings.Replace(wireComposition, `"requested_retention_seconds":3600,`, `"requested_retention_seconds":3600,"sharing":{"recipients":[{"kind":"User","issuer":"https://id.invalid","id":"x"}]},`, 1),
		"preset":   strings.Replace(wireComposition, `"requested_retention_seconds":3600,`, `"preset_ref":{"name":"pod-status","version":"v1"},`, 1),
		"peers":    strings.Replace(wireComposition, `"field":"packetFilter","value":"tcp port 8080"`, `"field":"packetPeers","value":{"entries":[{"cidrs":["10.0.0.0/8"]}],"protocol":"tcp","resolution":"frozen","maxEndpoints":1,"maxStaleness":"5s"}`, 1),
		"two":      strings.Replace(wireComposition, `"components":[{`, `"components":[{"id":"other","profileRef":{"catalog":"builtin","name":"syscall-activity","version":"v1"}},{`, 1),
		"no field": strings.Replace(wireComposition, `"field":"packetFilter"`, `"field":"impact"`, 1),
	} {
		if _, err := s.Call(t.Context(), f, "preview_capture", []byte(bad)); err == nil {
			t.Fatalf("%s accepted by the runtime subset", name)
		}
	}
	f.err = value.ErrRecorderUnavailable
	reply, err = s.Call(t.Context(), f, "request_capture", []byte(wireRequest))
	if err != nil || !strings.Contains(string(reply.Body), `"code":"RecorderUnavailable"`) || !strings.Contains(string(reply.Body), "nothing was reserved") {
		t.Fatalf("request refusal: %v %s", err, reply.Body)
	}
	// ADR-249: a pending review names its approval page and the approver role.
	f.err = authorization.ApprovalPendingError{GrantID: "00000000-0000-4000-8000-0000000009a1"}
	reply, err = s.Call(t.Context(), f, "request_capture", []byte(wireRequest))
	if err != nil || !strings.Contains(string(reply.Body), `"code":"ApprovalRequired"`) || !strings.Contains(string(reply.Body), `"navigation_uri":"https://console.invalid/approvals/00000000-0000-4000-8000-0000000009a1"`) || !strings.Contains(string(reply.Body), `"responsible_role":"approver"`) {
		t.Fatalf("pending approval: %v %s", err, reply.Body)
	}
	for code, final := range map[string]error{"ApprovalDenied": authorization.ErrGrantDenied, "ApprovalRevoked": authorization.ErrGrantRevoked, "ApprovalExpired": authorization.ErrGrantExpired} {
		f.err = final
		if reply, err = s.Call(t.Context(), f, "request_capture", []byte(wireRequest)); err != nil || !strings.Contains(string(reply.Body), `"code":"`+code+`"`) {
			t.Fatalf("%s: %v %s", code, err, reply.Body)
		}
	}
	// result_access travels only to the reviewed-plan request.
	f.err = nil
	withAccess := `{"preview_id":"00000000-0000-4000-8000-000000000020","idempotency_key":"same-key","result_access":{"actionIds":["a1"],"operations":["download_artifact"],"clientIDs":["console"],"maxArtifacts":1,"maxBytes":1024,"maxOperations":2,"notAfter":"2030-01-01T00:00:00Z"}}`
	if _, err = s.Call(t.Context(), f, "request_capture", []byte(withAccess)); err != nil || f.access == nil || f.access.MaxBytes != 1024 || f.access.ClientIDs[0] != "console" {
		t.Fatalf("result access not passed: %v %+v", err, f.access)
	}
	for name, bad := range map[string]string{
		"read_memory":  strings.Replace(withAccess, `"download_artifact"`, `"read_memory"`, 1),
		"five clients": strings.Replace(withAccess, `["console"]`, `["a","b","c","d","e"]`, 1),
	} {
		if _, err := s.Call(t.Context(), f, "request_capture", []byte(bad)); err == nil {
			t.Fatalf("%s accepted by the runtime subset", name)
		}
	}
}

func (f *recorderFixture) RequestWithResultAccess(ctx context.Context, current identities.CurrentIdentity, preview, key string, access *authorization.ResultAccess) (value.Accepted, error) {
	f.access = access
	return f.Request(ctx, current, preview, key)
}
