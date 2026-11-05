package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
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
	// resolved supplies namespace catalog profiles (the service reads them).
	resolved []planning.CatalogProfile
	filters  compiler.FilterCompiler
}

type oneInstruction struct{}

func (oneInstruction) CompileFilter(string) (planning.CompiledFilter, error) {
	return planning.CompiledFilter{LinkType: planning.FilterLinkType, Snaplen: planning.FilterSnaplen, Program: []planning.BPFInstruction{{Code: 0x6, K: 65535}}}, nil
}

func (f *recorderFixture) PreviewComposition(_ context.Context, _ identities.CurrentIdentity, in value.ContextIntent) (app.RecorderPreviewResult, error) {
	if f.resolved != nil {
		c := in.Composition.Clone()
		c.Resolved = f.resolved
		in.Composition = c
	}
	f.composition = in.Composition
	now := f.i.VerifiedAt
	target := targets.PodResolution{Request: targets.Request{ClusterID: in.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: in.Target.Namespace, UID: "ns"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: in.Target.Namespace, NamespaceUID: "ns", Name: "api-a", UID: "pod", NodeName: "worker", ControllerUID: "rs"}, NodeUID: "node", NodeBootID: "00000000-0000-4000-8000-000000000006", PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	if len(in.Composition.Components) > 1 {
		return f.groupPreview(in, target)
	}
	evidence, err := compiler.RecorderEvidenceType(*in.Composition)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	r, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "set", Generation: 1, Digest: [32]byte{7}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: evidence, AnchorAt: now}, now)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	input := planning.RecorderInput{CaptureID: "00000000-0000-4000-8000-000000000045", Executor: f.i.Principal, Target: target, Composition: *in.Composition, Retention: r, Deadline: now.Add(time.Minute)}
	filters := f.filters
	if filters == nil {
		filters = oneInstruction{}
	}
	plan, err := compiler.CompileRecorder(input, filters, now)
	if needed := (compiler.PeerResolutionNeeded{}); errors.As(err, &needed) {
		// ADR-283 PR 2: a synthetic regional resolution of two members.
		input.Peers = []targets.PeerResolution{{Request: needed.Request, Members: []targets.PeerMember{{Kind: "Pod", UID: "db-a", IP: "10.0.0.11"}, {Kind: "Pod", UID: "db-b", IP: "10.0.0.12"}}, ResolvedAt: now}}
		plan, err = compiler.CompileRecorder(input, oneInstruction{}, now)
	}
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

// groupPreview builds an ADR-276 group preview the way the application does:
// one plan per component, the recorder-group/v1 parent and its display merge.
func (f *recorderFixture) groupPreview(in value.ContextIntent, target targets.PodResolution) (app.RecorderPreviewResult, error) {
	now := f.i.VerifiedAt
	parts, err := compiler.SplitComposition(*in.Composition, oneInstruction{})
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	var plans []planning.RecorderPlan
	var assessments []planning.RecorderAssessment
	for n, c := range parts {
		evidence, err := compiler.RecorderEvidenceType(c)
		if err != nil {
			return app.RecorderPreviewResult{}, err
		}
		r, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "set", Generation: 1, Digest: [32]byte{7}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: evidence, AnchorAt: now}, now)
		if err != nil {
			return app.RecorderPreviewResult{}, err
		}
		plan, err := compiler.CompileRecorder(planning.RecorderInput{CaptureID: "00000000-0000-4000-8000-00000000005" + string(rune('0'+n)), Executor: f.i.Principal, Target: target, Composition: c, Retention: r, Deadline: now.Add(time.Minute), NodeRecorder: true, RequireApproval: true}, oneInstruction{}, now)
		if err != nil {
			return app.RecorderPreviewResult{}, err
		}
		a, err := compiler.AssessRecorder(plan, "00000000-0000-4000-8000-00000000017"+string(rune('0'+n)), now)
		if err != nil {
			return app.RecorderPreviewResult{}, err
		}
		plans, assessments = append(plans, plan), append(assessments, a)
	}
	scope, digest, err := compiler.CompileRecorderGroup("00000000-0000-4000-8000-000000000045", plans)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	plan, a, err := compiler.RecorderGroupDisplay(scope, digest, "00000000-0000-4000-8000-000000000161", plans, assessments)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	p := value.ContextPreview{ID: "00000000-0000-4000-8000-000000000020", Intent: in, Deadline: now.Add(5 * time.Minute), ScopeDigest: digest, Target: target.Request}
	return app.RecorderPreviewResult{Preview: p, Plan: plan, Assessment: a, ValidUntil: f.metadataUntil, Recordable: true}, nil
}

// ADR-276: a packet + syscall group preview passes the public output
// contract with both actions in one review.
func TestCompositionGroupPreviewWire(t *testing.T) {
	s, f := recorderOperations(t, true)
	in := `{` + wireTarget + `,"requested_retention_seconds":3600,"profile_composition":{"components":[{"id":"net","profileRef":{"catalog":"builtin","name":"network-connections","version":"v1"},"overrides":[{"actionID":"sample","field":"packetFilter","value":"tcp port 8080"},{"actionID":"sample","field":"packetAfter","value":"5s"},{"actionID":"sample","field":"actionTimeout","value":"15s"}]},{"id":"calls","profileRef":{"catalog":"builtin","name":"syscall-activity","version":"v1"},"overrides":[{"actionID":"syscalls","field":"actionExecutionMode","value":"onTrigger"},{"actionID":"syscalls","field":"syscallBefore","value":"0s"},{"actionID":"syscalls","field":"syscallAfter","value":"5s"},{"actionID":"syscalls","field":"actionTimeout","value":"15s"}]}],"maxTotalBytes":33554432,"maxDuration":"15s"}}`
	reply, err := s.Call(t.Context(), f, "preview_capture", []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Status string `json:"status"`
		Data   struct {
			Lifecycle struct {
				Actions []map[string]string `json:"actions"`
			} `json:"lifecycle_plan"`
			Assessment CaptureAssessment `json:"capture_assessment"`
		} `json:"data"`
	}
	if json.Unmarshal(reply.Body, &out) != nil || out.Status != "ok" || len(out.Data.Lifecycle.Actions) != 2 || len(out.Data.Assessment.Actions) != 2 {
		t.Fatalf("group preview: %s", reply.Body)
	}
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
	// ADR-283: a CIDR peer edit compiles into the hub filter and the preview
	// names its prefix count. Kubernetes peers are outside the runtime subset.
	cidrs := strings.Replace(wireComposition, `{"actionID":"sample","field":"packetFilter","value":"tcp port 8080"}`, `{"actionID":"sample","field":"packetFilter","value":"tcp port 8080"},{"actionID":"sample","field":"packetPeers","value":{"entries":[{"cidrs":["10.0.0.0/8","2001:db8::/32"]}],"protocol":"tcp","resolution":"frozen","maxEndpoints":1,"maxStaleness":"5s"}}`, 1)
	reply, err = s.Call(t.Context(), f, "preview_capture", []byte(cidrs))
	if err != nil || !strings.Contains(string(reply.Body), "Peers: 2 CIDR prefixes") || !strings.Contains(string(reply.Body), "((net 10.0.0.0/8 or net 2001:db8::/32) and tcp) and (tcp port 8080)") {
		t.Fatalf("cidr peers: %v %s", err, reply.Body)
	}
	if f.composition == nil || f.composition.Components[0].Edits[1].Peers == nil || len(f.composition.Components[0].Edits[1].Peers.CIDRs[0]) != 2 {
		t.Fatal("typed peers edit not decoded")
	}
	// ADR-283 PR 2: Kubernetes peers are previewed with their resolved
	// endpoint count and members digest; a plan-only preview has the generic
	// RecorderUnavailable blocker (part 3 lifted the peer-specific gate).
	k8s := strings.Replace(wireComposition, `"field":"packetFilter","value":"tcp port 8080"`, `"field":"packetPeers","value":{"entries":[{"resourceRef":{"kind":"Deployment","namespace":"payments","name":"db"}}],"protocol":"tcp","resolution":"frozen","maxEndpoints":8,"maxStaleness":"5s"}`, 1)
	reply, err = s.Call(t.Context(), f, "preview_capture", []byte(k8s))
	if err != nil || !strings.Contains(string(reply.Body), "Peers: 2 Kubernetes endpoints resolved at preview") || !strings.Contains(string(reply.Body), "(net 10.0.0.11/32 or net 10.0.0.12/32) and tcp") || !strings.Contains(string(reply.Body), `"code":"RecorderUnavailable"`) || strings.Contains(string(reply.Body), "Kubernetes peers in this release") || !strings.Contains(string(reply.Body), `"capture_enabled":false`) {
		t.Fatalf("kubernetes peers: %v %s", err, reply.Body)
	}
	if k := f.composition.Components[0].Edits[0].Peers; k == nil || len(k.Kubernetes) != 1 || k.Kubernetes[0].Resource.Kind != "Deployment" || k.Kubernetes[0].Resource.Namespace != "payments" {
		t.Fatal("typed Kubernetes peers edit not decoded")
	}
	// Schema subset: sharing, presets and malformed peer edits are not accepted; more than
	// eight components exceed the canonical bound (ADR-276 groups are below it).
	for name, bad := range map[string]string{
		"sharing":              strings.Replace(wireComposition, `"requested_retention_seconds":3600,`, `"requested_retention_seconds":3600,"sharing":{"recipients":[{"kind":"User","issuer":"https://id.invalid","id":"x"}]},`, 1),
		"preset":               strings.Replace(wireComposition, `"requested_retention_seconds":3600,`, `"preset_ref":{"name":"pod-status","version":"v1"},`, 1),
		"service without mode": strings.Replace(wireComposition, `"field":"packetFilter","value":"tcp port 8080"`, `"field":"packetPeers","value":{"entries":[{"resourceRef":{"kind":"Service","namespace":"payments","name":"db"}}],"protocol":"tcp","resolution":"frozen","maxEndpoints":1,"maxStaleness":"5s"}`, 1),
		"deployment with mode": strings.Replace(wireComposition, `"field":"packetFilter","value":"tcp port 8080"`, `"field":"packetPeers","value":{"entries":[{"resourceRef":{"kind":"Deployment","namespace":"payments","name":"db","readyOnly":true}}],"protocol":"tcp","resolution":"frozen","maxEndpoints":1,"maxStaleness":"5s"}`, 1),
		"bad peer":             strings.Replace(wireComposition, `"field":"packetFilter","value":"tcp port 8080"`, `"field":"packetPeers","value":{"entries":[{"cidrs":["10.0.0.0/8"]}],"protocol":"sctp","resolution":"frozen","maxEndpoints":1,"maxStaleness":"5s"}`, 1),
		"nine":                 strings.Replace(wireComposition, `"components":[{`, `"components":[`+strings.Repeat(`{"id":"other","profileRef":{"catalog":"builtin","name":"syscall-activity","version":"v1"}},`, 8)+`{`, 1),
		"no field":             strings.Replace(wireComposition, `"field":"packetFilter"`, `"field":"impact"`, 1),
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
	omittedClient := strings.Replace(withAccess, `"clientIDs":["console"],`, "", 1)
	if _, err = s.Call(t.Context(), f, "request_capture", []byte(omittedClient)); err != nil || f.access == nil || len(f.access.ClientIDs) != 1 || f.access.ClientIDs[0] != f.i.Principal.ClientID {
		t.Fatalf("currentclientdefault %v %+v", err, f.access)
	}
	explicitAgent := strings.Replace(withAccess, `"clientIDs":["console"]`, `"clientIDs":["agent"]`, 1)
	if _, err = s.Call(t.Context(), f, "request_capture", []byte(explicitAgent)); err != nil || len(f.access.ClientIDs) != 1 || f.access.ClientIDs[0] != "agent" {
		t.Fatalf("explicitclientrewritten %v %+v", err, f.access)
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

func TestRecorderPreviewOperationalFailureIsTypedUnavailable(t *testing.T) {
	s, f := recorderOperations(t, true)
	f.compileErr = targets.ErrUnavailable
	reply, err := s.Call(t.Context(), f, "preview_capture", []byte(wireComposition))
	var envelope struct {
		Status string `json:"status"`
		Data   struct {
			Code      string `json:"code"`
			Retryable bool   `json:"retryable"`
			PreviewID string `json:"preview_id"`
			Approval  bool   `json:"approval_required"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(reply.Body, &envelope) != nil || envelope.Status != "error" || envelope.Data.Code != "NotAvailable" || !envelope.Data.Retryable || envelope.Data.PreviewID != "" || envelope.Data.Approval {
		t.Fatal("operational failure became a reviewable or terminal preview", err, string(reply.Body))
	}
}

// ADR-282: a finite manual httpHeaders preview from a namespace profile
// renders within the preview_capture output contract.
func TestHTTPHeadersPreviewWire(t *testing.T) {
	for _, mode := range []string{"httpHeaders", "rawPackets"} {
		t.Run(mode, func(t *testing.T) {
			s, f := recorderOperations(t, true)
			raw, err := os.ReadFile("../../application/planning/profiles/network-connections-v1.json")
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err = json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			doc["name"] = "http-capture"
			action := doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)
			action["parameters"].(map[string]any)["profile"] = map[string]any{"kind": "httpHeaders", "protocol": "http1", "projectionRef": map[string]any{"name": "http-response-headers", "version": "v1"}, "maxFlows": 1024, "maxHeaderBytes": 32768, "maxReassemblyBytesPerFlow": 262144, "maxReassemblyBytes": 16777216, "idleTimeout": "30s"}
			if mode == "rawPackets" {
				action["parameters"].(map[string]any)["profile"] = map[string]any{"kind": "rawPackets", "snaplen": 96}
			}
			action["impact"] = "sensitiveRead"
			document, _ := json.Marshal(doc)
			f.resolved = []planning.CatalogProfile{{Ref: planning.ProfileRef{Catalog: "namespace", Name: "http-capture", Version: "v1"}, SourceClusterID: "00000000-0000-4000-8000-000000000001", SourceNamespaceUID: "ns", SourceUID: "http-uid", Document: document, Enabled: true}}
			in := `{` + wireTarget + `,"requested_retention_seconds":3600,"profile_composition":{"components":[{"id":"http","profileRef":{"catalog":"namespace","name":"http-capture","version":"v1"},"overrides":[{"actionID":"sample","field":"packetFilter","value":"tcp port 8080"},{"actionID":"sample","field":"actionExecutionMode","value":"onTrigger"},{"actionID":"sample","field":"packetBefore","value":"0s"},{"actionID":"sample","field":"packetAfter","value":"5s"},{"actionID":"sample","field":"actionTimeout","value":"15s"}]}],"maxTotalBytes":16777216,"maxDuration":"15s"}}`
			reply, err := s.Call(t.Context(), f, "preview_capture", []byte(in))
			if err != nil {
				t.Fatal("preview_capture", err)
			}
			if !strings.Contains(string(reply.Body), `"status":"ok"`) {
				t.Fatalf("http preview: %s", reply.Body)
			}
			var out struct {
				Data struct {
					Actions   []RecorderResultAccessAction `json:"result_access_actions"`
					Lifecycle struct {
						Actions []struct {
							ActionID string `json:"actionID"`
						} `json:"actions"`
					} `json:"lifecycle_plan"`
				} `json:"data"`
			}
			if json.Unmarshal(reply.Body, &out) != nil {
				t.Fatal("decode")
			}
			if mode == "rawPackets" {
				if len(out.Data.Actions) != 1 || len(out.Data.Lifecycle.Actions) != 1 || out.Data.Actions[0].ActionID != out.Data.Lifecycle.Actions[0].ActionID || !slices.Equal(out.Data.Actions[0].Operations, []string{"download_artifact", "pcap_query"}) {
					t.Fatalf("raw eligible actions: %s", reply.Body)
				}
			} else if len(out.Data.Actions) != 0 {
				t.Fatal("extract offered raw access", out.Data.Actions)
			}
		})
	}
}

func TestProfileWarningsDescribeProfileTiming(t *testing.T) {
	warnings := recorderWarnings(planning.RecorderPlan{Actions: []planning.RecorderAction{{Kind: "profile", ProfileRuntime: "go", ProfileType: "cpu", ProfileMode: "interval", Duration: "10s"}}})
	if len(warnings) != 1 || !strings.Contains(warnings[0], "go cpu profile (interval for 10s)") || strings.Contains(warnings[0], "Packet") {
		t.Fatal(warnings)
	}
}

func TestProfileWarningUsesOnlyItsReviewedEndpoint(t *testing.T) {
	endpoint := targets.ProfileEndpointResolution{SourceName: "go-endpoint", AddressMode: "targetLoopback", Port: 6060, PathPolicy: "go-pprof/v1", EndpointDigest: artifact.Digest{1}}
	plan := planning.RecorderPlan{Input: planning.RecorderInput{Endpoints: []targets.ProfileEndpointResolution{endpoint}}, Actions: []planning.RecorderAction{{Kind: "profile", ProfileRuntime: "any", ProfileType: "cpu", ProfileMode: "interval", Duration: "10s"}}}
	if warnings := recorderWarnings(plan); len(warnings) != 1 {
		t.Fatal("sampler received endpoint warning", warnings)
	}
	plan.Actions[0].EndpointDigest = hash(endpoint.EndpointDigest)
	if warnings := recorderWarnings(plan); len(warnings) != 2 || !strings.Contains(warnings[1], "go-endpoint") {
		t.Fatal("reviewed endpoint omitted", warnings)
	}
	plan.Actions[0].EndpointDigest = hash(artifact.Digest{2})
	if warnings := recorderWarnings(plan); len(warnings) != 1 {
		t.Fatal("unrelated endpoint shown", warnings)
	}
}

func TestRecorderResultAccessActionsUseCompiledRawOutputOnly(t *testing.T) {
	plan := planning.RecorderPlan{Approval: &planning.RecorderApproval{}, Actions: []planning.RecorderAction{
		{ID: "raw", Kind: "packetCapture", PacketProfile: "rawPackets"},
		{ID: "meta", Kind: "packetCapture", PacketProfile: "networkHeaders"},
		{ID: "http", Kind: "packetCapture", PacketProfile: "httpHeaders"},
		{ID: "profile", Kind: "profile"},
		{ID: "syscall", Kind: "syscallTrace", SyscallMode: "arguments"},
		{ID: "syscall-metadata", Kind: "syscallTrace", SyscallMode: "metadata"},
	}}
	got := recorderResultAccessActions(plan)
	if len(got) != 3 || got[0].ActionID != "raw" || !slices.Equal(got[0].Operations, []string{"download_artifact", "pcap_query"}) || got[1].ActionID != "profile" || !slices.Equal(got[1].Operations, []string{"download_artifact"}) || got[2].ActionID != "syscall" || !slices.Equal(got[2].Operations, []string{"download_artifact", "syscall_query"}) {
		t.Fatal(got)
	}
	plan.Approval = nil
	if recorderResultAccessActions(plan) != nil {
		t.Fatal("unreviewed actions offered")
	}
}
