package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	planner "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// Only authority and acquisition are synthetic here. The compiler, assessment,
// public preview projection and canonical/embedded schemas are production code.
type compiledAssessmentPreview struct {
	*contextOperationFixture
	result app.ContextPreviewResult
	calls  int
}

func (f *compiledAssessmentPreview) Preview(_ context.Context, _ identities.CurrentIdentity, in capture.ContextIntent) (app.ContextPreviewResult, error) {
	f.input = in
	f.calls++
	return f.result, nil
}

func compiledAssessmentResult(t *testing.T, i identity.Identity, class artifact.ContextExecutionClass) app.ContextPreviewResult {
	t.Helper()
	now := i.VerifiedAt
	target := targets.PodResolution{
		ExecutionClass:     class,
		Request:            targets.Request{ClusterID: "00000000-0000-4000-8000-000000000001", Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace-payments-uid"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "deployment-api-uid"}, PodName: "api-123", PodUID: "pod-uid"},
		Pin:                artifact.PinnedPod{Namespace: "payments", NamespaceUID: "namespace-payments-uid", Name: "api-123", UID: "pod-uid", ControllerUID: "replicaset-uid"},
		PodResourceVersion: "10", WorkloadResourceVersion: "20", ObservedAt: now, FreshUntil: now.Add(5 * time.Second),
	}
	if class == artifact.ContextNodeExecution {
		target.Pin.NodeName, target.NodeUID, target.NodeBootID = "worker", "node-uid", "00000000-0000-4000-8000-000000000006"
	}
	policies := privacy.PolicySet{
		Target: target.Target(), Revision: identity.Revision{UID: "policy-set", Generation: 1, Digest: [32]byte{7}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Complete: true,
		Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}},
	}
	retention, err := privacy.Resolve(policies, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: 60, AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.CompileContext(planning.ContextInput{
		CaptureID: "00000000-0000-4000-8000-000000000045", Executor: i.Principal, Deadline: now.Add(time.Minute), Target: target, Retention: retention,
		Capability: planning.ContextCapability{ExecutionClass: class, Revision: identity.Revision{UID: "context-capability", Generation: 1, Digest: [32]byte{2}}, Enabled: true, CollectorVersion: "synthetic-1", CollectorImageDigest: artifact.Digest{3}, ProjectionDigest: planner.ProjectionDigest(), ObservedAt: now, FreshUntil: now.Add(30 * time.Second)},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := planner.AssessContext(plan, "00000000-0000-4000-8000-000000000088", now)
	if err != nil {
		t.Fatal(err)
	}
	return app.ContextPreviewResult{
		Preview:    capture.ContextPreview{ID: "00000000-0000-4000-8000-000000000020", Deadline: now.Add(5 * time.Minute), ScopeDigest: plan.ScopeDigest, Target: plan.Input.Target.Request},
		ValidUntil: plan.ValidUntil, Assessment: assessment,
	}
}

func TestCompiledContextAssessmentPublicPreview(t *testing.T) {
	for _, test := range []struct {
		name  string
		class artifact.ContextExecutionClass
	}{{"node", artifact.ContextNodeExecution}, {"kubernetesAPI", artifact.ContextAPIExecution}} {
		t.Run(test.name, func(t *testing.T) {
			s, f := operationFixture(t, true)
			result := compiledAssessmentResult(t, f.i, test.class)
			t.Run("canonical-assessment", func(t *testing.T) {
				b, err := json.Marshal(ContextAssessment(result.Assessment))
				if err != nil {
					t.Fatal(err)
				}
				v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
				if err != nil {
					t.Fatal(err)
				}
				if err := canonicalSchema(t, "capture-assessment.schema.json#/$defs/assessment").Validate(v); err != nil {
					t.Fatalf("real compiled assessment violates canonical output contract: %v", err)
				}
			})
			t.Run("public-preview", func(t *testing.T) {
				capturePort := &compiledAssessmentPreview{contextOperationFixture: f, result: result}
				s.captures = capturePort
				reply, err := s.Call(t.Context(), f, "preview_capture", json.RawMessage(wirePreview))
				if err != nil {
					t.Fatalf("real compiled assessment cannot be returned by public preview: %v", err)
				}
				if err := s.contracts.ValidateOutput("preview_capture", reply.Body); err != nil {
					t.Fatal(err)
				}
				var out struct {
					Status string             `json:"status"`
					Data   ContextPreviewData `json:"data"`
				}
				if err := json.Unmarshal(reply.Body, &out); err != nil {
					t.Fatal(err)
				}
				if out.Status != "ok" || capturePort.calls != 1 || f.requests != 0 || !reply.ValidUntil.Equal(result.ValidUntil) {
					t.Fatal("preview lost its original dispatch, deadline or success result")
				}
				if len(out.Data.SelectedPods) != 1 || out.Data.SelectedPods[0].UID != result.Preview.Target.PodUID || out.Data.ExecutionDigest != hash(result.Preview.ScopeDigest) || out.Data.Assessment.CombinedImpact.Explanation != result.Assessment.Impact.Explanation {
					t.Fatal("public preview replaced the selected Pod, plan or real assessment")
				}
			})
		})
	}
}
