package postgres

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

func previewTestValue(t *testing.T) value.ContextPreview {
	t.Helper()
	uuid := func(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	scope := []byte(`{"format":"synthetic-passive-review"}`)
	p := value.ContextPreview{
		ID: uuid(1), RootID: uuid(2), InstallationID: uuid(3), CaptureID: uuid(5), CaseID: uuid(6), OccurrenceID: uuid(7), ArtifactID: uuid(8), AttemptID: uuid(9), AssessmentID: uuid(10), AssessmentRulesDigest: artifact.Digest{10},
		Actor:          identity.Principal{Issuer: "https://id.example.test", Subject: "developer", ClientID: "browser", Kind: identity.Human},
		Intent:         value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: uuid(11), Namespace: "app", Kind: "Deployment", Name: "api"}, Diagnostic: value.ContextDiagnosticName, RequestedSeconds: 3600},
		Target:         targets.Request{ClusterID: uuid(11), Namespace: cfg.NamespaceRef{Name: "app", UID: "namespace"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-one", PodUID: "pod"},
		Pin:            artifact.PinnedPod{Namespace: "app", NamespaceUID: "namespace", Name: "api-one", UID: "pod", NodeName: "worker", ControllerUID: "replicaset"},
		Storage:        value.ContextStorageSelection{StoreID: uuid(12), AllocationID: uuid(13), PoolRevision: 1, AllocationRevision: 1, BindingRevision: identity.Revision{UID: "storage", Generation: 1, Digest: [32]byte{1}}},
		Retention:      value.ContextRetentionReview{PurposeRef: "debug-context", RequestedSeconds: 3600, MaximumSeconds: 7200, DeletionBudgetSeconds: 60, Policies: []artifact.RetentionRule{{UID: "policy", Generation: 1, Digest: artifact.Digest{2}}}},
		Audience:       []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://id.example.test", SubjectID: "maintainers", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: uuid(14), BasisDigest: artifact.Digest{3}}},
		CanonicalScope: scope, ScopeDigest: sha256.Sum256(scope), CreatedAt: now, Deadline: now.Add(5 * time.Minute),
	}
	if !captureapp.ValidContextPreview(p) {
		t.Fatal("invalid synthetic preview")
	}
	return p
}
