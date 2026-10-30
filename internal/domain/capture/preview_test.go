package capture

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

func domainPreview() ContextPreview {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	id := func(s string) string { return "00000000-0000-4000-8000-0000000000" + s }
	return ContextPreview{ID: id("01"), RootID: id("02"), InstallationID: id("03"), IssuerEpoch: id("04"), CaptureID: id("05"), CaseID: id("06"), OccurrenceID: id("07"), ArtifactID: id("08"), AttemptID: id("09"), AssessmentID: id("10"), AssessmentRulesDigest: artifact.Digest{1}, Actor: identity.Principal{Issuer: "issuer", Subject: "developer", ClientID: "browser", Kind: identity.Human}, Intent: ContextIntent{Target: targets.WorkloadRequest{ClusterID: id("11"), Namespace: "payments", Kind: "Deployment", Name: "api"}, Diagnostic: ContextDiagnosticName, RequestedSeconds: 60}, Target: targets.Request{ClusterID: id("11"), Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "deployment"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "namespace", Name: "api-a", UID: "pod", NodeName: "node", ControllerUID: "replicaset"}, Storage: ContextStorageSelection{StoreID: id("12"), AllocationID: id("13"), PoolRevision: 1, AllocationRevision: 1, BindingRevision: identity.Revision{UID: "storage", Generation: 1, Digest: [32]byte{1}}}, Retention: ContextRetentionReview{PurposeRef: "diagnostics", RequestedSeconds: 60, MaximumSeconds: 3600, DeletionBudgetSeconds: 10, Policies: []artifact.RetentionRule{{UID: "retention", Generation: 1, Digest: artifact.Digest{2}}}}, Audience: []artifact.AudienceAssignment{{Kind: "User", Issuer: "issuer", SubjectID: "developer", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: id("14"), BasisDigest: artifact.Digest{3}}}, CanonicalScope: []byte("{}"), ScopeDigest: artifact.Digest{4}, CreatedAt: now, Deadline: now.Add(5 * time.Minute)}
}

func TestContextPreviewStructuralBounds(t *testing.T) {
	p := domainPreview()
	if !p.Valid() || !p.Current(p.CreatedAt) || p.Current(p.Deadline) || p.Current(p.CreatedAt.Add(-time.Microsecond)) {
		t.Fatal("invalid time boundary")
	}
	for name, mutate := range map[string]func(*ContextPreview){
		"duplicate generated ID":   func(p *ContextPreview) { p.AssessmentID = p.ID },
		"unbounded review":         func(p *ContextPreview) { p.Deadline = p.Deadline.Add(time.Microsecond) },
		"submicrosecond timestamp": func(p *ContextPreview) { p.CreatedAt = p.CreatedAt.Add(time.Nanosecond) },
		"changed intent namespace": func(p *ContextPreview) { p.Intent.Target.Namespace = "another" },
		"changed pod pin":          func(p *ContextPreview) { p.Pin.UID = "other" },
		"duplicate audience":       func(p *ContextPreview) { p.Audience = append(p.Audience, p.Audience[0]) },
		"duplicate policy":         func(p *ContextPreview) { p.Retention.Policies = append(p.Retention.Policies, p.Retention.Policies[0]) },
		"no report rule":           func(p *ContextPreview) { p.AssessmentRulesDigest = artifact.Digest{} },
		"oversized scope":          func(p *ContextPreview) { p.CanonicalScope = make([]byte, MaxContextPreviewScope+1) },
		"raw reason substitute": func(p *ContextPreview) {
			p.Intent.Reason = &ProtectedReasonRef{ID: "free text", CiphertextDigest: artifact.Digest{5}, ExpiresAt: p.Deadline}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := p.Clone()
			mutate(&bad)
			if bad.Valid() {
				t.Fatal("invalid structural preview accepted")
			}
		})
	}
}

func TestContextPreviewRelativeRetentionAndPodNormalization(t *testing.T) {
	p := domainPreview()
	p.Retention.RequestedSeconds = 1
	if !p.Valid() || !p.Current(p.CreatedAt.Add(2*time.Minute)) {
		t.Fatal("review consumed future evidence retention")
	}
	p.Intent.Target.Kind = "Pod"
	p.Intent.Target.Name = p.Target.PodName
	if !p.Valid() {
		t.Fatal("explicit pod cannot retain actual deployment owner")
	}
	p.Intent.Target.Name = "another-pod"
	if p.Valid() {
		t.Fatal("normalized target silently replaces explicit pod")
	}
}

func TestContextPreviewCloneAndReasonDeadline(t *testing.T) {
	p := domainPreview()
	p.Intent.Reason = &ProtectedReasonRef{ID: "00000000-0000-4000-8000-000000000099", CiphertextDigest: artifact.Digest{8}, ExpiresAt: p.Deadline}
	if !p.Valid() {
		t.Fatal("valid protected reference rejected")
	}
	p.Intent.RepeatedFrom = &HistoryLineage{CaptureID: "00000000-0000-4000-8000-000000000098", ExpiresAt: p.Deadline}
	copy := p.Clone()
	copy.Intent.RepeatedFrom.CaptureID = "00000000-0000-4000-8000-000000000097"
	if p.Intent.RepeatedFrom.CaptureID == copy.Intent.RepeatedFrom.CaptureID {
		t.Fatal("clone aliases repeat source")
	}
	copy.CanonicalScope[0] = '!'
	copy.Audience[0].SubjectID = "other"
	copy.Retention.Policies[0].UID = "other"
	copy.Intent.Reason.CiphertextDigest[0]++
	if p.CanonicalScope[0] != '{' || p.Audience[0].SubjectID != "developer" || p.Retention.Policies[0].UID != "retention" || p.Intent.Reason.CiphertextDigest[0] != 8 {
		t.Fatal("clone aliases mutable state")
	}
	p.Intent.Reason.ExpiresAt = p.CreatedAt.Add(time.Minute)
	if !p.Valid() {
		t.Fatal("descriptive reason expiry changed capture review lifetime")
	}
}

func TestContextPreviewExecutionClassPins(t *testing.T) {
	p := domainPreview()
	p.Pin.NodeName = ""
	if p.Valid() {
		t.Fatal("node preview silently fell back to API acquisition")
	}
	p.ExecutionClass = artifact.ContextAPIExecution
	if !p.Valid() {
		t.Fatal("explicit API preview requires node assignment")
	}
	p.Pin.NodeName = "node"
	if p.Valid() {
		t.Fatal("API preview retained node execution authority")
	}
	p.Pin.NodeName = ""
	p.ExecutionClass = "other"
	if p.Valid() {
		t.Fatal("unqualified execution class")
	}
}
