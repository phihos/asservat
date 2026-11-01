package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
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
		ID: uuid(1), RootID: uuid(2), InstallationID: uuid(3), IssuerEpoch: uuid(4), CaptureID: uuid(5), CaseID: uuid(6), OccurrenceID: uuid(7), ArtifactID: uuid(8), AttemptID: uuid(9), AssessmentID: uuid(10), AssessmentRulesDigest: artifact.Digest{10},
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

func previewTestRow(t *testing.T, p value.ContextPreview) custodydb.ContextPreview {
	t.Helper()
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(encoded)
	return custodydb.ContextPreview{PreviewKind: "context", ID: id(p.ID), RootID: id(p.RootID), CaptureID: id(p.CaptureID), AttemptID: id(p.AttemptID), ActorKey: previewActorKey(p.Actor), PrincipalKey: principalKey(p.Actor), BlueprintJson: encoded, BlueprintSha256: h[:], CreatedAt: ts(p.CreatedAt), Deadline: ts(p.Deadline)}
}

func TestContextPreviewRecordPreservesImmutableReviewAndRejectsCorruption(t *testing.T) {
	p := previewTestValue(t)
	got, err := previewRecord(previewTestRow(t, p))
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("valid historical passive preview changed", err)
	}
	for name, mutate := range map[string]func(*custodydb.ContextPreview){
		"wrong-kind":      func(r *custodydb.ContextPreview) { r.PreviewKind = "recordingSaveGroup" },
		"digest":          func(r *custodydb.ContextPreview) { r.BlueprintSha256[0]++ },
		"root":            func(r *custodydb.ContextPreview) { r.RootID = id(p.CaptureID) },
		"capture":         func(r *custodydb.ContextPreview) { r.CaptureID = id(p.ArtifactID) },
		"attempt":         func(r *custodydb.ContextPreview) { r.AttemptID = id(p.ArtifactID) },
		"actor":           func(r *custodydb.ContextPreview) { r.ActorKey[0]++ },
		"quota-principal": func(r *custodydb.ContextPreview) { r.PrincipalKey[0]++ },
		"deadline":        func(r *custodydb.ContextPreview) { r.Deadline = ts(p.Deadline.Add(time.Microsecond)) },
		"unknown-field": func(r *custodydb.ContextPreview) {
			r.BlueprintJson = append(r.BlueprintJson[:len(r.BlueprintJson)-1], []byte(`,"Token":"synthetic-never-store"}`)...)
			h := sha256.Sum256(r.BlueprintJson)
			r.BlueprintSha256 = h[:]
		},
		"duplicate-field": func(r *custodydb.ContextPreview) {
			r.BlueprintJson = append(r.BlueprintJson[:len(r.BlueprintJson)-1], []byte(`,"ID":"`+p.ID+`"}`)...)
			h := sha256.Sum256(r.BlueprintJson)
			r.BlueprintSha256 = h[:]
		},
		"noncanonical": func(r *custodydb.ContextPreview) {
			r.BlueprintJson = append(r.BlueprintJson, '\n')
			h := sha256.Sum256(r.BlueprintJson)
			r.BlueprintSha256 = h[:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			row := previewTestRow(t, p)
			mutate(&row)
			if got, err := previewRecord(row); err == nil || !reflect.DeepEqual(got, value.ContextPreview{}) {
				t.Fatal("corrupt preview returned metadata", err)
			}
		})
	}
}

func TestContextPreviewQuotaAndRequestKeysHaveDifferentClientScopes(t *testing.T) {
	actor := previewTestValue(t).Actor
	other := actor
	other.ClientID = "mcp"
	if !bytes.Equal(principalKey(actor), principalKey(other)) {
		t.Fatal("another client evades same-human preview ceiling")
	}
	if bytes.Equal(previewActorKey(actor), previewActorKey(other)) || bytes.Equal(contextRequestKey(actor, "same-key"), contextRequestKey(other, "same-key")) {
		t.Fatal("client-bound preview ownership or idempotency crossed clients")
	}
	other = actor
	other.Kind = identity.Workload
	if bytes.Equal(principalKey(actor), principalKey(other)) {
		t.Fatal("human and workload identity share quota principal")
	}
	other = actor
	other.Subject += ":browser"
	other.ClientID = "client"
	actor.ClientID = "browser:client"
	if bytes.Equal(contextRequestKey(actor, "key"), contextRequestKey(other, "key")) {
		t.Fatal("delimiter collision in request identity")
	}
}
