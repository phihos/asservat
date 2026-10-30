package postgres

import (
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

func assertReviewedSnapshotPlan(t *testing.T, plan planvalue.ContextPlan, expected artifact.ContextExpectation, check app.PolicySourceCheck) {
	t.Helper()
	in := plan.Input
	p := previewTestValue(t)
	p.RootID = check.Recovery.InstallationID
	p.InstallationID, p.IssuerEpoch = check.Recovery.InstallationID, check.Recovery.IssuerEpoch
	p.ExecutionClass = in.Target.ExecutionClass
	p.Actor = in.Executor
	p.CaptureID, p.CaseID, p.OccurrenceID = expected.CaptureUID, expected.CaseID, expected.OccurrenceID
	p.ArtifactID, p.AttemptID = expected.Registration.Location.ArtifactID, expected.Registration.Location.AttemptID
	p.Target, p.Pin = in.Target.Request, in.Target.Pin
	p.Intent = value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: p.Target.ClusterID, Namespace: p.Target.Namespace.Name, Kind: "Pod", Name: p.Target.PodName}, Snapshot: in.Snapshot.Clone(), RequestedSeconds: in.Retention.RequestedSeconds}
	p.Storage = value.ContextStorageSelection{StoreID: expected.Registration.StoreID, AllocationID: expected.Registration.AllocationID, PoolRevision: expected.Registration.PoolRevision, AllocationRevision: expected.Registration.AllocationRevision, BindingRevision: check.Settings.Revision}
	p.Retention = value.ContextRetentionReview{PurposeRef: in.Retention.PurposeRef, RequestedSeconds: in.Retention.RequestedSeconds, MaximumSeconds: in.Retention.MaximumSeconds, DeletionBudgetSeconds: in.Retention.DeletionBudgetSeconds, Policies: in.Retention.Policies}
	p.Audience = expected.Audience
	p.CanonicalScope, p.ScopeDigest = plan.CanonicalScope, plan.ScopeDigest
	p.CreatedAt, p.Deadline, p.SelectionUntil = plan.CompiledAt, in.Deadline, plan.CompiledAt.Add(time.Minute)
	p.AssessmentRulesDigest = compiler.SourceSnapshotAssessmentRulesDigest()
	if !app.ValidContextPreview(p) || !compiler.VerifyContextPlan(plan, plan.CompiledAt) || expected.Validate() != nil {
		t.Fatal("valid generated snapshot review baseline")
	}
	a := value.Admission{RootID: p.RootID, Recovery: check.Recovery, Plan: plan, Registration: expected.Registration, CaseID: p.CaseID, OccurrenceID: p.OccurrenceID, Storage: value.StorageBinding{Revision: p.Storage.BindingRevision}, Eligibility: authorization.CaptureEligibility{DefaultAudience: p.Audience}}
	if !reviewedContextMatches(p, a) {
		t.Fatal("genuine source snapshot assessment was rejected by reviewed admission")
	}
	wrong := p.Clone()
	wrong.AssessmentRulesDigest = compiler.ContextAssessmentRulesDigestForClass(p.ExecutionClass)
	if reviewedContextMatches(wrong, a) {
		t.Fatal("snapshot accepted with ordinary metadata assessment")
	}
	wrong = p.Clone()
	wrong.AssessmentRulesDigest = compiler.RecorderAssessmentRulesDigest()
	if reviewedContextMatches(wrong, a) {
		t.Fatal("snapshot accepted with finite recorder assessment")
	}
}

func metadataReviewedBinding(t *testing.T) (value.ContextPreview, value.Admission) {
	t.Helper()
	p := previewTestValue(t)
	p.AssessmentRulesDigest = compiler.ContextAssessmentRulesDigestForClass(p.ExecutionClass)
	a := value.Admission{RootID: p.RootID, Recovery: artifact.RecoveryProof{InstallationID: p.InstallationID, IssuerEpoch: p.IssuerEpoch}, Plan: planvalue.ContextPlan{ScopeDigest: p.ScopeDigest, CanonicalScope: p.CanonicalScope, Input: planvalue.ContextInput{CaptureID: p.CaptureID, Executor: p.Actor, Deadline: p.Deadline, Target: targets.PodResolution{ExecutionClass: p.ExecutionClass, Request: p.Target, Pin: p.Pin}}}, Registration: artifact.Registration{Location: artifact.Location{ArtifactID: p.ArtifactID, AttemptID: p.AttemptID}, StoreID: p.Storage.StoreID, AllocationID: p.Storage.AllocationID, PoolRevision: p.Storage.PoolRevision, AllocationRevision: p.Storage.AllocationRevision}, CaseID: p.CaseID, OccurrenceID: p.OccurrenceID, Storage: value.StorageBinding{Revision: p.Storage.BindingRevision}, Eligibility: authorization.CaptureEligibility{DefaultAudience: p.Audience}}
	a.Plan.Input.Retention.PurposeRef = p.Retention.PurposeRef
	a.Plan.Input.Retention.RequestedSeconds = p.Retention.RequestedSeconds
	a.Plan.Input.Retention.MaximumSeconds = p.Retention.MaximumSeconds
	a.Plan.Input.Retention.DeletionBudgetSeconds = p.Retention.DeletionBudgetSeconds
	a.Plan.Input.Retention.Policies = p.Retention.Policies
	return p, a
}

func TestReviewedMetadataAssessmentRemainsExact(t *testing.T) {
	p, a := metadataReviewedBinding(t)
	if !reviewedContextMatches(p, a) {
		t.Fatal("existing metadata review stopped matching")
	}
	p.AssessmentRulesDigest = compiler.SourceSnapshotAssessmentRulesDigest()
	if reviewedContextMatches(p, a) {
		t.Fatal("ordinary metadata accepted snapshot assessment")
	}
}

func TestReviewedFiniteRecorderAssessmentRemainsExact(t *testing.T) {
	p, a := metadataReviewedBinding(t)
	composition := planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "net", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "10s"}
	p.Intent.Diagnostic = ""
	p.Intent.Composition = &composition
	p.AssessmentRulesDigest = compiler.RecorderAssessmentRulesDigest()
	a.Plan.Input.Recorder = &planvalue.RecorderContext{Composition: composition}
	if !app.ValidContextPreview(p) {
		t.Fatal("finite recorder review structural baseline")
	}
	if !reviewedContextMatches(p, a) {
		t.Fatal("existing finite recorder assessment stopped matching")
	}
	p.AssessmentRulesDigest = compiler.SourceSnapshotAssessmentRulesDigest()
	if reviewedContextMatches(p, a) {
		t.Fatal("finite recorder accepted source snapshot assessment")
	}
}
