package catalog

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	permissions "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

func caseID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

type caseFixture struct {
	now                                                                                     time.Time
	i                                                                                       identity.Identity
	p                                                                                       authorization.Projection
	recovery                                                                                artifact.RecoveryProof
	routes                                                                                  value.ContextCaseRoutes
	record                                                                                  permissions.ContextDownloadEvidence
	retained                                                                                privacy.RetainedResolution
	identityReads, routeReads, permissionReads, catalogReads, retentionReads, recoveryReads int
	fail                                                                                    string
	processingReads                                                                         int
	processingChange                                                                        bool
	afterRetention, afterFinalRecovery, afterFinalPermissions                               func()
}

func (f *caseFixture) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	f.identityReads++
	if f.fail == "identity" || ctx.Err() != nil {
		return identity.Identity{}, errors.New("private session")
	}
	return f.i, nil
}
func (f *caseFixture) Resolve(ctx context.Context, _ string) (identity.Identity, error) {
	return f.ResolveIdentity(ctx)
}
func (f *caseFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	f.recoveryReads++
	if f.recoveryReads > 1 && f.afterFinalRecovery != nil {
		f.afterFinalRecovery()
	}
	if f.fail == "recovery" {
		return artifact.RecoveryProof{}, errors.New("private recovery")
	}
	return f.recovery, nil
}
func (f *caseFixture) ResolveContextCase(_ context.Context, q value.CaseRouteQuery) (value.ContextCaseRoutes, error) {
	f.routeReads++
	if f.fail == "routes" || q.CaseID != f.routes.CaseID || q.RootID != caseID(1) || !q.Valid(f.now) {
		return value.ContextCaseRoutes{}, errors.New("private route")
	}
	return f.routes, nil
}
func (f *caseFixture) Permissions(_ context.Context, target authorization.Target) (authorization.Projection, error) {
	f.permissionReads++
	if f.permissionReads > 1 && f.afterFinalPermissions != nil {
		f.afterFinalPermissions()
	}
	if f.fail == "permissions" || target != f.p.Target {
		return authorization.Projection{}, errors.New("private permissions")
	}
	return f.p, nil
}
func (f *caseFixture) ContextDownloadEvidence(_ context.Context, id string) (permissions.ContextDownloadEvidence, error) {
	f.catalogReads++
	if f.fail == "catalog" || id != f.record.Retained.Registration.Location.ArtifactID {
		return permissions.ContextDownloadEvidence{}, errors.New("private metadata")
	}
	return f.record, nil
}
func (f *caseFixture) ResolveRetained(_ context.Context, in privacy.Input, old privacy.Deadlines, origins []artifact.RetentionRule) (privacy.RetainedResolution, error) {
	f.retentionReads++
	if f.afterRetention != nil {
		f.afterRetention()
	}
	if f.fail == "retention" || !reflect.DeepEqual(in, f.record.Retained.Input) || old != f.record.Retained.Effective || !reflect.DeepEqual(origins, f.record.Retained.OriginPolicies) {
		return privacy.RetainedResolution{}, errors.New("private policy")
	}
	return f.retained, nil
}
func newCaseFixture() (*caseFixture, ContextCaseService) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	rev := identity.Revision{UID: caseID(20), Generation: 1, Digest: artifact.Digest{1}}
	i := identity.Identity{Principal: identity.Principal{Issuer: "https://issuer.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}, Scopes: []string{"evidence:read"}, Groups: []string{"team"}, Policy: rev, VerifiedAt: n, ValidUntil: n.Add(5 * time.Second)}
	target := authorization.Target{ClusterID: caseID(3), NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}
	a := artifact.AudienceAssignment{Kind: "Group", Issuer: i.Principal.Issuer, SubjectID: "team", Role: "evidence-reader", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{2}, AssignmentID: caseID(11)}
	p := authorization.Projection{Target: target, Revision: rev, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: n, DeniesFreshUntil: n.Add(5 * time.Second), Allows: []authorization.CurrentAssignment{{Audience: a, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}}}
	reg := artifact.Registration{Location: artifact.Location{ClusterID: target.ClusterID, ArtifactID: caseID(5), AttemptID: caseID(6)}, StoreID: caseID(7), AllocationID: caseID(8), PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: n.Add(-time.Minute), WriteUntil: n.Add(-time.Second), ExpiresAt: n.Add(time.Hour), DeleteBy: n.Add(2 * time.Hour)}
	dates := privacy.Deadlines{AnchorAt: reg.AnchorAt, ExpiresAt: reg.ExpiresAt, DeleteBy: reg.DeleteBy}
	refs := []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{5}}}
	proof := artifact.RetentionProof{RootID: caseID(1), ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, PodUID: target.PodUID, Topology: rev, Policy: rev, Selectors: rev, SourceCount: 1, ObservedAt: n, ValidUntil: n.Add(5 * time.Second), Sources: [2]artifact.RetentionSourceVersion{{ClusterID: target.ClusterID, ControlNamespaceUID: "control", Epoch: caseID(22), Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: rev}}}
	f := &caseFixture{now: n, i: i, p: p, recovery: artifact.RecoveryProof{InstallationID: caseID(2), IssuerEpoch: caseID(22), Revision: rev, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, routes: value.ContextCaseRoutes{CaseID: caseID(9), Routes: []value.ContextCaseRoute{{CaptureID: caseID(4), ArtifactID: caseID(5), Target: target}}, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}, record: permissions.ContextDownloadEvidence{PurposeRef: "diagnostics", CaptureID: caseID(4), Version: artifact.Digest{3}, Audience: []artifact.AudienceAssignment{a}, Retained: privacy.RetainedArtifact{RootID: caseID(1), Registration: reg, Input: privacy.Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: 3600, AnchorAt: reg.AnchorAt}, OriginPolicies: refs, Effective: dates}, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}, retained: privacy.RetainedResolution{Target: target, PolicyRevision: rev, PurposeRef: "diagnostics", Policies: refs, Deadlines: dates, ValidUntil: n.Add(5 * time.Second), Proof: proof}}
	return f, ContextCaseService{RootID: caseID(1), InstallationID: caseID(2), Routes: f, Permissions: f, Catalog: f, Retention: f, Recovery: f, Processing: f, Now: func() time.Time { return f.now }}
}
func TestContextCaseReadUsesOrdinaryAudienceAndEffectiveDates(t *testing.T) {
	f, s := newCaseFixture()
	f.retained.ExpiresAt = f.now.Add(10 * time.Minute)
	f.retained.DeleteBy = f.now.Add(20 * time.Minute)
	f.routes.ValidUntil = f.now.Add(2 * time.Second)
	got, err := s.GetContextCase(context.Background(), f, f.routes.CaseID)
	if err != nil || !got.Valid(f.now) || len(got.Artifacts) != 1 || got.Artifacts[0].Version != f.record.Version || !got.Artifacts[0].ExpiresAt.Equal(f.retained.ExpiresAt) || !got.Artifacts[0].DeleteBy.Equal(f.retained.DeleteBy) || !got.ValidUntil.Equal(f.routes.ValidUntil) {
		t.Fatalf("ordinary case: %+v %v", got, err)
	}
	if f.catalogReads != 1 || f.retentionReads != 1 || f.permissionReads != 2 || f.recoveryReads != 2 || f.identityReads != 3 {
		t.Fatal("missing independent final checks", f)
	}
}
func TestContextCaseNoMetadataBeforeCurrentRights(t *testing.T) {
	for _, name := range []string{"identity", "scope", "no-assignment", "deny", "incomplete", "expired"} {
		t.Run(name, func(t *testing.T) {
			f, s := newCaseFixture()
			switch name {
			case "identity":
				f.fail = "identity"
			case "scope":
				f.i.Scopes = []string{"evidence:capture"}
			case "no-assignment":
				f.p.Allows = nil
			case "deny":
				f.p.Denies = f.p.Allows
			case "incomplete":
				f.p.DeniesComplete = false
			case "expired":
				f.p.DeniesFreshUntil = f.now
			}
			got, err := s.GetContextCase(context.Background(), f, f.routes.CaseID)
			if err != value.ErrUnavailable || got.CaseID != "" || f.catalogReads != 0 || f.retentionReads != 0 {
				t.Fatal("unauthorized metadata lookup", got, err)
			}
			if (name == "scope" || name == "identity") && f.routeReads != 0 {
				t.Fatal("unauthenticated routing")
			}
		})
	}
}
func TestContextCaseRejectsWrongLineageAndFreshContraryFacts(t *testing.T) {
	tests := []struct {
		name string
		edit func(*caseFixture, *ContextCaseService)
	}{
		{"wrong-case", func(f *caseFixture, s *ContextCaseService) { f.routes.CaseID = caseID(99) }},
		{"duplicate-artifact", func(f *caseFixture, s *ContextCaseService) {
			f.routes.Routes = append(f.routes.Routes, f.routes.Routes[0])
		}},
		{"overflow", func(f *caseFixture, s *ContextCaseService) {
			for len(f.routes.Routes) <= 100 {
				r := f.routes.Routes[0]
				r.ArtifactID = caseID(100 + len(f.routes.Routes))
				f.routes.Routes = append(f.routes.Routes, r)
			}
		}},
		{"foreign-installation", func(f *caseFixture, s *ContextCaseService) { f.recovery.InstallationID = caseID(99) }},
		{"wrong-capture", func(f *caseFixture, s *ContextCaseService) { f.record.CaptureID = caseID(99) }},
		{"wrong-target", func(f *caseFixture, s *ContextCaseService) { f.record.Retained.Input.Target.PodUID = "other" }},
		{"different-artifact", func(f *caseFixture, s *ContextCaseService) {
			f.record.Retained.Registration.Location.ArtifactID = caseID(99)
		}},
		{"raw-evidence", func(f *caseFixture, s *ContextCaseService) { f.record.Retained.Input.EvidenceType = "coreDump" }},
		{"audience-changed", func(f *caseFixture, s *ContextCaseService) { f.record.Audience[0].AssignmentID = caseID(99) }},
		{"missing-version", func(f *caseFixture, s *ContextCaseService) { f.record.Version = artifact.Digest{} }},
		{"extended-expiry", func(f *caseFixture, s *ContextCaseService) {
			f.retained.ExpiresAt = f.record.Retained.Effective.ExpiresAt.Add(time.Second)
		}},
		{"extended-delete", func(f *caseFixture, s *ContextCaseService) {
			f.retained.DeleteBy = f.record.Retained.Effective.DeleteBy.Add(time.Second)
		}},
		{"wrong-purpose", func(f *caseFixture, s *ContextCaseService) { f.retained.PurposeRef = "other" }},
		{"missing-proof", func(f *caseFixture, s *ContextCaseService) { f.retained.Proof = artifact.RetentionProof{} }},
		{"closed-access", func(f *caseFixture, s *ContextCaseService) { f.retained.ExpiresAt = f.now }},
		{"membership-revoked", func(f *caseFixture, s *ContextCaseService) { f.afterRetention = func() { f.i.Groups = nil } }},
		{"deny-arrives", func(f *caseFixture, s *ContextCaseService) { f.afterRetention = func() { f.p.Denies = f.p.Allows } }},
		{"permission-revision", func(f *caseFixture, s *ContextCaseService) { f.afterRetention = func() { f.p.Revision.Generation++ } }},
		{"identity-revision", func(f *caseFixture, s *ContextCaseService) { f.afterRetention = func() { f.i.Policy.Generation++ } }},
		{"original-deadline", func(f *caseFixture, s *ContextCaseService) {
			f.afterRetention = func() {
				f.now = f.now.Add(5 * time.Second)
				f.retained.ValidUntil = f.now.Add(5 * time.Second)
				f.retained.Proof.ObservedAt = f.now
				f.retained.Proof.ValidUntil = f.retained.ValidUntil
			}
		}},
		{"recovery-changes-last", func(f *caseFixture, s *ContextCaseService) {
			f.afterFinalRecovery = func() { f.recovery.Revision.Generation++ }
		}},
		{"identity-lost-last", func(f *caseFixture, s *ContextCaseService) { f.afterFinalRecovery = func() { f.fail = "identity" } }},
		{"groups-lost-last", func(f *caseFixture, s *ContextCaseService) { f.afterFinalRecovery = func() { f.i.Groups = nil } }},
		{"scope-lost-last", func(f *caseFixture, s *ContextCaseService) { f.afterFinalRecovery = func() { f.i.Scopes = nil } }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, s := newCaseFixture()
			tt.edit(f, &s)
			got, err := s.GetContextCase(context.Background(), f, caseID(9))
			if err != value.ErrUnavailable || got.CaseID != "" || len(got.Artifacts) != 0 {
				t.Fatalf("stale metadata %+v %v", got, err)
			}
		})
	}
	for _, name := range []string{"routes", "permissions", "catalog", "retention", "recovery"} {
		t.Run("failure-"+name, func(t *testing.T) {
			f, s := newCaseFixture()
			f.fail = name
			if _, err := s.GetContextCase(context.Background(), f, caseID(9)); err != value.ErrUnavailable {
				t.Fatal("private error escaped", err)
			}
		})
	}
}
func TestContextCaseRequestOwnerCancellationCannotDetach(t *testing.T) {
	f, s := newCaseFixture()
	owner, cancel := context.WithCancel(context.Background())
	defer cancel()
	source, _, err := identities.NewBearerRequest(owner, f, "synthetic", func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	f.afterFinalRecovery = cancel
	got, err := s.GetContextCase(context.Background(), source, caseID(9))
	if err != value.ErrUnavailable || got.CaseID != "" {
		t.Fatal("detached request disclosed", got, err)
	}
}

// Synthetic processing authority in a component fixture; production composes
// the recovery-bound SQL reader, not this fixture.
func (f *caseFixture) ContextProcessing(_ context.Context, r permissions.ContextDownloadEvidence, recovery artifact.RecoveryProof) (artifact.DownloadProcessingProof, error) {
	f.processingReads++
	if f.fail == "processing" || !reflect.DeepEqual(r, f.record) || recovery != f.recovery {
		return artifact.DownloadProcessingProof{}, errors.New("restricted")
	}
	p := artifact.DownloadProcessingProof{RootID: caseID(1), Epoch: caseID(30), CaptureID: r.CaptureID, Location: r.Retained.Registration.Location, Sequence: 1, StateDigest: artifact.Digest{6}, ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}
	if f.processingChange && f.processingReads > 1 {
		p.Sequence++
	}
	return p, nil
}
func TestContextCaseProcessingRestrictionCoversMetadataAndFinalChange(t *testing.T) {
	for _, reason := range []string{"restricted", "changed", "missing"} {
		t.Run(reason, func(t *testing.T) {
			f, s := newCaseFixture()
			switch reason {
			case "restricted":
				f.fail = "processing"
			case "changed":
				f.processingChange = true
			case "missing":
				s.Processing = nil
			}
			got, e := s.GetContextCase(context.Background(), f, f.routes.CaseID)
			if e != value.ErrUnavailable || len(got.Artifacts) != 0 {
				t.Fatal("processing restriction disclosed metadata", got, e)
			}
		})
	}
}
func TestContextCaseDoesNotProbeProcessingBeforeRights(t *testing.T) {
	f, s := newCaseFixture()
	f.p.Allows = nil
	if _, e := s.GetContextCase(context.Background(), f, f.routes.CaseID); e != value.ErrUnavailable || f.processingReads != 0 {
		t.Fatal("processing lookup before eligibility", e, f.processingReads)
	}
}
