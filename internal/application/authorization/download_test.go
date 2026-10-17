package authorization

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

type downloadAuthorityFixture struct {
	*fixture
	record                                         ContextDownloadEvidence
	resolved                                       privacy.RetainedResolution
	environment                                    artifact.DownloadEnvironment
	catalogReads, retentionReads, environmentReads int
	fail                                           string
	afterEnvironment                               func()
}

func (f *downloadAuthorityFixture) ContextDownloadEvidence(_ context.Context, id string) (ContextDownloadEvidence, error) {
	f.catalogReads++
	if id != f.record.Retained.Registration.Location.ArtifactID || f.fail == "catalog" {
		return ContextDownloadEvidence{}, errors.New("private catalog details")
	}
	return f.record, nil
}
func (f *downloadAuthorityFixture) ResolveRetained(_ context.Context, in privacy.Input, old privacy.Deadlines, origins []artifact.RetentionRule) (privacy.RetainedResolution, error) {
	f.retentionReads++
	if !reflect.DeepEqual(in, f.record.Retained.Input) || old != f.record.Retained.Effective || !reflect.DeepEqual(origins, f.record.Retained.OriginPolicies) || f.fail == "retention" {
		return privacy.RetainedResolution{}, errors.New("private privacy details")
	}
	return f.resolved, nil
}
func (f *downloadAuthorityFixture) DownloadEnvironment(_ context.Context, record ContextDownloadEvidence, p identity.Principal) (artifact.DownloadEnvironment, error) {
	f.environmentReads++
	if !reflect.DeepEqual(record, f.record) || p != f.i.Principal || f.fail == "environment" {
		return artifact.DownloadEnvironment{}, errors.New("private placement details")
	}
	if f.afterEnvironment != nil {
		f.afterEnvironment()
	}
	return f.environment, nil
}
func newDownloadAuthorityFixture() (*downloadAuthorityFixture, ContextDownloadAuthority, artifact.DownloadScope) {
	base, _, _ := newFixture()
	n := base.now
	root := "88888888-8888-4888-8888-888888888888"
	epoch := "99999999-9999-4999-8999-999999999999"
	base.p.Revision.UID = epoch
	t := base.p.Target
	scope := artifact.DownloadScope{RootID: root, ArtifactID: base.e.ArtifactID, CaptureID: "44444444-4444-4444-8444-444444444444", ClusterID: t.ClusterID, NamespaceUID: t.NamespaceUID, WorkloadUID: t.WorkloadUID, PodUID: t.PodUID, Version: artifact.Digest{2}, Principal: base.i.Principal}
	reg := artifact.Registration{Location: artifact.Location{ClusterID: t.ClusterID, ArtifactID: scope.ArtifactID, AttemptID: "55555555-5555-4555-8555-555555555555"}, StoreID: "66666666-6666-4666-8666-666666666666", AllocationID: "77777777-7777-4777-8777-777777777777", PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: n.Add(-time.Minute), WriteUntil: n.Add(-time.Second), ExpiresAt: n.Add(time.Hour), DeleteBy: n.Add(2 * time.Hour)}
	rev := identity.Revision{UID: "retention", Generation: 1, Digest: artifact.Digest{4}}
	refs := []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{5}}}
	deadlines := privacy.Deadlines{AnchorAt: reg.AnchorAt, ExpiresAt: reg.ExpiresAt, DeleteBy: reg.DeleteBy}
	proof := artifact.RetentionProof{RootID: root, ClusterID: t.ClusterID, NamespaceUID: t.NamespaceUID, WorkloadUID: t.WorkloadUID, PodUID: t.PodUID, Topology: rev, Policy: rev, Selectors: rev, SourceCount: 1, ObservedAt: n, ValidUntil: n.Add(5 * time.Second), Sources: [2]artifact.RetentionSourceVersion{{ClusterID: t.ClusterID, ControlNamespaceUID: "control", Epoch: epoch, Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: identity.Revision{UID: epoch, Generation: 1, Digest: artifact.Digest{3}}}}}
	f := &downloadAuthorityFixture{fixture: base, record: ContextDownloadEvidence{CaptureID: scope.CaptureID, PurposeRef: "diagnostics", Version: scope.Version, Audience: base.e.Audience, Retained: privacy.RetainedArtifact{RootID: root, Registration: reg, Input: privacy.Input{Target: t, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: 3600, AnchorAt: reg.AnchorAt}, OriginPolicies: refs, Effective: deadlines}, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}, resolved: privacy.RetainedResolution{Target: t, PolicyRevision: rev, PurposeRef: "diagnostics", Policies: refs, Deadlines: deadlines, Proof: proof, ValidUntil: n.Add(5 * time.Second)}, environment: artifact.DownloadEnvironment{InstallationID: root, RecoveryRevision: rev, RootID: root, Region: "europe", StoreID: reg.StoreID, RecoveryEpoch: epoch, Location: reg.Location, Principal: base.i.Principal, Revision: rev, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}}
	return f, ContextDownloadAuthority{RootID: root, Identities: f, Permissions: f, Catalog: f, Retention: f, Environment: f, Now: func() time.Time { return f.now }}, scope
}
func TestContextDownloadAuthorityUsesCurrentAudienceAndRetentionAfterCapture(t *testing.T) {
	f, s, scope := newDownloadAuthorityFixture()
	// Acquisition has closed, but independently authorized native download remains
	// available for the retained artifact. A shortening is reflected immediately.
	f.resolved.ExpiresAt = f.now.Add(10 * time.Minute)
	f.resolved.DeleteBy = f.now.Add(20 * time.Minute)
	f.environment.ValidUntil = f.now.Add(2 * time.Second)
	out, err := s.CheckDownload(context.Background(), "synthetic-token", scope)
	if err != nil || !out.Valid(f.now) || out.Scope != scope || !out.ValidUntil.Equal(f.environment.ValidUntil) || out.Retention != f.resolved.Proof || !out.AccessUntil.Equal(f.resolved.ExpiresAt) || !out.DeleteBy.Equal(f.resolved.DeleteBy) {
		t.Fatal("native disclosure decision", out, err)
	}
	if f.catalogReads != 1 || f.retentionReads != 1 || f.environmentReads != 1 || f.policyReads != 2 {
		t.Fatal("missing independent current checks")
	}
}
func TestContextDownloadAuthorityRefusesBeforeCatalogLookup(t *testing.T) {
	for _, which := range []string{"identity", "client", "deny", "scope", "no-grant", "incomplete"} {
		t.Run(which, func(t *testing.T) {
			f, s, scope := newDownloadAuthorityFixture()
			switch which {
			case "identity":
				f.identityError = true
			case "client":
				scope.Principal.ClientID = "other"
			case "deny":
				f.p.Denies = f.p.Allows
			case "scope":
				f.i.Scopes = []string{"evidence:read"}
			case "no-grant":
				f.p.Allows = nil
			case "incomplete":
				f.p.DeniesComplete = false
			}
			if _, err := s.CheckDownload(context.Background(), "synthetic-token", scope); err == nil || f.catalogReads != 0 || f.retentionReads != 0 || f.environmentReads != 0 {
				t.Fatal("unauthorized lookup", err)
			}
		})
	}
}
func TestContextDownloadAuthorityRefusesMissingChangedAndExpiredInputs(t *testing.T) {
	tests := []struct {
		name string
		edit func(*downloadAuthorityFixture, *ContextDownloadAuthority, *artifact.DownloadScope)
	}{
		{"missing-environment", func(f *downloadAuthorityFixture, s *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			s.Environment = nil
		}},
		{"missing-proof", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.resolved.Proof = artifact.RetentionProof{}
		}},
		{"wrong-proof-target", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.resolved.Proof.PodUID = "other"
		}},
		{"reclassified-raw", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.record.Retained.Input.EvidenceType = "coreDump"
		}},
		{"new-owner-not-in-original-audience", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.record.Audience = nil
		}},
		{"wrong-copy-version", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.record.Version[0]++
		}},
		{"replacement-capture", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.record.CaptureID = f.record.Retained.Registration.Location.AttemptID
		}},
		{"longer-deadline", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.resolved.ExpiresAt = f.resolved.ExpiresAt.Add(time.Second)
		}},
		{"purpose-substitution", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.resolved.PurposeRef = "other"
		}},
		{"closed-retention", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.resolved.ExpiresAt = f.now
		}},
		{"wrong-store", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.environment.StoreID = f.environment.RootID
		}},
		{"wrong-environment-client", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.environment.Principal.ClientID = "other"
		}},
		{"missing-recovery", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.environment.RecoveryEpoch = ""
		}},
		{"membership-revoked-after-io", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.afterEnvironment = func() { f.i.Groups = nil }
		}},
		{"deny-arrives-after-io", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.afterEnvironment = func() { f.p.Denies = f.p.Allows }
		}},
		{"identity-policy-changes-after-io", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.afterEnvironment = func() { f.i.Policy.Generation++ }
		}},
		{"permission-changes-after-io", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.afterEnvironment = func() { f.p.Revision.Generation++ }
		}},
		{"original-observation-expires", func(f *downloadAuthorityFixture, _ *ContextDownloadAuthority, _ *artifact.DownloadScope) {
			f.afterEnvironment = func() {
				f.now = f.now.Add(5 * time.Second)
				f.environment.ObservedAt = f.now
				f.environment.ValidUntil = f.now.Add(5 * time.Second)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, s, scope := newDownloadAuthorityFixture()
			test.edit(f, &s, &scope)
			if out, err := s.CheckDownload(context.Background(), "synthetic-token", scope); err == nil || out != (artifact.DownloadAuthority{}) {
				t.Fatal("invalid disclosure decision", err)
			}
		})
	}
	for _, source := range []string{"catalog", "retention", "environment"} {
		f, s, scope := newDownloadAuthorityFixture()
		f.fail = source
		if _, err := s.CheckDownload(context.Background(), "synthetic-token", scope); !errors.Is(err, artifact.ErrDownloadUnavailable) {
			t.Fatal("private error escaped", err)
		}
	}
	f, s, scope := newDownloadAuthorityFixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.CheckDownload(ctx, "synthetic-token", scope); err == nil || f.policyReads != 0 {
		t.Fatal("cancelled authority used")
	}
}
