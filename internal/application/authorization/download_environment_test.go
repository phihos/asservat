package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

type environmentFixture struct {
	now                                         time.Time
	policy                                      privacy.DownloadPolicy
	recovery                                    artifact.RecoveryProof
	processing                                  artifact.DownloadProcessingProof
	policyReads, recoveryReads, processingReads int
	policyHook, recoveryHook, processingHook    func()
	processingErr                               bool
}

func (f *environmentFixture) DownloadPolicy(context.Context) (privacy.DownloadPolicy, error) {
	f.policyReads++
	if f.policyHook != nil {
		f.policyHook()
	}
	return f.policy, nil
}
func (f *environmentFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	f.recoveryReads++
	if f.recoveryHook != nil {
		f.recoveryHook()
	}
	return f.recovery, nil
}
func (f *environmentFixture) ContextProcessing(_ context.Context, r ContextDownloadEvidence, p artifact.RecoveryProof) (artifact.DownloadProcessingProof, error) {
	f.processingReads++
	if f.processingHook != nil {
		f.processingHook()
	}
	if f.processingErr || p != f.recovery || r.CaptureID != f.processing.CaptureID {
		return artifact.DownloadProcessingProof{}, errors.New("private processing state")
	}
	return f.processing, nil
}
func newEnvironmentFixture() (*environmentFixture, CurrentDownloadEnvironment, ContextDownloadEvidence, identity.Principal) {
	base, _, scope := newDownloadAuthorityFixture()
	r := base.record
	n := time.Now().UTC().Truncate(time.Microsecond)
	r.ObservedAt = n
	r.ValidUntil = n.Add(5 * time.Second)
	reg := &r.Retained.Registration
	reg.AnchorAt = n.Add(-time.Minute)
	reg.WriteUntil = n.Add(-time.Second)
	reg.ExpiresAt = n.Add(time.Hour)
	reg.DeleteBy = n.Add(2 * time.Hour)
	r.Retained.Input.AnchorAt = reg.AnchorAt
	r.Retained.Effective = privacy.Deadlines{AnchorAt: reg.AnchorAt, ExpiresAt: reg.ExpiresAt, DeleteBy: reg.DeleteBy}
	rev := identity.Revision{UID: scope.RootID, Generation: 1, Digest: artifact.Digest{7}}
	path := privacy.DownloadPath{ID: scope.RootID, TargetClusterID: scope.ClusterID, StoreID: reg.StoreID, StorageRegion: "local", AcquisitionClusterID: scope.ClusterID, AcquisitionRegion: "local", ConnectorClusterID: scope.ClusterID, ConnectorRegion: "local", HubClusterID: scope.ClusterID, HubRegion: "local", WorkerConfiguration: rev, HubConfiguration: rev}
	p := privacy.DownloadPolicy{RootID: scope.RootID, InstallationID: scope.RootID, RecoveryEpoch: scope.RootID, Revision: rev, ProtectionDigest: artifact.Digest{8}, PermittedRegions: []string{"local"}, Paths: []privacy.DownloadPath{path}, Clients: []privacy.DownloadClient{{Issuer: scope.Principal.Issuer, ID: scope.Principal.ClientID, Kind: scope.Principal.Kind, DataClasses: []string{"metadata"}, PrivacyClasses: []string{"potentialPersonalData"}, EvidenceTypes: []string{"context"}, Purposes: []string{r.PurposeRef}, PathIDs: []string{path.ID}}}, Operators: []privacy.ProcessingOperator{{Issuer: scope.Principal.Issuer, ClientID: scope.Principal.ClientID, Kind: "Group", ID: "privacy"}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	f := &environmentFixture{now: n, policy: p, recovery: artifact.RecoveryProof{InstallationID: scope.RootID, IssuerEpoch: scope.RootID, Revision: rev, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, processing: artifact.DownloadProcessingProof{RootID: scope.RootID, Epoch: scope.RootID, CaptureID: r.CaptureID, Location: reg.Location, Sequence: 1, StateDigest: artifact.Digest{9}, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}}
	return f, CurrentDownloadEnvironment{RootID: scope.RootID, InstallationID: scope.RootID, Policies: f, Recovery: f, Processing: f, Now: func() time.Time { return f.now }}, r, scope.Principal
}
func TestCurrentDownloadEnvironmentRequiresIndependentPolicyProcessingRecovery(t *testing.T) {
	f, s, r, a := newEnvironmentFixture()
	out, e := s.DownloadEnvironment(context.Background(), r, a)
	if e != nil || !out.Valid(f.now) || out.Path != f.policy.Paths[0] || out.Processing != f.processing || out.RecoveryRevision != f.recovery.Revision || f.policyReads != 2 || f.recoveryReads != 2 || f.processingReads != 2 {
		t.Fatal("incomplete composed environment", e)
	}
	for _, mode := range []string{"client", "purpose", "processing-missing", "processing-denied", "processing-substitution", "recovery", "policy-change", "recovery-change", "processing-change"} {
		t.Run(mode, func(t *testing.T) {
			f, s, r, a := newEnvironmentFixture()
			switch mode {
			case "client":
				a.ClientID = "unapproved-mcp"
			case "purpose":
				r.PurposeRef = "different"
			case "processing-missing":
				f.processing = artifact.DownloadProcessingProof{}
			case "processing-denied":
				f.processingErr = true
			case "processing-substitution":
				f.processing.CaptureID = f.processing.RootID
			case "recovery":
				f.recovery.IssuerEpoch = r.CaptureID
			case "policy-change":
				f.policyHook = func() {
					if f.policyReads == 2 {
						f.policy.Revision.Generation++
					}
				}
			case "processing-change":
				f.processingHook = func() {
					if f.processingReads == 2 {
						f.processing.Sequence++
					}
				}
			case "recovery-change":
				f.recoveryHook = func() {
					if f.recoveryReads == 2 {
						f.recovery.Revision.Generation++
					}
				}
			}
			if _, e := s.DownloadEnvironment(context.Background(), r, a); e == nil {
				t.Fatal("missing/contradictory authority accepted")
			}
			if (mode == "client" || mode == "purpose") && f.processingReads != 0 {
				t.Fatal("unauthorized processing lookup")
			}
		})
	}
}
func TestCurrentDownloadEnvironmentPreservesEarliestDeadlineAfterBlockingWork(t *testing.T) {
	for _, at := range []string{"policy", "processing", "final-recovery"} {
		t.Run(at, func(t *testing.T) {
			f, s, r, a := newEnvironmentFixture()
			original := f.now.Add(time.Second)
			f.policy.FreshUntil = original
			advance := func() { f.now = original }
			switch at {
			case "policy":
				f.policyHook = func() {
					if f.policyReads == 2 {
						advance()
					}
				}
			case "processing":
				f.processingHook = advance
			case "final-recovery":
				f.recoveryHook = func() {
					if f.recoveryReads == 2 {
						advance()
					}
				}
			}
			if _, e := s.DownloadEnvironment(context.Background(), r, a); e == nil {
				t.Fatal("blocking work renewed original policy deadline")
			}
		})
	}
	f, s, r, a := newEnvironmentFixture()
	end := f.now.Add(time.Second)
	f.processing.ValidUntil = end
	out, e := s.DownloadEnvironment(context.Background(), r, a)
	if e != nil || !out.ValidUntil.Equal(end) {
		t.Fatal("processing deadline not inherited", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := f.policyReads
	if _, e = s.DownloadEnvironment(ctx, r, a); e == nil || f.policyReads != before {
		t.Fatal("canceled caller admitted")
	}
}
