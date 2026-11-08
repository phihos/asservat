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
	// ADR-311: one policy, recovery and processing read per check; SQL effect
	// fences reject a change after them and the next check observes it.
	if e != nil || !out.Valid(f.now) || out.Path != f.policy.Paths[0] || out.Processing != f.processing || out.RecoveryRevision != f.recovery.Revision || f.policyReads != 1 || f.recoveryReads != 1 || f.processingReads != 1 {
		t.Fatal("incomplete composed environment", e, f.policyReads, f.recoveryReads, f.processingReads)
	}
	for _, mode := range []string{"client", "purpose", "processing-missing", "processing-denied", "processing-substitution", "recovery"} {
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
	for _, at := range []string{"policy", "processing", "recovery"} {
		t.Run(at, func(t *testing.T) {
			f, s, r, a := newEnvironmentFixture()
			original := f.now.Add(time.Second)
			f.policy.FreshUntil = original
			advance := func() { f.now = original }
			switch at {
			case "policy":
				f.policyHook = func() {
					if f.policyReads == 1 {
						advance()
					}
				}
			case "processing":
				f.processingHook = advance
			case "recovery":
				f.recoveryHook = func() {
					if f.recoveryReads == 1 {
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

// A change after one check's single reads is not polled within that check; the
// SQL effect fences compare the carried revisions, and the next check observes
// the current state: a revision change is carried forward and a revocation or
// recovery change refuses.
func TestCurrentDownloadEnvironmentNextCheckObservesChange(t *testing.T) {
	for _, mode := range []string{"policy-revision", "recovery-revision", "processing-sequence", "client-revoked", "recovery-epoch", "processing-denied"} {
		t.Run(mode, func(t *testing.T) {
			f, s, r, a := newEnvironmentFixture()
			first, e := s.DownloadEnvironment(context.Background(), r, a)
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "policy-revision":
				f.policy.Revision.Generation++
			case "recovery-revision":
				f.recovery.Revision.Generation++
			case "processing-sequence":
				f.processing.Sequence++
			case "client-revoked":
				f.policy.Clients = nil
			case "recovery-epoch":
				f.recovery.IssuerEpoch = r.CaptureID
			case "processing-denied":
				f.processingErr = true
			}
			next, e := s.DownloadEnvironment(context.Background(), r, a)
			if f.policyReads != 2 {
				t.Fatal("next check reused the previous policy read", f.policyReads)
			}
			switch mode {
			case "policy-revision":
				if e != nil || next.Revision.Generation == first.Revision.Generation || next.Revision.Digest == first.Revision.Digest {
					t.Fatal("changed policy revision not carried to the effect fences", e)
				}
			case "recovery-revision":
				if e != nil || next.RecoveryRevision == first.RecoveryRevision {
					t.Fatal("changed recovery revision not carried to the effect fences", e)
				}
			case "processing-sequence":
				if e != nil || next.Processing.Sequence == first.Processing.Sequence {
					t.Fatal("changed processing state not carried to the effect fences", e)
				}
			default:
				if e == nil {
					t.Fatal("revocation or recovery change accepted at the next check", mode)
				}
			}
		})
	}
}
