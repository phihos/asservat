package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

// Stop at the first business-journal boundary. This exercises the public
// composition's real ProcessingChanges logic without imitating SQL effects.
type processingSelectionFixture struct {
	profiles auditvalue.AcceptedCapacityAuditProfiles
	identity identity.Identity
	policy   value.DownloadPolicy
	recovery artifact.RecoveryProof
	draft    *privacy.ProcessingDecision
}

func (f *processingSelectionFixture) ReadCapacityAuditProfiles(context.Context) (auditvalue.AcceptedCapacityAuditProfiles, error) {
	return f.profiles, nil
}
func (f *processingSelectionFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	return f.identity, nil
}
func (f *processingSelectionFixture) DownloadPolicy(context.Context) (value.DownloadPolicy, error) {
	return f.policy, nil
}
func (f *processingSelectionFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, nil
}
func (f *processingSelectionFixture) PrepareProcessing(_ context.Context, _ value.ProcessingAuthority, draft privacy.ProcessingDecision) (privacy.ProcessingPrepared, error) {
	f.draft = &draft
	return privacy.ProcessingPrepared{}, value.ErrUnavailable
}
func (*processingSelectionFixture) ApplyProcessing(context.Context, value.ProcessingAuthority, privacy.ProcessingDecision) (value.ProcessingReceipt, error) {
	return value.ProcessingReceipt{}, value.ErrUnavailable
}
func (*processingSelectionFixture) Begin(context.Context, auditvalue.OperationIntent) error {
	return value.ErrUnavailable
}
func (*processingSelectionFixture) Finish(context.Context, auditvalue.OperationOutcome) error {
	return value.ErrUnavailable
}

func TestPublicProcessingSelectsReservedReleasePolicyAndRetention(t *testing.T) {
	for _, action := range []string{"initialize_processing", "restrict_processing", "release_processing"} {
		t.Run(action, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			const root = "00000000-0000-4000-8000-000000000001"
			rev := identity.Revision{UID: root, Generation: 1, Digest: artifact.Digest{1}}
			principal := identity.Principal{Issuer: "https://identity.invalid", ClientID: "console", Subject: "operator", Kind: identity.Human}
			f := &processingSelectionFixture{
				identity: identity.Identity{Principal: principal, Policy: rev, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)},
				policy: value.DownloadPolicy{RootID: root, InstallationID: root, RecoveryEpoch: root, Revision: rev,
					ProtectionDigest: artifact.Digest{2}, PermittedRegions: []string{}, Paths: []artifact.DownloadPath{}, Clients: []value.DownloadClient{},
					Operators: []value.ProcessingOperator{{Issuer: principal.Issuer, ClientID: principal.ClientID, Kind: "User", ID: principal.Subject}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)},
				recovery: artifact.RecoveryProof{InstallationID: root, IssuerEpoch: root, Revision: rev, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)},
			}
			lane := func(name, layout string, retained int64) auditvalue.CapacityAuditProfile {
				q := auditvalue.OperationHistoryQualification{ID: root, Digest: artifact.Digest{1}, Layout: layout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1}
				b, w := q.SlotBacking(2)
				return auditvalue.CapacityAuditProfile{RetainedSeconds: retained, Policy: auditvalue.OperationLifecyclePolicy{RootID: root, InstallationID: root, Lane: name,
					StoreID: root, PolicyID: root, BackupProfileID: root, PolicyDigest: artifact.Digest{2}, BackupProfileDigest: artifact.Digest{3}, BackingRevision: 1,
					MetadataSlots: 16, BackupReservedBytes: 16 * b, WALReservedBytes: 16 * w, CleanupBudgetSeconds: 1, ProofWindowSeconds: 1,
					ValidUntil: now.Add(time.Hour), MaxPurgeLeases: 2, History: &q, OverdueTerminal: auditvalue.OperationOverdueTerminal}}
			}
			f.profiles.Normal = lane("normal", auditvalue.OperationVerificationHistoryLayout, 3600)
			f.profiles.Processing = lane("processing", auditvalue.ProcessingReleaseHistoryLayout, 1800)
			mac, err := auditapp.NewOperationMAC("input", bytes.Repeat([]byte{1}, 32), "account", bytes.Repeat([]byte{2}, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer mac.Close()
			s := publicProcessingChanges{root: root, installation: root, profiles: f, policies: f, recovery: f, decisions: f, audit: f, releaseAudit: f, mac: mac}
			change := value.ProcessingChange{RequestID: root, Action: action}
			if action != "initialize_processing" {
				change.RuleID = "00000000-0000-4000-8000-000000000002"
				change.Scope = value.ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: root, ArtifactID: root, AttemptID: root}}
				if action == "release_processing" {
					change.ExpectedRevision = 1
				}
			}
			if _, err = s.Change(t.Context(), f, change); !errors.Is(err, value.ErrUnavailable) || f.draft == nil || !f.draft.Valid() {
				t.Fatal("public composition did not reach the prepared journal boundary", err)
			}
			want := f.profiles.Normal
			if action == "release_processing" {
				want = f.profiles.Processing
			}
			intent := f.draft.Intent
			if intent.Lifecycle.Policy.Lane != want.Policy.Lane || intent.Lifecycle.Policy.History.Layout != want.Policy.History.Layout || intent.RetainUntil.Sub(intent.CreatedAt) != time.Duration(want.RetainedSeconds)*time.Second {
				t.Fatal("public decision used another lane's policy or retention", intent)
			}
			if action == "release_processing" && (intent.PrincipalDigest != f.draft.ReleaseAccount || intent.Actor != principal) {
				t.Fatal("release lost its reserved account or actual human actor")
			}
		})
	}
}

type processingRefusalFixture struct {
	t        *testing.T
	ctx      context.Context
	cancel   context.CancelFunc
	cancelAt string
	reads    []string
	deadline time.Time
	identity identity.Identity
	policy   value.DownloadPolicy
}

func (f *processingRefusalFixture) read(ctx context.Context, stage string) {
	f.reads = append(f.reads, stage)
	got, bounded := ctx.Deadline()
	want, originalBound := f.ctx.Deadline()
	if !bounded || originalBound && !got.Equal(want) || !originalBound && got.After(time.Now().Add(5*time.Second)) {
		f.t.Error("diagnostic dependency extended the original deadline or five-second ceiling")
	}
	if !f.deadline.IsZero() && !got.Equal(f.deadline) {
		f.t.Error("diagnostic deadline renewed between dependency reads")
	}
	f.deadline = got
	if stage == f.cancelAt {
		f.cancel()
		if ctx.Err() == nil {
			f.t.Error("diagnostic dependency was detached from request cancellation")
		}
	}
}
func (f *processingRefusalFixture) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	f.read(ctx, "identity")
	return f.identity, nil
}
func (f *processingRefusalFixture) DownloadPolicy(ctx context.Context) (value.DownloadPolicy, error) {
	f.read(ctx, "policy")
	return f.policy, nil
}
func (f *processingRefusalFixture) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	f.read(ctx, "recovery")
	return artifact.RecoveryProof{}, nil
}

func TestPublicProcessingRefusalKeepsOriginalRequest(t *testing.T) {
	for _, test := range []struct {
		name, cancelAt string
		reads          int
	}{
		{"current", "", 3},
		{"uncapped-parent", "", 3},
		{"already-cancelled", "before", 0},
		{"already-expired", "expired", 0},
		{"cancelled-after-identity", "identity", 1},
		{"cancelled-after-policy", "policy", 2},
		{"cancelled-after-recovery", "recovery", 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now()
			until := now.Add(time.Second)
			if test.cancelAt == "expired" {
				until = now.Add(-time.Second)
			}
			var ctx context.Context
			var cancel context.CancelFunc
			if test.name == "uncapped-parent" {
				ctx, cancel = context.WithCancel(context.Background())
			} else {
				ctx, cancel = context.WithDeadline(context.Background(), until)
			}
			defer cancel()
			if test.cancelAt == "before" {
				cancel()
			}
			const root = "00000000-0000-4000-8000-000000000001"
			rev := identity.Revision{UID: root, Generation: 1, Digest: [32]byte{1}}
			principal := identity.Principal{Issuer: "https://identity.invalid", ClientID: "console", Subject: "operator", Kind: identity.Human}
			f := &processingRefusalFixture{t: t, ctx: ctx, cancel: cancel, cancelAt: test.cancelAt,
				identity: identity.Identity{Principal: principal, Policy: rev, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)},
				policy: value.DownloadPolicy{RootID: root, InstallationID: root, RecoveryEpoch: root, Revision: rev,
					ProtectionDigest: artifact.Digest{2}, PermittedRegions: []string{}, Paths: []artifact.DownloadPath{}, Clients: []value.DownloadClient{},
					Operators:  []value.ProcessingOperator{{Issuer: principal.Issuer, ClientID: principal.ClientID, Kind: "User", ID: principal.Subject}},
					ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}
			s := publicProcessingChanges{root: root, installation: root, policies: f, recovery: f, refused: func(string) {}}
			want := "request"
			if test.cancelAt == "" {
				want = "change"
			}
			if got := s.refusedStep(ctx, f); got != want {
				t.Errorf("refusal step = %q, want %q", got, want)
			}
			if len(f.reads) != test.reads {
				t.Fatalf("dependency reads = %v, want %d before cancellation", f.reads, test.reads)
			}
		})
	}
}
