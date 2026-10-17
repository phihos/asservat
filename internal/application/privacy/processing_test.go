package privacy

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"fmt"
	"testing"
	"time"
)

func processingID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

// Synthetic current source and durable journal fixture. No test value qualifies
// deployment regions, identity groups, SQL completeness or backend capacity.
type processingFixture struct {
	now                       time.Time
	i                         identity.Identity
	p                         value.DownloadPolicy
	recovery                  artifact.RecoveryProof
	prepared                  *ProcessingDecision
	receipt                   *value.ProcessingReceipt
	begins, finishes, applies int
	lost                      bool
	afterFinish, afterApply   func()
}

func (f *processingFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	return f.i, nil
}
func (f *processingFixture) DownloadPolicy(context.Context) (value.DownloadPolicy, error) {
	return f.p, nil
}
func (f *processingFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, nil
}
func (f *processingFixture) PrepareProcessing(_ context.Context, a value.ProcessingAuthority, d ProcessingDecision) (ProcessingPrepared, error) {
	if !a.Valid(f.now) {
		return ProcessingPrepared{}, value.ErrUnavailable
	}
	if f.prepared != nil {
		if f.prepared.Change != d.Change {
			return ProcessingPrepared{}, value.ErrConflict
		}
		return ProcessingPrepared{Decision: *f.prepared, Receipt: f.receipt}, nil
	}
	f.prepared = &d
	return ProcessingPrepared{Decision: d}, nil
}
func (f *processingFixture) Begin(_ context.Context, in auditvalue.OperationIntent) error {
	f.begins++
	if !in.Valid() {
		return value.ErrUnavailable
	}
	return nil
}
func (f *processingFixture) Finish(_ context.Context, out auditvalue.OperationOutcome) error {
	f.finishes++
	if !out.Valid() || out.Effect != "unknown" {
		return value.ErrUnavailable
	}
	if f.afterFinish != nil {
		f.afterFinish()
	}
	return nil
}
func (f *processingFixture) ApplyProcessing(_ context.Context, a value.ProcessingAuthority, d ProcessingDecision) (value.ProcessingReceipt, error) {
	if !a.Valid(f.now) || f.finishes == 0 || f.prepared == nil || d.DecisionDigest != f.prepared.DecisionDigest {
		return value.ProcessingReceipt{}, value.ErrUnavailable
	}
	f.applies++
	f.receipt = &value.ProcessingReceipt{RootID: d.Intent.RootID, Epoch: processingID(7), RequestID: d.Change.RequestID, OperationID: d.Intent.ID, State: "initialized", Sequence: 2, ObservedAt: a.ObservedAt, ValidUntil: a.ValidUntil}
	if d.Change.Action != "initialize_processing" {
		f.receipt.RuleID = d.Change.RuleID
		f.receipt.Revision = d.Change.ExpectedRevision + 1
		f.receipt.State = "restricted"
		if d.Change.Action == "release_processing" {
			f.receipt.State = "released"
		}
	}
	if f.afterApply != nil {
		f.afterApply()
	}
	if f.lost {
		return value.ProcessingReceipt{}, value.ErrUnavailable
	}
	return *f.receipt, nil
}
func newProcessingFixture(t *testing.T) (*processingFixture, ProcessingChanges, value.ProcessingChange) {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	root := processingID(1)
	rev := identity.Revision{UID: processingID(2), Generation: 1, Digest: artifact.Digest{1}}
	i := identity.Identity{Principal: identity.Principal{Issuer: "https://identity.invalid", ClientID: "console", Subject: "privacy-operator", Kind: identity.Human}, Groups: []string{"privacy"}, Scopes: []string{"evidence:read"}, Policy: rev, VerifiedAt: n, ValidUntil: n.Add(5 * time.Second)}
	f := &processingFixture{now: n, i: i, p: value.DownloadPolicy{RootID: root, InstallationID: root, RecoveryEpoch: processingID(3), Revision: rev, ProtectionDigest: artifact.Digest{2}, PermittedRegions: []string{}, Paths: []artifact.DownloadPath{}, Clients: []value.DownloadClient{}, Operators: []value.ProcessingOperator{{Issuer: i.Principal.Issuer, ClientID: i.Principal.ClientID, Kind: "Group", ID: "privacy"}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, recovery: artifact.RecoveryProof{InstallationID: root, IssuerEpoch: processingID(3), Revision: rev, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}}
	key, account := make([]byte, 32), make([]byte, 32)
	key[0] = 1
	account[0] = 2
	mac, e := auditapp.NewOperationMAC("test-input", key, "test-account", account)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(mac.Close)
	policy := auditvalue.OperationLifecyclePolicy{RootID: root, Lane: "normal", InstallationID: root, StoreID: root, PolicyID: root, BackupProfileID: root, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: 10, MaxPurgeLeases: 16, CleanupBudgetSeconds: 10, ProofWindowSeconds: 60, ValidUntil: n.Add(time.Hour)}
	policy.History = &auditvalue.OperationHistoryQualification{ID: root, Digest: artifact.Digest{3}, Layout: auditvalue.OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}
	b, w := policy.History.SlotBacking(policy.MaxPurgeLeases)
	policy.BackupReservedBytes = b * policy.MetadataSlots
	policy.WALReservedBytes = w * policy.MetadataSlots
	service := ProcessingChanges{RootID: root, InstallationID: root, Policies: f, Recovery: f, Decisions: f, Audit: f, MAC: mac, AuditPolicy: policy, RetainedSeconds: 3600, Now: func() time.Time { return f.now }}
	return f, service, value.ProcessingChange{RequestID: processingID(4), Action: "initialize_processing"}
}
func TestProcessingDecisionAuditsPreparedUnknownBeforeCAS(t *testing.T) {
	f, s, c := newProcessingFixture(t)
	out, e := s.Change(context.Background(), f, c)
	if e != nil || !out.Valid(f.now) || out.State != "initialized" || f.begins != 1 || f.finishes != 1 || f.applies != 1 || f.prepared.Outcome.Effect != "unknown" {
		t.Fatal("prepared decision/CAS", out, e, f.begins, f.finishes, f.applies)
	}
}
func TestProcessingUnknownCASReplyRecoversOriginalWithoutAuditSpend(t *testing.T) {
	f, s, c := newProcessingFixture(t)
	f.lost = true
	if _, e := s.Change(context.Background(), f, c); e == nil {
		t.Fatal("lost response called accepted")
	}
	f.lost = false
	out, e := s.Change(context.Background(), f, c)
	if e != nil || out.OperationID != c.RequestID || f.begins != 1 || f.finishes != 1 || f.applies != 1 {
		t.Fatal("replay allocated new work", out, e, f.begins, f.finishes, f.applies)
	}
}
func TestProcessingNoReleaseFromOrdinaryApprovalAndNoAuthorityAfterWait(t *testing.T) {
	for _, why := range []string{"ordinary-owner", "client", "post-audit-revoke", "post-audit-expire", "post-SQL-revoke"} {
		t.Run(why, func(t *testing.T) {
			f, s, c := newProcessingFixture(t)
			switch why {
			case "ordinary-owner":
				f.i.Groups = []string{"owners"}
			case "client":
				f.i.Principal.ClientID = "other"
			case "post-audit-revoke":
				f.afterFinish = func() { f.i.Groups = nil }
			case "post-audit-expire":
				f.afterFinish = func() { f.now = f.i.ValidUntil }
			case "post-SQL-revoke":
				f.afterApply = func() { f.i.Groups = nil }
			}
			out, e := s.Change(context.Background(), f, c)
			if e == nil || out.RequestID != "" {
				t.Fatal("lost current authority disclosed receipt", out, e)
			}
			if why != "post-SQL-revoke" && f.applies != 0 {
				t.Fatal("CAS after lost authority")
			}
		})
	}
}

// Normal audit exhaustion must not consume the separately prepaid release lane.
type exhaustedProcessingAudit struct{ calls int }

func (f *exhaustedProcessingAudit) Begin(context.Context, auditvalue.OperationIntent) error {
	f.calls++
	return value.ErrUnavailable
}
func (f *exhaustedProcessingAudit) Finish(context.Context, auditvalue.OperationOutcome) error {
	f.calls++
	return value.ErrUnavailable
}
func TestProcessingReleaseUsesReservedLaneAndActualHuman(t *testing.T) {
	f, s, c := newProcessingFixture(t)
	normal := &exhaustedProcessingAudit{}
	s.Audit = normal
	s.ReleaseAudit = f
	p := s.AuditPolicy
	p.Lane = "processing"
	q := *p.History
	q.Layout = auditvalue.ProcessingReleaseHistoryLayout
	p.History = &q
	b, w := q.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes = b * p.MetadataSlots
	p.WALReservedBytes = w * p.MetadataSlots
	s.ReleaseAuditPolicy = p
	c.Action = "release_processing"
	c.RuleID = processingID(8)
	c.ExpectedRevision = 1
	c.Scope = value.ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: processingID(9), ArtifactID: processingID(10), AttemptID: processingID(11)}}
	out, e := s.Change(context.Background(), f, c)
	if e != nil || out.State != "released" || normal.calls != 0 || f.prepared.Intent.Actor != f.i.Principal || auditvalue.OperationLane(f.prepared.Intent.Name) != "processing" || f.prepared.Intent.PrincipalDigest != f.prepared.ReleaseAccount {
		t.Fatal("prepaid release changed actor or used normal capacity", out, e, normal.calls)
	}
	human, _ := s.MAC.Principal(f.i.Principal)
	if human == f.prepared.ReleaseAccount {
		t.Fatal("rule reserve reused human account")
	}
}
func TestProcessingReleaseRejectsPublicOrWrongPrivateQualification(t *testing.T) {
	for _, layout := range []string{auditvalue.OperationVerificationHistoryLayout, auditvalue.ConnectorOperationHistoryLayout} {
		f, s, c := newProcessingFixture(t)
		s.ReleaseAudit = f
		p := s.AuditPolicy
		p.Lane = "processing"
		q := *p.History
		q.Layout = layout
		q.MaximumRowFootprintBytes = 1 << 20
		p.History = &q
		b, w := q.SlotBacking(p.MaxPurgeLeases)
		p.BackupReservedBytes = b * p.MetadataSlots
		p.WALReservedBytes = w * p.MetadataSlots
		s.ReleaseAuditPolicy = p
		c.Action = "release_processing"
		c.RuleID = processingID(8)
		c.ExpectedRevision = 1
		c.Scope = value.ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: processingID(9), ArtifactID: processingID(10), AttemptID: processingID(11)}}
		if _, e := s.Change(context.Background(), f, c); e == nil || f.begins != 0 {
			t.Fatal("unqualified release provider work", layout, e)
		}
	}
}
