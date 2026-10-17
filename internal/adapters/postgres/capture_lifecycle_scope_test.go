package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

func captureCleanupScopedIntent(t *testing.T, now time.Time, revision int64) value.OperationIntent {
	t.Helper()
	const root = "10000000-0000-4000-8000-000000000001"
	const capture = "10000000-0000-4000-8000-000000000002"
	mac, err := app.NewOperationMAC("input-v1", bytes.Repeat([]byte{1}, 32), "account-v1", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer mac.Close()
	c := value.CaptureIntent{RootID: root, CaptureID: capture, CaseID: root, OccurrenceID: capture, ArtifactID: root, AttemptID: capture, Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "operator", ClientID: "console", Kind: identity.Human}, Target: authorization.Target{ClusterID: root, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}, ScopeDigest: artifact.Digest{1}, SubmissionDigest: artifact.Digest{2}, ExpectationDigest: artifact.Digest{3}, PermissionEpoch: root, PermissionSequence: 1, IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{4}}, CreatedAt: now, Deadline: now.Add(30 * time.Second), ExpiresAt: now.Add(time.Minute), DeleteBy: now.Add(2 * time.Minute), ReservedBytes: 4096}
	p := value.OperationLifecyclePolicy{RootID: root, Lane: "capture", InstallationID: root, StoreID: root, PolicyID: root, BackupProfileID: root, PolicyDigest: artifact.Digest{5}, BackupProfileDigest: artifact.Digest{6}, BackingRevision: revision, MetadataSlots: 4, MaxPurgeLeases: 2, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, ValidUntil: now.Add(time.Hour)}
	p.History = &value.OperationHistoryQualification{ID: root, Digest: artifact.Digest{7}, Layout: value.CaptureOperationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1}
	b, w := p.History.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes, p.WALReservedBytes = b*p.MetadataSlots, w*p.MetadataSlots
	d, err := mac.CaptureAccount(root, root, root)
	if err != nil {
		t.Fatal(err)
	}
	a := value.CaptureAuditAccount{RootID: root, AllocationID: root, AccountVersion: mac.AccountVersion(), AccountDigest: d, Revision: revision, Records: 4, RetainedSeconds: 3600, Policy: p}
	in, err := app.PrepareCaptureOperation(c, a, mac, now.Add(5*time.Second))
	if err != nil || !in.Valid() {
		t.Fatal("synthetic admitted capture intent", err)
	}
	return in
}

func TestCaptureCleanupScopePreservesOriginalCohorts(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	old := captureCleanupScopedIntent(t, now.Add(-time.Hour), 1)
	next := captureCleanupScopedIntent(t, now, 2)
	scope := captureLifecycleScope{old.RootID, old.Lifecycle.Policy.InstallationID, old.Lifecycle.Policy.StoreID}
	before, _ := json.Marshal(old)
	if !scope.matches(old) || !scope.matches(next) {
		t.Fatal("valid original cohorts rejected")
	}
	after, _ := json.Marshal(old)
	if !bytes.Equal(before, after) {
		t.Fatal("cleanup selection rebound historical policy, account, or dates")
	}
	const other = "10000000-0000-4000-8000-000000000099"
	for _, wrong := range []captureLifecycleScope{{}, {other, scope.installation, scope.store}, {scope.root, other, scope.store}, {scope.root, scope.installation, other}} {
		if wrong.matches(old) {
			t.Fatal("historical capture crossed its installed scope")
		}
	}
	// Valid historical shape is not authority to extend a writer or delete a row.
	changed := old
	binding := *old.Lifecycle
	changed.Lifecycle = &binding
	changed.WriteUntil = now.Add(time.Second)
	if scope.matches(changed) {
		t.Fatal("scope accepted a changed original writer end")
	}
	// The original row binding, rather than the current constructor profile,
	// rejects substitution of a newer otherwise valid policy.
	a := custodydb.OperationAudit{ID: id(old.ID), RootID: id(old.RootID), Lane: "capture", PrincipalDigest: old.PrincipalDigest[:], RequestUntil: ts(old.RequestUntil), WriteUntil: ts(old.WriteUntil), RetainUntil: ts(old.RetainUntil)}
	a.Intent, _ = json.Marshal(old)
	d := custodydb.OperationAuditLifecycle{OperationID: a.ID, RootID: a.RootID, Lane: "capture", InstallationID: id(old.Lifecycle.Policy.InstallationID), IssuerEpoch: a.IssuerEpoch, OriginalPurgeAt: ts(old.Lifecycle.OriginalPurgeAt), CertificatePurgeAt: ts(old.Lifecycle.CertificatePurgeAt), LiveRetireBy: ts(old.Lifecycle.LiveRetireBy)}
	d.Binding, _ = json.Marshal(old.Lifecycle)
	if _, err := lifecycleState(a, d); err != nil {
		t.Fatal("original persisted lifecycle rejected", err)
	}
	binding.Policy = next.Lifecycle.Policy
	changed = old
	changed.Lifecycle = &binding
	a.Intent, _ = json.Marshal(changed)
	if _, err := lifecycleState(a, d); err == nil {
		t.Fatal("new current policy reinterpreted old persisted lifecycle")
	}
	old.Lifecycle = nil
	if scope.matches(old) {
		t.Fatal("missing original lifecycle accepted")
	}
}

func TestCaptureCleanupFullPolicyConstructorRetainsValidation(t *testing.T) {
	in := captureCleanupScopedIntent(t, time.Now().UTC().Truncate(time.Microsecond), 1)
	p := in.Lifecycle.Policy
	p.History = nil
	recovery, err := NewRecoveryTransactionGuard(p.RootID, p.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewCaptureOperationLifecycles(context.Background(), nil, p, recovery); err != app.ErrUnavailable {
		t.Fatal("full-policy constructor skipped historical backing validation", err)
	}
	if _, err = NewScopedCaptureOperationLifecycles(context.Background(), nil, p.RootID, p.InstallationID, p.StoreID, nil); err != app.ErrUnavailable {
		t.Fatal("scope accepted missing recovery", err)
	}
}
