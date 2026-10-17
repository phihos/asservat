package evidence

import (
	"context"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

type healthyStopFixture struct {
	base             *stopFixture
	binding          audit.DownloadStopLifecycleBinding
	stored           *audit.DownloadStopWriteCompletion
	produced         audit.DownloadStopWriteCompletion
	creates, records int
	loseCompletion   bool
}

func (f *healthyStopFixture) ReadDownloadStopBinding(context.Context, artifact.DownloadStopDecision) (audit.DownloadStopLifecycleBinding, error) {
	return f.binding, nil
}
func (f *healthyStopFixture) ReadDownloadStopCompletion(context.Context, artifact.DownloadStopDecision) (audit.DownloadStopWriteCompletion, error) {
	if f.stored == nil {
		return audit.DownloadStopWriteCompletion{}, artifact.ErrDownloadUnavailable
	}
	return *f.stored, nil
}
func (f *healthyStopFixture) RecordDownloadStopCompletion(_ context.Context, _ artifact.DownloadStopDecision, c audit.DownloadStopWriteCompletion) error {
	f.records++
	if f.loseCompletion {
		return artifact.ErrDownloadUnavailable
	}
	f.stored = &c
	return nil
}
func (f *healthyStopFixture) CreateClosedDownloadStop(context.Context, audit.DownloadStopLifecycleBinding, artifact.DownloadStopDecision) (audit.DownloadStopWriteCompletion, error) {
	f.creates++
	return f.produced, nil
}
func newHealthyStopFixture(t *testing.T) (*healthyStopFixture, DownloadStopObjects) {
	t.Helper()
	base, _ := newStopFixture(t)
	d := &base.snapshot.Decision
	d.RequestedAt = d.RequestedAt.Truncate(time.Microsecond)
	d.WriteUntil = d.WriteUntil.Truncate(time.Microsecond)
	d.RetainUntil = d.RetainUntil.Truncate(time.Microsecond)
	p := audit.DownloadStopLifecyclePolicy{RootID: d.RootID, InstallationID: d.RootID, StoreID: d.StoreID, PolicyID: d.RootID, BackupProfileID: d.RootID, QualificationID: d.RootID, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, QualificationDigest: artifact.Digest{3}, Layout: audit.DownloadStopHistoryLayout, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1, MaxPurgeLeases: 4}
	b := audit.DownloadStopLifecycleBinding{Protocol: audit.DownloadStopWriterProtocol, RootID: d.RootID, DownloadID: d.DownloadID, AllocationID: d.RootID, IssuerEpoch: d.RootID, Policy: p, ReservedAt: d.RequestedAt, TransferUntil: d.RequestedAt.Add(time.Minute), HardDeleteBy: d.RetainUntil, OriginalPurgeAt: d.RetainUntil.Add(-4 * time.Minute), CertificatePurgeAt: d.RetainUntil.Add(-2 * time.Minute), LiveRetireBy: d.RetainUntil.Add(-time.Minute), HistoryReleaseAt: d.RetainUntil.Add(-time.Minute), HistoryDeleteBy: d.RetainUntil}
	c := audit.DownloadStopWriteCompletion{Protocol: audit.DownloadStopWriterProtocol, RootID: d.RootID, DownloadID: d.DownloadID, StoreID: d.StoreID, Phase: "decision", BindingDigest: auditapp.OperationLifecycleDigest(b), RecordDigest: auditapp.OperationLifecycleDigest(*d), Receipt: base.receipt(), StoredAt: d.RequestedAt, ClosedAt: d.RequestedAt}
	if !b.Valid() || !c.Valid(b, "decision", d.RequestedAt, d.WriteUntil) {
		t.Fatal("invalid fixture")
	}
	f := &healthyStopFixture{base: base, binding: b, produced: c}
	objects, e := NewHealthyDownloadStopObjects(base, f, f)
	if e != nil {
		t.Fatal(e)
	}
	return f, objects
}
func TestHealthyStopFindCannotInventLostProducerCompletion(t *testing.T) {
	f, objects := newHealthyStopFixture(t)
	d := f.base.snapshot.Decision
	f.loseCompletion = true
	if _, e := objects.CreateDownloadStop(t.Context(), d); e == nil {
		t.Fatal("lost SQL completion became acknowledged")
	}
	// The old adapter can find the original receipt. That fact is deliberately
	// insufficient to upgrade a lost joined-completion observation.
	if _, e := objects.FindDownloadStop(t.Context(), d); e == nil || f.base.finds != 0 || f.creates != 1 || f.records != 1 {
		t.Fatal("Find reconstructed writer completion", e, f.base.finds, f.creates, f.records)
	}
}
func TestHealthyStopRecoversOnlyExactPersistedCompletion(t *testing.T) {
	f, objects := newHealthyStopFixture(t)
	d := f.base.snapshot.Decision
	r, e := objects.CreateDownloadStop(t.Context(), d)
	if e != nil {
		t.Fatal(e)
	}
	got, e := objects.FindDownloadStop(t.Context(), d)
	if e != nil || got != r || f.creates != 1 || f.records != 1 {
		t.Fatal("valid exact replay failed", e)
	}
	f.stored.RecordDigest[0]++
	if _, e = objects.FindDownloadStop(t.Context(), d); e == nil || f.base.finds != 1 {
		t.Fatal("changed record reached backend")
	}
}
func TestHealthyStopRejectsForeignBindingAndIncompleteClose(t *testing.T) {
	for _, change := range []func(*healthyStopFixture){func(f *healthyStopFixture) { f.binding.Protocol = artifact.DownloadStopProtocol }, func(f *healthyStopFixture) { f.produced.ClosedAt = time.Time{} }, func(f *healthyStopFixture) { f.produced.BindingDigest[0]++ }} {
		f, o := newHealthyStopFixture(t)
		change(f)
		if _, e := o.CreateDownloadStop(t.Context(), f.base.snapshot.Decision); e == nil || f.records != 0 {
			t.Fatal("unqualified completion persisted")
		}
	}
}

// The independent provider may not be called merely because a durable
// completion exists. Its separately prepaid SQL verification attempt comes first.
type deniedStopVerification struct {
	state         audit.DownloadStopLifecycleSnapshot
	claims, opens int
}

func (f *deniedStopVerification) ReadDownloadStopLifecycle(context.Context, string) (audit.DownloadStopLifecycleSnapshot, error) {
	return f.state, nil
}
func (f *deniedStopVerification) BeginDownloadStopPurge(context.Context, string, string) (audit.DownloadStopPurgeLease, error) {
	panic("unexpected purge")
}
func (f *deniedStopVerification) RecordOriginalDownloadStopPurge(context.Context, audit.DownloadStopPurgeLease) (audit.DownloadStopRetirement, error) {
	panic("unexpected original purge")
}
func (f *deniedStopVerification) ClaimDownloadStopCertificate(context.Context, audit.DownloadStopRetirement) (bool, error) {
	panic("replayed certificate writer")
}
func (f *deniedStopVerification) RecordDownloadStopCertificateCompletion(context.Context, audit.DownloadStopRetirement, audit.DownloadStopWriteCompletion) error {
	panic("unexpected completion")
}
func (f *deniedStopVerification) RecordTerminalDownloadStopPurge(context.Context, audit.DownloadStopPurgeLease) (audit.DownloadStopPurgeResult, error) {
	panic("unexpected terminal purge")
}
func (f *deniedStopVerification) ClaimDownloadStopCertificateVerification(context.Context, audit.DownloadStopRetirement) (bool, error) {
	f.claims++
	return false, artifact.ErrDownloadUnavailable
}
func (f *deniedStopVerification) AcknowledgeDownloadStopCertificate(context.Context, audit.DownloadStopRetirement, audit.Receipt) error {
	panic("unqualified acknowledgement")
}
func (f *deniedStopVerification) AcknowledgeDownloadStopAbsence(context.Context, audit.DownloadStopPurgeLease, audit.DownloadStopPurgeResult) error {
	panic("unexpected absence acknowledgement")
}
func (f *deniedStopVerification) RetireDownloadStop(context.Context, string) error {
	panic("unexpected retirement")
}
func (f *deniedStopVerification) PurgeDownloadStopObjects(context.Context, audit.DownloadStopPurgeLease) error {
	panic("unexpected provider purge")
}
func (f *deniedStopVerification) CreateDownloadStopCertificate(context.Context, audit.DownloadStopLifecycleBinding, audit.DownloadStopRetirement) (audit.DownloadStopWriteCompletion, error) {
	panic("replayed provider creation")
}
func (f *deniedStopVerification) VerifyDownloadStopCertificate(context.Context, audit.DownloadStopRetirement, audit.Receipt) error {
	f.opens++
	return artifact.ErrDownloadUnavailable
}
func (f *deniedStopVerification) VerifyDownloadStopAbsence(context.Context, audit.DownloadStopPurgeLease) error {
	panic("unexpected provider absence")
}
func TestStopCertificateVerificationRequiresPrepaidAttemptBeforeOpen(t *testing.T) {
	f, _ := newHealthyStopFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	b := f.binding
	r := audit.DownloadStopRetirement{RootID: b.RootID, DownloadID: b.DownloadID, StoreID: b.Policy.StoreID, InstallationID: b.Policy.InstallationID, IssuerEpoch: b.IssuerEpoch, Mode: "written", BindingDigest: auditapp.OperationLifecycleDigest(b), ObjectsDigest: artifact.Digest{1}, WritersDigest: artifact.Digest{2}, PurgeFence: 1, PurgedAt: now, CertificateWriteUntil: now.Add(time.Second), CertificatePurgeAt: b.CertificatePurgeAt, LiveRetireBy: b.LiveRetireBy}
	if !r.Valid() {
		t.Fatal("invalid retirement fixture")
	}
	g := &deniedStopVerification{state: audit.DownloadStopLifecycleSnapshot{Binding: b, Retirement: &r, CertificateStarted: true, CertificateWriter: &f.produced}}
	cleanup := DownloadStopCleanup{Journal: g, Acknowledgements: g, Finalizer: g, Objects: g, Verifier: g, Now: time.Now}
	if e := cleanup.Advance(t.Context(), b.DownloadID); e == nil || g.claims != 1 || g.opens != 0 {
		t.Fatal("verification was not prepaid", e, g.claims, g.opens)
	}
}
