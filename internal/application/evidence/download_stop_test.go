package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
)

type stopFixture struct {
	now                                 time.Time
	i                                   identity.Identity
	snapshot                            DownloadStopSnapshot
	stops, claims, creates, finds, acks int
	failCreate                          bool
	after                               func()
}

func (f *stopFixture) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return f.i, ctx.Err()
}
func (f *stopFixture) StopDownload(_ context.Context, i identity.Identity, id string, key artifact.Digest, request string) (DownloadStopSnapshot, error) {
	f.stops++
	if i.Principal != f.snapshot.Decision.Actor || id != f.snapshot.Decision.DownloadID || key != f.snapshot.Decision.KeyDigest {
		return DownloadStopSnapshot{}, artifact.ErrDownloadUnavailable
	}
	return f.snapshot, nil
}
func (f *stopFixture) ClaimDownloadStopWrite(context.Context, artifact.DownloadStopDecision) (bool, error) {
	f.claims++
	fresh := !f.snapshot.WriteStarted
	f.snapshot.WriteStarted = true
	return fresh, nil
}
func (f *stopFixture) receipt() audit.Receipt {
	return audit.Receipt{Key: artifact.DownloadStopKey(f.snapshot.Decision.RootID, f.snapshot.Decision.DownloadID), ETag: "exact", Bytes: 512, SHA256: artifact.Digest{3}}
}
func (f *stopFixture) CreateDownloadStop(context.Context, artifact.DownloadStopDecision) (audit.Receipt, error) {
	f.creates++
	if f.after != nil {
		f.after()
	}
	if f.failCreate {
		return audit.Receipt{}, errors.New("private provider diagnostic")
	}
	return f.receipt(), nil
}
func (f *stopFixture) FindDownloadStop(context.Context, artifact.DownloadStopDecision) (audit.Receipt, error) {
	f.finds++
	return f.receipt(), nil
}
func (f *stopFixture) AcknowledgeDownloadStop(_ context.Context, _ artifact.DownloadStopDecision, r audit.Receipt) error {
	f.acks++
	f.snapshot.Receipt = &r
	return nil
}
func (f *stopFixture) PendingDownloadStops(context.Context) ([]DownloadStopSnapshot, error) {
	return []DownloadStopSnapshot{f.snapshot}, nil
}
func newStopFixture(t *testing.T) (*stopFixture, ContextDownloadStopCoordinator) {
	t.Helper()
	base, _ := newDownloadControlFixture(t)
	now := time.Now().UTC()
	base.refresh(now)
	f := &stopFixture{now: now, i: base.i}
	f.i.Scopes = []string{"openid"}
	f.snapshot = DownloadStopSnapshot{ObservedAt: now, ValidUntil: now.Add(5 * time.Second), Decision: artifact.DownloadStopDecision{Protocol: artifact.DownloadStopProtocol, RootID: base.a.Scope.RootID, DownloadID: "22222222-2222-4222-8222-222222222222", RequestID: "33333333-3333-4333-8333-333333333333", StoreID: base.source.Expectation.Registration.StoreID, Actor: f.i.Principal, KeyDigest: DownloadStopKeyDigest("same-key"), State: "Cancelled", RequestedAt: now, WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}}
	if !f.i.Valid(now) || !f.snapshot.Decision.Valid() {
		t.Fatal("invalid synthetic stop fixture")
	}
	return f, ContextDownloadStopCoordinator{Ledger: f, Acknowledgements: f, Objects: f, Now: func() time.Time { return f.now }}
}
func TestDownloadStopWithoutEvidenceScopesAndSameKeyReplay(t *testing.T) {
	f, s := newStopFixture(t)
	d := f.snapshot.Decision
	out, e := s.CancelContextDownload(t.Context(), f, d.DownloadID, "same-key", d.RequestID)
	if e != nil || out.State != "Cancelled" || out.AuditState != "recorded" || f.creates != 1 || f.acks != 1 {
		t.Fatal(out, e)
	}
	out, e = s.CancelContextDownload(t.Context(), f, d.DownloadID, "same-key", "44444444-4444-4444-8444-444444444444")
	if e != nil || out.RequestID != d.RequestID || f.claims != 1 || f.creates != 1 {
		t.Fatal("replay renewed stop or receipt", out, e)
	}
	if _, e = s.CancelContextDownload(t.Context(), f, d.DownloadID, "different-key", d.RequestID); e == nil {
		t.Fatal("new key accepted")
	}
}
func TestDownloadStopUnknownWriteRemainsPendingAndNeverRecreated(t *testing.T) {
	f, s := newStopFixture(t)
	d := f.snapshot.Decision
	f.failCreate = true
	out, e := s.CancelContextDownload(t.Context(), f, d.DownloadID, "same-key", d.RequestID)
	if e != nil || out.State != "Cancelled" || out.AuditState != "pending" {
		t.Fatal("restriction lost on audit failure", out, e)
	}
	out, e = s.CancelContextDownload(t.Context(), f, d.DownloadID, "same-key", d.RequestID)
	if e != nil || out.AuditState != "recorded" || f.creates != 1 || f.finds != 1 {
		t.Fatal("unknown PUT replayed", out, e)
	}
}
func TestDownloadStopFinalIdentityDeadlineAfterProviderWait(t *testing.T) {
	f, s := newStopFixture(t)
	d := f.snapshot.Decision
	f.after = func() { f.now = f.now.Add(6 * time.Second) }
	if out, e := s.CancelContextDownload(t.Context(), f, d.DownloadID, "same-key", d.RequestID); e == nil || out.DownloadID != "" || f.stops != 1 {
		t.Fatal("expired identity disclosed receipt", out, e)
	}
}
func TestDownloadStopReconciliationFindsOriginalAfterWriteWindow(t *testing.T) {
	f, s := newStopFixture(t)
	f.snapshot.WriteStarted = true
	f.now = f.now.Add(time.Minute)
	if e := s.ReconcilePending(t.Context(), f); e != nil || f.finds != 1 || f.creates != 0 || f.acks != 1 {
		t.Fatal("late existing receipt could not reconcile", e)
	}
	f, s = newStopFixture(t)
	f.now = f.now.Add(time.Minute)
	if e := s.ReconcilePending(t.Context(), f); e != nil || f.claims != 0 || f.creates != 0 {
		t.Fatal("late reconciliation started a new write", e)
	}
}
func TestDownloadStopAlreadyTerminalIsCoarseAndActorBound(t *testing.T) {
	f, s := newStopFixture(t)
	d := f.snapshot.Decision
	f.snapshot.Decision.State = "AlreadyTerminal"
	out, e := s.CancelContextDownload(t.Context(), f, d.DownloadID, "same-key", d.RequestID)
	if e != nil || out.State != "AlreadyTerminal" {
		t.Fatal(out, e)
	}
	f.i.Principal.ClientID = "different-client"
	if _, e = s.CancelContextDownload(t.Context(), f, d.DownloadID, "same-key", d.RequestID); e == nil {
		t.Fatal("foreign client read stop receipt")
	}
}
