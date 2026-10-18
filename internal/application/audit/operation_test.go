package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func auditIntent() value.OperationIntent {
	n := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	return value.OperationIntent{ID: "00000000-0000-4000-8000-000000000001", RootID: "00000000-0000-4000-8000-000000000002", TraceID: "00000000-0000-4000-8000-000000000001", Name: "get_capture", InputFormat: "context-input/v1", MACVersion: "audit-v1", AccountVersion: "accounts-v1", Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Hour)}
}
func auditOutcome(in value.OperationIntent) value.OperationOutcome {
	return value.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "none", ClientReceipt: "unknown", OutputDigest: artifact.Digest{3}, OutputBytes: 15, MetadataUntil: in.RequestUntil, RecordedAt: in.CreatedAt.Add(time.Second)}
}

type operationFixture struct {
	snap                           value.OperationSnapshot
	creates, finds, acks           int
	lostCreate, lostClaim, failAck bool
	after                          func()
}

func (f *operationFixture) ReserveOperation(_ context.Context, in value.OperationIntent) (value.OperationSnapshot, error) {
	if f.snap.Intent.ID == "" {
		f.snap.Intent = in
	}
	return f.snap, nil
}
func (f *operationFixture) ClaimOperationWrite(_ context.Context, in value.OperationIntent, phase string) (bool, error) {
	p := &f.snap.IntentStarted
	if phase == "outcome" {
		p = &f.snap.OutcomeStarted
	}
	old := *p
	*p = true
	if f.lostClaim {
		f.lostClaim = false
		return false, errors.New("lost commit")
	}
	return !old, nil
}
func (f *operationFixture) FreezeOperationOutcome(_ context.Context, o value.OperationOutcome) (value.OperationSnapshot, error) {
	f.snap.Outcome = &o
	return f.snap, nil
}
func receipt(in value.OperationIntent, phase string) value.Receipt {
	return value.Receipt{Key: value.OperationAuditKey(in.RootID, in.ID, phase), ETag: "synthetic", Bytes: 100, SHA256: artifact.Digest{1}}
}
func (f *operationFixture) AcknowledgeOperation(_ context.Context, in value.OperationIntent, phase string, r value.Receipt) error {
	f.acks++
	if f.failAck {
		return errors.New("provider details forbidden")
	}
	if phase == "intent" {
		f.snap.IntentReceipt = &r
	} else {
		f.snap.OutcomeReceipt = &r
	}
	if f.after != nil {
		f.after()
	}
	return nil
}
func (f *operationFixture) CreateOperationIntent(_ context.Context, in value.OperationIntent) (value.Receipt, error) {
	f.creates++
	if f.lostCreate {
		f.lostCreate = false
		return value.Receipt{}, errors.New("unknown PUT")
	}
	return receipt(in, "intent"), nil
}
func (f *operationFixture) FindOperationIntent(_ context.Context, in value.OperationIntent) (value.Receipt, error) {
	f.finds++
	if f.creates == 0 {
		return value.Receipt{}, errors.New("not found")
	}
	return receipt(in, "intent"), nil
}
func (f *operationFixture) CreateOperationOutcome(_ context.Context, in value.OperationOutcome) (value.Receipt, error) {
	f.creates++
	return receipt(in.Intent, "outcome"), nil
}
func (f *operationFixture) FindOperationOutcome(_ context.Context, in value.OperationOutcome) (value.Receipt, error) {
	f.finds++
	return receipt(in.Intent, "outcome"), nil
}
func TestOperationAuditorUnknownRepliesNeverRecreate(t *testing.T) {
	for _, mode := range []string{"lost-create", "lost-claim", "lost-ack"} {
		t.Run(mode, func(t *testing.T) {
			in := auditIntent()
			f := &operationFixture{lostCreate: mode == "lost-create", lostClaim: mode == "lost-claim", failAck: mode == "lost-ack"}
			s := OperationAuditor{Journal: f, Acknowledgements: f, Objects: f, Now: func() time.Time { return in.CreatedAt }}
			if e := s.Begin(context.Background(), in); !errors.Is(e, ErrUnavailable) {
				t.Fatal("unknown first reply accepted", e)
			}
			f.failAck = false
			err := s.Begin(context.Background(), in)
			if mode == "lost-claim" {
				if !errors.Is(err, ErrUnavailable) || f.creates != 0 || f.finds != 1 {
					t.Fatal("unknown claim created later", err, f)
				}
			} else if err != nil || f.creates != 1 || f.finds != 1 {
				t.Fatal("unknown write recreated", err, f)
			}
		})
	}
}
func TestOperationAuditorPreservesOriginalDeadlineAfterAcknowledgement(t *testing.T) {
	in := auditIntent()
	now := in.CreatedAt
	f := &operationFixture{}
	s := OperationAuditor{Journal: f, Acknowledgements: f, Objects: f, Now: func() time.Time { return now }}
	f.after = func() { now = in.RequestUntil }
	if !errors.Is(s.Begin(context.Background(), in), ErrUnavailable) || f.snap.IntentReceipt == nil {
		t.Fatal("late acknowledgement revived authority")
	}
}
func TestOperationAuditDoesNotAssertDelivery(t *testing.T) {
	in := auditIntent()
	f := &operationFixture{}
	s := OperationAuditor{Journal: f, Acknowledgements: f, Objects: f, Now: func() time.Time { return in.CreatedAt }}
	if err := s.Begin(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	out := auditOutcome(in)
	if err := s.Finish(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	if f.creates != 2 || f.acks != 2 || f.snap.Outcome.ClientReceipt != "unknown" {
		t.Fatal(f)
	}
	if err := s.Finish(context.Background(), out); err != nil || f.creates != 2 {
		t.Fatal("completion replay created", err)
	}
	out.ClientReceipt = "received"
	if !errors.Is(s.Finish(context.Background(), out), ErrUnavailable) {
		t.Fatal("asserted client receipt")
	}
}
func TestOperationMACRotationKeepsAccountSpendIdentity(t *testing.T) {
	key, account := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	a, e := NewOperationMAC("audit-v1", key, "account-v1", account)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := NewOperationMAC("audit-v2", bytes.Repeat([]byte{3}, 32), "account-v1", account)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	p := auditIntent().Actor
	x, _ := a.Principal(p)
	p.ClientID = "mcp"
	y, _ := b.Principal(p)
	if x != y {
		t.Fatal("audit key/client rotation reset account")
	}
	p.Subject = "another"
	z, _ := a.Principal(p)
	if z == x {
		t.Fatal("distinct principals share identity")
	}
	d1, _ := a.Digest("context-input/v1", []byte("value"))
	d2, _ := b.Digest("context-input/v1", []byte("value"))
	d3, _ := a.Digest("mcp-result/v1", []byte("value"))
	if d1 == d2 || d1 == d3 {
		t.Fatal("key/domain separation missing")
	}
	a.Close()
	if _, e = a.Principal(p); e == nil {
		t.Fatal("closed key used")
	}
	if _, e = NewOperationMAC("same", account, "accounts", account); e == nil {
		t.Fatal("same purpose keys accepted")
	}
}

// A failed Begin names its closed step and still matches ErrUnavailable
// (installed journey runs stopped at an unnamed audit-begin).
func TestOperationAuditorNamesTheStepThatStopped(t *testing.T) {
	in := auditIntent()
	f := &operationFixture{lostCreate: true}
	s := OperationAuditor{Journal: f, Acknowledgements: f, Objects: f, Now: func() time.Time { return in.CreatedAt }}
	err := s.Begin(context.Background(), in)
	var step interface{ FixedStep() string }
	if !errors.Is(err, ErrUnavailable) || !errors.As(err, &step) || step.FixedStep() != "object" {
		t.Fatal("step", err)
	}
}
