package audit

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
)

// A positive joined certificate writer is already durable. The independent
// acknowledgement is unavailable, so no retry may acquire an unbounded number
// of decrypt/verification operations for that same original record.
type verificationBudgetFixture struct {
	OperationLifecycleJournal
	OperationLifecycleAcknowledgements
	OperationRetirementFinalizer
	OperationCleanupObjects
	OperationCleanupVerifier
	snapshot                                value.OperationLifecycleSnapshot
	claims, verifications, acknowledgements int
	claimError, verifyError                 bool
	purges                                  []string
	certificateClaims                       int
	claimHook                               func(context.Context) time.Time
	verifyHook                              func(context.Context)
}

func (f *verificationBudgetFixture) ReadOperationLifecycle(context.Context, string) (value.OperationLifecycleSnapshot, error) {
	return f.snapshot, nil
}
func (f *verificationBudgetFixture) VerifyOperationCertificate(ctx context.Context, _ value.OperationRetirement, _ value.Receipt) error {
	f.verifications++
	if f.verifyHook != nil {
		f.verifyHook(ctx)
	}
	if f.verifyError {
		return ErrUnavailable
	}
	return nil
}
func (f *verificationBudgetFixture) AcknowledgeOperationCertificate(context.Context, value.OperationRetirement, value.Receipt) error {
	f.acknowledgements++
	return ErrUnavailable
}

// The independently credentialed SQL facet implements this bounded pre-I/O
// claim. A lost claim response remains spent and cannot create a fresh budget.
func (f *verificationBudgetFixture) ClaimOperationCertificateVerification(ctx context.Context, _ value.OperationRetirement, _ value.Receipt) (time.Time, error) {
	if f.claims >= 2 {
		return time.Time{}, ErrUnavailable
	}
	f.claims++
	if f.claimError {
		return time.Time{}, ErrUnavailable
	}
	if f.claimHook != nil {
		return f.claimHook(ctx), nil
	}
	return time.Now().Add(time.Second), nil
}

func verificationFixture(t *testing.T) (*verificationBudgetFixture, OperationCleanup, string) {
	in := auditIntent()
	var e error
	in, e = BindOperationLifecycle(in, healthyPolicy(in))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := value.OperationRetirement{
		RootID: in.RootID, OperationID: in.ID, StoreID: in.RootID,
		InstallationID: in.RootID, IssuerEpoch: in.ID,
		PostmasterAt: now.Add(-time.Hour), DatabaseOID: 1,
		ObjectsDigest: artifact.Digest{1}, WritersDigest: artifact.Digest{2},
		PurgeFence: 1, PurgedAt: now, CertificateWriteUntil: now.Add(30 * time.Second),
		CertificatePurgeAt: now.Add(time.Minute), LiveRetireBy: now.Add(2 * time.Minute),
	}
	if !r.Valid() {
		t.Fatal("invalid fixture retirement")
	}
	receipt := receipt(in, "intent")
	receipt.Key = value.OperationAuditKey(in.RootID, in.ID, "deletion-certificate")
	c := value.OperationWriteCompletion{
		Protocol: value.OperationWriterProtocol, RootID: in.RootID, OperationID: in.ID,
		StoreID: in.RootID, Phase: "deletion-certificate", RecordDigest: OperationLifecycleDigest(r),
		Receipt: receipt, StoredAt: now, ClosedAt: now,
	}
	if !c.Valid(in.RootID, in.ID, in.RootID, "deletion-certificate", r.PurgedAt, r.CertificateWriteUntil) {
		t.Fatal("invalid fixture completion")
	}
	f := &verificationBudgetFixture{snapshot: value.OperationLifecycleSnapshot{Intent: in, Retirement: &r, CertificateStarted: true, CertificateWriter: &c}}
	service := OperationCleanup{Journal: f, Acknowledgements: f, Finalizer: f, Objects: f, Verifier: f}
	return f, service, in.ID
}

func TestOperationCertificateAcknowledgementFailureCannotRepeatUnboundedVerification(t *testing.T) {
	f, service, id := verificationFixture(t)
	for i := 0; i < 8; i++ {
		if e := service.Advance(context.Background(), id); e == nil {
			t.Fatal("unknown acknowledgement reported completion")
		}
	}
	if f.verifications != 2 || f.claims != 2 || f.acknowledgements != 2 {
		t.Fatalf("verification budget escaped: claims=%d provider_calls=%d acknowledgements=%d; expected two prepaid attempts", f.claims, f.verifications, f.acknowledgements)
	}
}

func TestOperationVerificationUnknownClaimAndProviderFailureRemainSpent(t *testing.T) {
	for _, mode := range []string{"unknown-claim", "provider-failure"} {
		t.Run(mode, func(t *testing.T) {
			f, s, id := verificationFixture(t)
			f.claimError = mode == "unknown-claim"
			f.verifyError = mode == "provider-failure"
			for i := 0; i < 8; i++ {
				if e := s.Advance(context.Background(), id); e != ErrUnavailable {
					t.Fatal(e)
				}
			}
			want := 2
			if f.claimError {
				want = 0
			}
			if f.claims != 2 || f.verifications != want || f.acknowledgements != 0 {
				t.Fatal("failed/unknown work refilled", f.claims, f.verifications, f.acknowledgements)
			}
		})
	}
}
func TestOperationVerificationPreservesDeadlineAndCancellationThroughProvider(t *testing.T) {
	for _, mode := range []string{"claim-wait", "claim-extension", "provider-wait", "provider-cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, s, id := verificationFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			switch mode {
			case "claim-wait":
				f.claimHook = func(c context.Context) time.Time { <-c.Done(); return time.Now().Add(time.Second) }
			case "claim-extension":
				f.claimHook = func(context.Context) time.Time { return time.Now().Add(time.Minute) }
			case "provider-wait":
				f.verifyHook = func(c context.Context) { <-c.Done() }
			case "provider-cancel":
				f.verifyHook = func(context.Context) { cancel() }
			}
			if e := s.Advance(ctx, id); e != ErrUnavailable {
				t.Fatal("expired/canceled verification succeeded", e)
			}
			if f.claims != 1 || f.acknowledgements != 0 {
				t.Fatal("provider result escaped original context", f.claims, f.acknowledgements)
			}
			if (mode == "claim-wait" || mode == "claim-extension") && f.verifications != 0 {
				t.Fatal("provider called without current permit")
			}
		})
	}
}

func (f *verificationBudgetFixture) BeginOperationPurge(_ context.Context, _ string, phase string) (value.OperationPurgeLease, error) {
	f.purges = append(f.purges, phase)
	return value.OperationPurgeLease{}, ErrUnavailable
}
func (f *verificationBudgetFixture) ClaimOperationCertificate(context.Context, value.OperationRetirement) (bool, error) {
	f.certificateClaims++
	return false, ErrUnavailable
}
func TestHistoricalUnacknowledgedCleanupCannotStartDoomedProviderWork(t *testing.T) {
	for _, phase := range []string{"before-original-purge", "before-certificate", "acknowledged"} {
		t.Run(phase, func(t *testing.T) {
			f, s, id := verificationFixture(t)
			in := f.snapshot.Intent
			in.Lifecycle = nil
			p := healthyPolicy(in)
			p.History = nil
			p.BackupReservedBytes = 0
			p.WALReservedBytes = 0
			bound, e := BindOperationLifecycle(in, p)
			if e != nil {
				t.Fatal(e)
			}
			f.snapshot.Intent = bound
			switch phase {
			case "before-original-purge":
				f.snapshot.Retirement = nil
				f.snapshot.CertificateWriter = nil
			case "before-certificate":
				f.snapshot.CertificateWriter = nil
			case "acknowledged":
				r := f.snapshot.CertificateWriter.Receipt
				f.snapshot.CertificateReceipt = &r
			}
			if e = s.Advance(context.Background(), id); e != ErrUnavailable {
				t.Fatal(e)
			}
			if f.certificateClaims != 0 || f.verifications != 0 || f.claims != 0 {
				t.Fatal("historical unsupported record started certificate work", f.certificateClaims, f.claims, f.verifications)
			}
			if phase == "acknowledged" {
				if len(f.purges) != 1 || f.purges[0] != "terminal" {
					t.Fatal("acknowledged historical terminal cleanup blocked", f.purges)
				}
			} else if len(f.purges) != 0 {
				t.Fatal("unsupported unacknowledged history purged originals", f.purges)
			}
		})
	}
}
