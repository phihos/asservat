package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Explicit synthetic SQL/source/identity ports test the coordinator, not a
// production native worker or a generic artifact authorization implementation.
type responseTransferFixture struct {
	*downloadWorkerFixture
	r                                                          artifact.DownloadResponse
	w                                                          artifact.DownloadWindow
	wi                                                         audit.DownloadWindowIntent
	size                                                       int64
	chunks, batches, leases, begins, intents, outcomes, closed int
	checks                                                     int
	emitted                                                    int64
	active                                                     bool
	fail                                                       string
	badHash, unverified                                        bool
	advanceBetweenWindows                                      bool
	slowRead                                                   int  // chunk ordinal whose read outlasts its lease
	revokeAfterStart                                           bool // every identity/authority check after the response start refuses
	stopAfterFirstWindow                                       bool // explicit Stop once the first window is acknowledged
	principal                                                  *identity.Principal
	minWriteLease                                              time.Duration // least lease time left at any chunk write
	backing                                                    []byte
	windowWrite                                                time.Time
	format                                                     string
}
type responseTestBatch struct {
	f      *responseTransferFixture
	until  time.Time
	closed bool
}

func (b *responseTestBatch) ResolveIdentity(context.Context) (identity.Identity, error) {
	if b.closed {
		return identity.Identity{}, artifact.ErrDownloadExpired
	}
	p := b.f.s.Scope.Principal
	if b.f.principal != nil {
		p = *b.f.principal
	}
	return identity.Identity{Principal: p, Policy: b.f.a.IdentityRevision, VerifiedAt: b.f.now, ValidUntil: b.until, Scopes: []string{"evidence:read", "evidence:download"}}, nil
}
func (b *responseTestBatch) Close() {
	if !b.closed {
		b.closed = true
		b.f.active = false
	}
}
func (f *responseTransferFixture) BeginBatch(context.Context) (identities.IdentityBatch, error) {
	if f.active {
		return nil, identities.ErrReaderBusy
	}
	if f.fail == "identity" || f.revokeAfterStart && f.begins > 0 {
		return nil, artifact.ErrDownloadUnavailable
	}
	f.active = true
	f.batches++
	return &responseTestBatch{f: f, until: f.now.Add(5 * time.Second)}, nil
}
func (f *responseTransferFixture) Close() { f.closed++ }
func (f *responseTransferFixture) CheckDownloadCurrent(ctx context.Context, b identities.CurrentIdentity, s artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	i, e := b.ResolveIdentity(ctx)
	if e != nil {
		return artifact.DownloadAuthority{}, e
	}
	f.checks++
	a := f.a
	a.CheckedAt = f.now
	a.ValidUntil = identity.Earlier(i.ValidUntil, a.AccessUntil)
	if f.fail == "authority" || f.revokeAfterStart && f.begins > 0 {
		return a, artifact.ErrDownloadUnavailable
	}
	return a, nil
}
func (f *responseTransferFixture) BeginDownloadResponse(_ context.Context, _ string, a artifact.DownloadAuthority, r artifact.DownloadResponse) (artifact.DownloadResponse, error) {
	f.begins++
	var e error
	f.s, f.r, e = f.s.BeginResponse(a, r, f.now)
	return f.r, e
}
func (f *responseTransferFixture) BeginDownloadWindow(_ context.Context, _, _, _, id string, a artifact.DownloadAuthority) (audit.DownloadWindowIntent, error) {
	var e error
	writeUntil := f.s.Deadline.Add(time.Minute)
	if !f.windowWrite.IsZero() {
		writeUntil = f.windowWrite
	}
	f.s, f.r, f.w, e = f.r.BeginWindow(f.s, a, id, f.s.ID, writeUntil, f.now)
	f.wi = audit.DownloadWindowIntent{Response: f.r, Window: f.w}
	return f.wi, e
}
func (f *responseTransferFixture) LeaseDownloadResponse(_ context.Context, _, _, _, _ string, a artifact.DownloadAuthority) (artifact.DownloadDeliveryLease, error) {
	f.leases++
	var l artifact.DownloadDeliveryLease
	var e error
	f.r, l, e = f.r.Lease(f.s, f.w, a, f.r.OwnerID, f.now)
	return l, e
}
func (f *responseTransferFixture) FinishDownloadWindow(_ context.Context, i audit.DownloadWindowIntent, o artifact.DownloadWindowOutcome) (audit.DownloadWindowAuditOutcome, error) {
	var e error
	f.s, f.r, f.w, e = f.r.RecordWindow(f.s, f.w, o, f.now)
	if e != nil {
		return audit.DownloadWindowAuditOutcome{}, e
	}
	return audit.DownloadWindowAuditOutcome{Intent: i, Outcome: *f.w.Outcome}, nil
}
func (f *responseTransferFixture) CloseDownloadResponse(context.Context, string, string, string) error {
	f.r.Closed = true
	return nil
}
func (f *responseTransferFixture) windowReceipt(i audit.DownloadWindowIntent, phase string) audit.DownloadWindowWriteResult {
	return audit.DownloadWindowWriteResult{Receipt: audit.Receipt{Key: audit.DownloadWindowAuditKey(f.s.Scope.RootID, i.Response.ID, i.Window.ID, phase), Version: "synthetic-original-version", ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{3}}}
}
func (f *responseTransferFixture) CreateDownloadWindowIntent(_ context.Context, i audit.DownloadWindowIntent) (audit.DownloadWindowWriteResult, error) {
	f.intents++
	if f.fail == "intent" {
		return audit.DownloadWindowWriteResult{}, artifact.ErrDownloadUnavailable
	}
	return f.windowReceipt(i, "intent"), nil
}
func (f *responseTransferFixture) FindDownloadWindowIntent(context.Context, audit.DownloadWindowIntent) (audit.Receipt, error) {
	panic("no automatic intent replay")
}
func (f *responseTransferFixture) CreateDownloadWindowOutcome(_ context.Context, o audit.DownloadWindowAuditOutcome) (audit.DownloadWindowWriteResult, error) {
	f.outcomes++
	if f.fail == "outcome" {
		return audit.DownloadWindowWriteResult{}, artifact.ErrDownloadUnavailable
	}
	return f.windowReceipt(o.Intent, "outcome"), nil
}
func (f *responseTransferFixture) FindDownloadWindowOutcome(context.Context, audit.DownloadWindowAuditOutcome) (audit.Receipt, error) {
	panic("no automatic outcome replay")
}
func (f *responseTransferFixture) AcknowledgeDownloadWindowIntent(context.Context, audit.DownloadWindowIntent, audit.DownloadWindowWriteResult) error {
	if f.fail == "intent-ack" {
		return artifact.ErrDownloadUnavailable
	}
	f.w.IntentAcknowledged = true
	return nil
}
func (f *responseTransferFixture) AcknowledgeDownloadWindowOutcome(context.Context, audit.DownloadWindowAuditOutcome, audit.DownloadWindowWriteResult) error {
	if f.fail == "outcome-ack" {
		return artifact.ErrDownloadUnavailable
	}
	var e error
	f.s, f.r, f.w, e = f.r.AcknowledgeWindow(f.s, f.w, f.now)
	if f.stopAfterFirstWindow {
		f.s.State = artifact.DownloadCancelled
	}
	if f.advanceBetweenWindows && !f.r.Closed {
		f.now = f.now.Add(6 * time.Second)
	}
	return e
}
func syntheticResponseHash(size int64) artifact.Digest {
	h := sha256.New()
	b := make([]byte, artifact.DeliveryBytes)
	for at := int64(0); at < size; {
		n := min(int64(len(b)), size-at)
		h.Write(b[:n])
		at += n
	}
	return artifact.Digest(h.Sum(nil))
}
func (f *responseTransferFixture) Describe(context.Context, artifact.DownloadSession, artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error) {
	if f.fail == "source" {
		return artifact.NativeDownloadMetadata{}, 0, artifact.ErrDownloadUnavailable
	}
	sum := syntheticResponseHash(f.size)
	if f.badHash {
		sum[0]++
	}
	return artifact.NativeDownloadMetadata{Filename: "synthetic.core", Format: f.format, ETag: `"v1"`, Size: f.size, SHA256: sum, ReadUntil: f.a.AccessUntil, DeleteBy: f.a.DeleteBy}, artifact.DownloadWindowBytes, nil
}
func (f *responseTransferFixture) ReadChunk(_ context.Context, l artifact.DownloadDeliveryLease, offset, length int64) (NativeResponseChunk, error) {
	if !f.w.IntentAcknowledged || !l.Allows(offset, length, f.now) {
		return NativeResponseChunk{}, artifact.ErrDownloadExpired
	}
	if f.fail == "read" {
		return NativeResponseChunk{}, artifact.ErrDownloadUnavailable
	}
	f.backing = make([]byte, length)
	if f.slowRead > 0 && f.chunks+1 == f.slowRead {
		f.now = f.now.Add(6 * time.Second) // a frame load outlasted the lease
		f.slowRead = -1
	}
	return NativeResponseChunk{Bytes: f.backing, ReadWork: length, FinalVerified: offset+length == f.size && !f.unverified}, nil
}
func (f *responseTransferFixture) SelectDownloadResponse(m artifact.NativeDownloadMetadata) (artifact.DownloadSelection, error) {
	return artifact.DownloadSelection{Length: m.Size}, nil
}
func (f *responseTransferFixture) OpenDownloadResponse(context.Context, artifact.NativeDownloadMetadata, artifact.DownloadResponse) (DownloadResponseSink, error) {
	return f, nil
}
func (f *responseTransferFixture) WriteChunk(_ context.Context, l artifact.DownloadDeliveryLease, offset int64, b []byte) (int64, error) {
	if !l.Allows(offset, int64(len(b)), f.now) || !f.w.IntentAcknowledged || offset != f.emitted {
		return 0, artifact.ErrDownloadExpired
	}
	f.chunks++
	if left := l.Until.Sub(f.now); f.minWriteLease == 0 || left < f.minWriteLease {
		f.minWriteLease = left
	}
	if f.fail == "write" {
		f.emitted++
		return 1, artifact.ErrDownloadUnavailable
	}
	f.emitted += int64(len(b))
	return int64(len(b)), nil
}
func (f *responseTransferFixture) Finish(context.Context) error {
	if f.emitted != f.size {
		return artifact.ErrIntegrity
	}
	return nil
}
func newResponseTransferFixture(t *testing.T, size int64) (*responseTransferFixture, DownloadResponseTransfer, DownloadResponseRequest) {
	base, _, _ := downloadWorkerTest(t)
	base.s.State = artifact.DownloadReady
	base.s.OutputLimit = max(1, size)
	base.s.ReadLimit = 2 * artifact.DownloadWindowBytes
	base.s.Requests = 1
	f := &responseTransferFixture{downloadWorkerFixture: base, size: size}
	count := 0
	service := DownloadResponseTransfer{Sessions: f, Responses: f, Authority: f, Objects: f, Audit: f, Now: func() time.Time { return f.now }, NewID: func() string { count++; return fmt.Sprintf("22222222-2222-4222-8222-%012d", count) }}
	req := DownloadResponseRequest{SessionID: f.s.ID, ResponseID: f.s.ID, OwnerID: f.s.ID, HardUntil: f.s.Deadline}
	return f, service, req
}
func TestResponseTransferMultipleWindowsReuseLeaseAndFinishWholeFile(t *testing.T) {
	f, service, req := newResponseTransferFixture(t, artifact.DownloadWindowBytes+17)
	f.advanceBetweenWindows = true
	if e := service.Transfer(context.Background(), f, req, f, f); e != nil {
		t.Fatal(e)
	}
	// Two batches and two complete checks, all before the response starts;
	// the second window continues the started decision (ADR-312).
	if f.s.State != artifact.DownloadCompleted || f.emitted != f.size || f.chunks != 65 || f.intents != 2 || f.outcomes != 2 || f.leases != 2 || f.batches != 2 || f.checks != 2 || f.s.Requests != 1 || f.s.ChargedOutput != f.size {
		t.Fatalf("state=%s chunks=%d leases=%d batches=%d checks=%d intent=%d outcome=%d", f.s.State, f.chunks, f.leases, f.batches, f.checks, f.intents, f.outcomes)
	}
	for _, b := range f.backing {
		if b != 0 {
			t.Fatal("native buffer retained")
		}
	}
}

// ADR-244: a local source's read that outlasts its lease is written only under
// a renewed lease, which continues the started decision (ADR-312).
func TestResponseTransferRenewsLeaseAfterSlowLocalRead(t *testing.T) {
	f, service, req := newResponseTransferFixture(t, 3*artifact.DeliveryBytes)
	f.slowRead = 2
	if e := service.Transfer(context.Background(), f, req, f, f); e != nil {
		t.Fatal(e)
	}
	if f.s.State != artifact.DownloadCompleted || f.emitted != f.size || f.leases != 2 || f.batches != 2 || f.minWriteLease < localWriteMargin {
		t.Fatal("slow read not delivered under a renewed lease", f.s.State, f.emitted, f.leases, f.batches, f.minWriteLease)
	}
	// A renewal that cannot give the margin (the response's original end is
	// near) writes nothing; every earlier write started with at least the margin.
	f, service, req = newResponseTransferFixture(t, 3*artifact.DeliveryBytes)
	f.slowRead = 2
	req.HardUntil = f.now.Add(7 * time.Second)
	if e := service.Transfer(context.Background(), f, req, f, f); !errors.Is(e, artifact.ErrDownloadExpired) {
		t.Fatal("short renewal accepted", e)
	}
	if f.emitted != artifact.DeliveryBytes || f.minWriteLease < localWriteMargin {
		t.Fatal("chunk written with less than the margin", f.emitted, f.minWriteLease)
	}
	for _, b := range f.backing {
		if b != 0 {
			t.Fatal("refused chunk retained")
		}
	}
}

// ADR-312: once started, a response does not observe identity, permission or
// policy again. Revocation after the start (here: every later identity batch
// and complete check refuses) does not stop it.
func TestStartedResponseContinuesAfterPermissionChange(t *testing.T) {
	for _, slow := range []bool{false, true} {
		f, service, req := newResponseTransferFixture(t, 2*artifact.DownloadWindowBytes+17)
		f.advanceBetweenWindows, f.revokeAfterStart = true, true
		f.s.ReadLimit = 3 * artifact.DownloadWindowBytes
		if slow {
			f.slowRead = 2
		}
		if e := service.Transfer(context.Background(), f, req, f, f); e != nil {
			t.Fatal("started response stopped after a permission change", slow, e)
		}
		if f.s.State != artifact.DownloadCompleted || f.emitted != f.size || f.checks != 2 || f.batches != 2 || f.intents != 3 {
			t.Fatal("started response observed authority again", slow, f.s.State, f.emitted, f.checks, f.batches, f.intents)
		}
	}
}

// ADR-312: a started response still ends at each original bound and at Stop.
func TestStartedResponseStopsAtOriginalBounds(t *testing.T) {
	for _, bound := range []string{"retention", "credential", "session", "stop"} {
		t.Run(bound, func(t *testing.T) {
			f, service, req := newResponseTransferFixture(t, 2*artifact.DownloadWindowBytes+17)
			f.advanceBetweenWindows = true
			f.s.ReadLimit = 3 * artifact.DownloadWindowBytes
			end := f.now.Add(8 * time.Second)
			switch bound {
			case "retention":
				f.a.AccessUntil = end
			case "credential":
				req.HardUntil = end
			case "session":
				f.s.Deadline = end
			case "stop":
				f.stopAfterFirstWindow = true
			}
			e := service.Transfer(context.Background(), f, req, f, f)
			if e == nil || f.s.State == artifact.DownloadCompleted {
				t.Fatal("started response outlived its original bound", e, f.s.State)
			}
			// Windows one and two (at +0 s and +6 s) are within the bound; the
			// third (+12 s) is not. Stop already refuses the second window.
			want := 2 * artifact.DownloadWindowBytes
			if bound == "stop" {
				want = artifact.DownloadWindowBytes
			}
			if f.emitted != want || f.intents != int(want/artifact.DownloadWindowBytes) {
				t.Fatal("bytes after the original bound", f.emitted, f.intents)
			}
		})
	}
}

// Every content request authenticates; a request whose authenticated caller is
// not the session's principal is refused before any accounting.
func TestResponseTransferRefusesDifferentPrincipal(t *testing.T) {
	f, service, req := newResponseTransferFixture(t, 17)
	other := f.s.Scope.Principal
	other.Subject = "someone-else"
	f.principal = &other
	if e := service.Transfer(context.Background(), f, req, f, f); e == nil || f.begins != 0 || f.emitted != 0 || f.s.ChargedOutput != 0 {
		t.Fatal("different principal admitted", e, f.begins, f.emitted)
	}
}

func TestResponseTransferFailureKeepsPrepaidSpendNoAutomaticRetry(t *testing.T) {
	for _, failure := range []string{"identity", "authority", "source", "intent", "intent-ack", "read", "write", "outcome", "outcome-ack"} {
		t.Run(failure, func(t *testing.T) {
			f, s, r := newResponseTransferFixture(t, 2)
			f.fail = failure
			if e := s.Transfer(context.Background(), f, r, f, f); e == nil {
				t.Fatal("failure succeeded")
			}
			if f.s.State == artifact.DownloadCompleted {
				t.Fatal("uncertain transfer completed")
			}
			preflight := failure == "identity" || failure == "authority" || failure == "source"
			if preflight && (f.begins != 0 || f.s.ChargedOutput != 0) {
				t.Fatal("preflight spent")
			}
			if !preflight && (f.s.ChargedOutput != 2 || f.intents != 1) {
				t.Fatal("uncertainty refunded/retried", f.intents, f.s.ChargedOutput)
			}
			if failure == "write" && f.s.EmittedBytes != 1 {
				t.Fatal("partial write missing from historical accounting")
			}
		})
	}
}
func TestResponseTransferVerifiesFinalBeforeLastBytes(t *testing.T) {
	for _, which := range []string{"hash", "range-proof"} {
		t.Run(which, func(t *testing.T) {
			f, s, r := newResponseTransferFixture(t, artifact.DeliveryBytes+5)
			f.badHash = which == "hash"
			f.unverified = which == "range-proof"
			if e := s.Transfer(context.Background(), f, r, f, f); e == nil {
				t.Fatal("bad integrity succeeded")
			}
			if f.emitted != artifact.DeliveryBytes || f.s.State == artifact.DownloadCompleted {
				t.Fatal("unverified last bytes emitted")
			}
		})
	}
}
func TestResponseTransferEmptyNativeStillHasOneAuditedWindow(t *testing.T) {
	f, s, r := newResponseTransferFixture(t, 0)
	if e := s.Transfer(context.Background(), f, r, f, f); e != nil {
		t.Fatal(e)
	}
	if f.s.State != artifact.DownloadCompleted || f.intents != 1 || f.outcomes != 1 || f.chunks != 1 {
		t.Fatal("empty response lacks bounded completion")
	}
}

// Installed native91: the window's audit deadline is its protected-capacity
// control's, about 24 h ahead; the content transfer must accept it, and a
// refused window names its stage for the operator report.
func TestResponseTransferAcceptsCapacityControlWindowDeadline(t *testing.T) {
	f, s, r := newResponseTransferFixture(t, 2)
	f.windowWrite = f.now.Add(24*time.Hour + 30*time.Second)
	if e := s.Transfer(context.Background(), f, r, f, f); e != nil || f.s.State != artifact.DownloadCompleted {
		t.Fatal("capacity control window deadline refused the transfer", e)
	}
	f, s, r = newResponseTransferFixture(t, 2)
	f.windowWrite = f.now.Add(artifact.MaxDownloadWindowWrite + time.Second)
	e := s.Transfer(context.Background(), f, r, f, f)
	var fixed interface{ FixedStep() string }
	if !errors.Is(e, artifact.ErrInvalid) || !errors.As(e, &fixed) || fixed.FixedStep() != "window" {
		t.Fatal("refused window did not name its stage", e)
	}
}

func TestResponseTransferRawFormatsReserveEveryWindow(t *testing.T) {
	for _, format := range []string{artifact.RawPCAPNGFormat, artifact.SyscallArgumentsFormat, artifact.PprofFormat, artifact.GoTraceFormat} {
		t.Run(format, func(t *testing.T) {
			f, service, req := newResponseTransferFixture(t, artifact.DownloadWindowBytes+17)
			f.format = format
			probe := &rawUseProbe{steps: &f.calls}
			service.RawResults = probe
			if err := service.Transfer(context.Background(), f, req, f, f); err != nil {
				t.Fatal(err)
			}
			var bytes int64
			for _, use := range probe.uses {
				bytes += use.Bytes
				if use.Operation != "download_artifact" || use.Operations != 0 {
					t.Fatal(use)
				}
			}
			if len(probe.uses) != 2 || bytes != f.size || probe.ids[0] == probe.ids[1] {
				t.Fatal("raw windows not charged", probe.uses, probe.ids)
			}
			f, service, req = newResponseTransferFixture(t, 17)
			f.format = format
			probe = &rawUseProbe{steps: &f.calls, err: artifact.ErrDownloadUnavailable}
			service.RawResults = probe
			if err := service.Transfer(context.Background(), f, req, f, f); err == nil || f.chunks != 0 || f.emitted != 0 {
				t.Fatal("refused raw budget read bytes", f.chunks, f.emitted, err)
			}
			f, service, req = newResponseTransferFixture(t, 17)
			f.format = format
			if err := service.Transfer(context.Background(), f, req, f, f); err == nil || f.chunks != 0 {
				t.Fatal("missing raw budget admitted", err)
			}
		})
	}
}

func TestResponseTransferApprovedFormatsNeedNoRawPool(t *testing.T) {
	for _, format := range []string{artifact.ContextFormat, artifact.PCAPNGFormat, artifact.SyscallRecordsFormat, artifact.HTTPHeadersFormat} {
		t.Run(format, func(t *testing.T) {
			f, service, req := newResponseTransferFixture(t, 17)
			f.format = format
			if err := service.Transfer(context.Background(), f, req, f, f); err != nil || f.emitted != 17 {
				t.Fatal(f.emitted, err)
			}
		})
	}
}
