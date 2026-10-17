package evidence

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Synthetic current human/worker proof and ledger for the in-process lifetime
// only. These fixtures do not qualify runtime identity, SQL or a native relay.
type downloadResultFixture struct {
	observationEntered, observationRelease chan struct{}
	shortenAfterAck                        bool
	lostBeginReply, lostAckReply           bool
	nativeExpectationDigest                artifact.Digest
	*downloadWorkerFixture
	mu                       sync.Mutex
	identity                 identity.Identity
	enrollment               value.WorkerEnrollment
	proofFailure             bool
	proofChange              func(*value.WorkerEnrollmentProof)
	acknowledged             bool
	expireAfterAck           bool
	changeAfterAck           string
	observeChange            func()
	nativeEntered            chan struct{}
	nativeRelease            chan struct{}
	ignoreNativeCancellation bool
}
type noLegacyDownloadAuthority struct{}

func (noLegacyDownloadAuthority) CheckDownload(context.Context, string, artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	panic("current identity path synthesized a bearer credential")
}
func (f *downloadResultFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.identity
	i.Groups = slices.Clone(i.Groups)
	i.Scopes = slices.Clone(i.Scopes)
	return i, nil
}
func (f *downloadResultFixture) CheckDownloadCurrent(_ context.Context, _ identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if scope != f.a.Scope {
		return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
	}
	return f.a, f.step("current-authority")
}
func (f *downloadResultFixture) ReadWorkerEnrollmentProof(_ context.Context, session, worker string, key artifact.Digest) (value.WorkerEnrollmentProof, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := value.WorkerEnrollmentProof{Worker: f.enrollment.Worker, PublicKeyDigest: f.enrollment.PublicKeyDigest, TokenDigest: artifact.Digest{1}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}
	if f.proofChange != nil {
		f.proofChange(&p)
	}
	if f.proofFailure || session != f.enrollment.Worker.Intent.SessionID || worker != f.enrollment.Worker.Intent.ID || key != f.enrollment.PublicKeyDigest {
		return value.WorkerEnrollmentProof{}, artifact.ErrDownloadUnavailable
	}
	return p, nil
}

type blockResultObservation struct{}

func (f *downloadResultFixture) ObserveDownload(ctx context.Context, id string, a artifact.DownloadAuthority, p *artifact.DownloadPreparation) (artifact.DownloadObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.observeChange != nil {
		f.observeChange()
	}
	if id != f.s.ID || a.Scope != f.s.Scope || !a.Valid(f.now) {
		return artifact.DownloadObservation{}, artifact.ErrDownloadUnavailable
	}
	if p != nil && (!f.acknowledged || !f.o.Success || p.SessionID != id || p.BatchID != f.i.Batch.ID || p.Generation != f.i.Batch.Generation) {
		return artifact.DownloadObservation{}, artifact.ErrDownloadUnavailable
	}
	s := f.s
	s.State = s.ObservedState(f.now)
	out := artifact.DownloadObservation{Session: s, ObservedAt: f.now, ValidUntil: identity.Earlier(f.now.Add(5*time.Second), a.ValidUntil)}
	if block, _ := ctx.Value(blockResultObservation{}).(bool); block {
		f.mu.Unlock()
		close(f.observationEntered)
		select {
		case <-f.observationRelease:
		case <-ctx.Done():
		}
		f.mu.Lock()
	}
	return out, nil
}
func (f *downloadResultFixture) LookupDownloadKey(context.Context, artifact.DownloadKeyQuery) (artifact.DownloadKeyLookup, error) {
	panic("unused")
}
func (f *downloadResultFixture) BeginDownloadBatch(c context.Context, id string, a artifact.DownloadAuthority, b artifact.DownloadBatch) (audit.DownloadIntent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out, err := f.downloadWorkerFixture.BeginDownloadBatch(c, id, a, b)
	if err == nil && f.lostBeginReply {
		return audit.DownloadIntent{}, artifact.ErrDownloadUnavailable
	}
	return out, err
}
func (f *downloadResultFixture) PermitDownloadBatch(c context.Context, id string, a artifact.DownloadAuthority, b string, g int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.downloadWorkerFixture.PermitDownloadBatch(c, id, a, b, g)
}
func (f *downloadResultFixture) PermitDownloadMetadata(c context.Context, id string, a artifact.DownloadAuthority, b string, g int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c.Err() != nil || !a.Valid(f.now) || !f.now.Before(f.i.Batch.LeaseUntil) {
		return artifact.ErrDownloadExpired
	}
	return f.downloadWorkerFixture.PermitDownloadMetadata(c, id, a, b, g)
}
func (f *downloadResultFixture) FinishDownloadBatch(c context.Context, id, b string, g, n int64, success, full bool) (audit.DownloadOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.downloadWorkerFixture.FinishDownloadBatch(c, id, b, g, n, success, full)
}
func (f *downloadResultFixture) WriteDownloadIntent(c context.Context, i audit.DownloadIntent) (audit.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.downloadWorkerFixture.WriteDownloadIntent(c, i)
}
func (f *downloadResultFixture) WriteDownloadOutcome(c context.Context, o audit.DownloadOutcome) (audit.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.downloadWorkerFixture.WriteDownloadOutcome(c, o)
}
func (f *downloadResultFixture) AcknowledgeDownloadIntent(c context.Context, i audit.DownloadIntent, r audit.Receipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.downloadWorkerFixture.AcknowledgeDownloadIntent(c, i, r)
}
func (f *downloadResultFixture) AcknowledgeDownloadOutcome(c context.Context, o audit.DownloadOutcome, r audit.Receipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err := f.downloadWorkerFixture.AcknowledgeDownloadOutcome(c, o, r)
	if err == nil {
		f.acknowledged = true
	}
	if err == nil && f.lostAckReply {
		return artifact.ErrDownloadUnavailable
	}
	if f.shortenAfterAck {
		f.a.AccessUntil = f.now.Add(time.Second)
		f.a.ValidUntil = f.a.AccessUntil
		f.a.DeleteBy = f.now.Add(30 * time.Second)
	}
	if f.expireAfterAck {
		f.now = f.now.Add(6 * time.Second)
	}
	switch f.changeAfterAck {
	case "groups":
		f.identity.Groups = []string{"changed"}
	case "scopes":
		f.identity.Scopes = []string{"evidence:read"}
	case "policy":
		f.identity.Policy.Generation++
	}
	return err
}
func (f *downloadResultFixture) ReadContext(c context.Context, e artifact.ContextExpectation, copies artifact.Copies, until time.Time) ([]byte, error) {
	f.mu.Lock()
	f.nativeExpectationDigest = ContextExpectationDigest(e)
	b, err := f.downloadWorkerFixture.ReadContext(c, e, copies, until)
	f.mu.Unlock()
	if f.nativeEntered != nil {
		close(f.nativeEntered)
	}
	if f.nativeRelease != nil {
		if f.ignoreNativeCancellation {
			<-f.nativeRelease
		} else {
			select {
			case <-f.nativeRelease:
			case <-c.Done():
				return b, c.Err()
			}
		}
	}
	return b, err
}
func (f *downloadResultFixture) refresh(at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = at
	until := at.Add(5 * time.Second)
	f.identity.VerifiedAt = at
	f.identity.ValidUntil = until
	f.a.CheckedAt = at
	f.a.ValidUntil = until
	f.a.Environment.ObservedAt = at
	f.a.Environment.ValidUntil = until
	f.a.Retention.ObservedAt = at
	f.a.Retention.ValidUntil = until
}
func (f *downloadResultFixture) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == name {
			n++
		}
	}
	return n
}
func newDownloadResultFixture(t *testing.T) (*downloadResultFixture, ContextDownloadResultConfig, *ContextDownloadResultOwner) {
	t.Helper()
	base, w, _ := downloadWorkerTest(t)
	cf, _ := newDownloadControlFixture(t)
	base.now = cf.now
	base.a = cf.a
	base.s.Scope = cf.a.Scope
	base.s.CreatedAt = cf.now
	base.s.Deadline = cf.now.Add(time.Minute)
	f := &downloadResultFixture{downloadWorkerFixture: base, identity: cf.i}
	target := routeTestWorker(t, 1)
	base.a.Environment.InstallationID = target.Intent.Profile.InstallationID
	target.Intent.SessionID = base.s.ID
	target.Intent.Authority = base.a
	target.Intent.CreatedAt = base.now
	target.Intent.RunUntil = base.s.Deadline
	target.Binding.DownloadID = base.s.ID
	f.enrollment = value.WorkerEnrollment{Worker: target, PublicKeyDigest: artifact.Digest{42}, ClaimedAt: base.now}
	w.Sessions = f
	w.Audit = f
	w.AuditAcknowledgements = f
	w.Native = f
	w.Authority = noLegacyDownloadAuthority{}
	w.CurrentAuthority = f
	w.Now = func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
	r := ContextDownloadRequest{SessionID: base.s.ID, Scope: base.a.Scope, Expectation: cf.source.Expectation, Copies: cf.source.Copies}
	cfg := ContextDownloadResultConfig{Enrollment: f.enrollment, Worker: w, Proofs: f, Observations: f, Request: r}
	o, err := NewContextDownloadResultOwner(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		o.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := o.Wait(ctx); err != nil {
			t.Error(err)
		}
	})
	return f, cfg, o
}

func TestContextDownloadResultSurvivesExpiredFirstReplyWithoutAnotherRead(t *testing.T) {
	f, _, o := newDownloadResultFixture(t)
	f.expireAfterAck = true
	if err := o.Prepare(context.Background(), f); err == nil {
		t.Fatal("expired first response succeeded")
	}
	if !f.acknowledged || f.s.State != artifact.DownloadReady {
		t.Fatal("successful outcome not acknowledged")
	}
	if !bytes.Equal(f.nativeBacking, make([]byte, len(f.nativeBacking))) {
		t.Fatal("native bytes retained")
	}
	f.refresh(f.now)
	out, err := o.Read(context.Background(), f)
	if err != nil || out.Prepared.Native.Size != int64(len(f.body)) || out.Prepared.Preparation.BatchID != f.i.Batch.ID || !out.ValidUntil.After(f.now) {
		t.Fatal(out, err)
	}
	if err = o.Prepare(context.Background(), f); err != nil {
		t.Fatal("same original preparation did not recover", err)
	}
	if f.count("native") != 1 || f.count("begin") != 1 || f.s.Requests != 1 {
		t.Fatal("recovery repeated paid preparation", f.calls)
	}
}
func TestContextDownloadResultUnknownOutcomeCannotRepeatOrDisclose(t *testing.T) {
	for _, stage := range []string{"begin", "finish", "outcome", "outcome-ack"} {
		t.Run(stage, func(t *testing.T) {
			f, _, o := newDownloadResultFixture(t)
			f.failure = stage
			if err := o.Prepare(context.Background(), f); err == nil {
				t.Fatal("uncertain effect succeeded")
			}
			f.failure = ""
			if _, err := o.Read(context.Background(), f); err == nil {
				t.Fatal("unacknowledged result readable")
			}
			if err := o.Prepare(context.Background(), f); !errors.Is(err, ErrDownloadMetadataUnavailable) {
				t.Fatal("uncertain preparation automatically retried", err)
			}
			if f.count("begin") != 1 || f.count("native") > 1 {
				t.Fatal(f.calls)
			}
		})
	}
}
func TestContextDownloadResultRestartDoesNotReprepareSpentSession(t *testing.T) {
	f, cfg, o := newDownloadResultFixture(t)
	if err := o.Prepare(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	o.Close()
	if err := o.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	replacement, err := NewContextDownloadResultOwner(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err = replacement.Prepare(context.Background(), f); !errors.Is(err, ErrDownloadMetadataUnavailable) {
		t.Fatal("lost private result caused another read", err)
	}
	if f.count("begin") != 1 || f.count("native") != 1 {
		t.Fatal(f.calls)
	}
}
func TestContextDownloadResultRequiresExactWorkerAndHistoricalReceipt(t *testing.T) {
	for _, which := range []string{"worker", "key", "version", "batch", "generation", "ack", "worker-unavailable"} {
		t.Run(which, func(t *testing.T) {
			f, _, o := newDownloadResultFixture(t)
			if err := o.Prepare(context.Background(), f); err != nil {
				t.Fatal(err)
			}
			switch which {
			case "worker":
				f.proofChange = func(p *value.WorkerEnrollmentProof) { p.Worker.Binding.PodUID = "33333333-3333-4333-8333-333333333333" }
			case "key":
				f.proofChange = func(p *value.WorkerEnrollmentProof) { p.PublicKeyDigest[0]++ }
			case "version":
				f.s.Scope.Version[0]++
			case "batch":
				f.i.Batch.ID = "33333333-3333-4333-8333-333333333333"
			case "generation":
				f.i.Batch.Generation++
			case "ack":
				f.acknowledged = false
			case "worker-unavailable":
				f.proofFailure = true
			}
			if _, err := o.Read(context.Background(), f); err == nil {
				t.Fatal("changed provenance disclosed result")
			}
			if f.count("native") != 1 {
				t.Fatal("status read decrypted again")
			}
		})
	}
}
func TestContextDownloadResultCurrentIdentityChangesDenyFirstResponse(t *testing.T) {
	for _, which := range []string{"groups", "scopes", "policy"} {
		t.Run(which, func(t *testing.T) {
			f, _, o := newDownloadResultFixture(t)
			f.changeAfterAck = which
			if err := o.Prepare(context.Background(), f); err == nil {
				t.Fatal("identity changed before response")
			}
			if f.count("native") != 1 || !f.acknowledged {
				t.Fatal("wrong accounting")
			}
		})
	}
}
func TestContextDownloadResultConcurrentPreparationHasOneNativeRead(t *testing.T) {
	f, _, o := newDownloadResultFixture(t)
	f.nativeEntered = make(chan struct{})
	f.nativeRelease = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- o.Prepare(context.Background(), f) }()
	select {
	case <-f.nativeEntered:
	case <-time.After(time.Second):
		t.Fatal("native read did not begin")
	}
	err := o.Prepare(context.Background(), f)
	close(f.nativeRelease)
	first := <-done
	if !errors.Is(err, artifact.ErrDownloadConflict) || first != nil {
		t.Fatal(err, first)
	}
	if f.count("native") != 1 || f.count("begin") != 1 {
		t.Fatal(f.calls)
	}
}
func TestContextDownloadResultCloseJoinsWorkAndForbidsLateRetention(t *testing.T) {
	f, _, o := newDownloadResultFixture(t)
	f.nativeEntered = make(chan struct{})
	f.nativeRelease = make(chan struct{})
	f.ignoreNativeCancellation = true
	done := make(chan error, 1)
	go func() { done <- o.Prepare(context.Background(), f) }()
	select {
	case <-f.nativeEntered:
	case <-time.After(time.Second):
		t.Fatal("native read did not begin")
	}
	o.Close()
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := o.Wait(wait)
	cancel()
	close(f.nativeRelease)
	result := <-done
	if !errors.Is(err, context.DeadlineExceeded) || result == nil {
		t.Fatal("closing released in-flight work", err, result)
	}
	if err = o.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = o.Read(context.Background(), f); err == nil {
		t.Fatal("closed result disclosed")
	}
	if f.s.ChargedRead != ContextDownloadReadWork || f.s.Requests != 1 {
		t.Fatal("cancellation refunded uncertain read")
	}
}
func TestContextDownloadResultCurrentRetentionAndResponseBounds(t *testing.T) {
	f, _, o := newDownloadResultFixture(t)
	if err := o.Prepare(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	f.a.AccessUntil = f.now.Add(2 * time.Second)
	f.a.ValidUntil = f.a.AccessUntil
	f.a.DeleteBy = f.now.Add(30 * time.Second)
	out, err := o.Read(context.Background(), f)
	if err != nil || out.Prepared.Native.ReadUntil != f.a.AccessUntil || out.Prepared.Native.DeleteBy != f.a.DeleteBy || out.ValidUntil.After(f.a.ValidUntil) {
		t.Fatal(out, err)
	}
	f.refresh(f.now.Add(3 * time.Second))
	if _, err = o.Read(context.Background(), f); err == nil {
		t.Fatal("shortened retention renewed result")
	}
}
func TestContextDownloadResultObservationCannotRenewAfterBlockingRead(t *testing.T) {
	f, _, o := newDownloadResultFixture(t)
	if err := o.Prepare(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	f.observeChange = func() { f.now = f.now.Add(6 * time.Second) }
	if _, err := o.Read(context.Background(), f); err == nil {
		t.Fatal("blocked observation renewed original authority")
	}
}
func TestContextDownloadPrepareCurrentUsesNoBearerAdapter(t *testing.T) {
	f, cfg, _ := newDownloadResultFixture(t)
	out, err := cfg.Worker.PrepareCurrent(context.Background(), f, cfg.Request)
	if err != nil || out.Size != int64(len(f.body)) {
		t.Fatal(out, err)
	}
	if f.count("current-authority") < 1 || f.count("native") != 1 {
		t.Fatal(f.calls)
	}
}

func TestContextDownloadResultLostCommitReplyNeverRepeatsRead(t *testing.T) {
	for _, stage := range []string{"begin", "outcome-ack"} {
		t.Run(stage, func(t *testing.T) {
			f, _, o := newDownloadResultFixture(t)
			if stage == "begin" {
				f.lostBeginReply = true
			} else {
				f.lostAckReply = true
			}
			if err := o.Prepare(context.Background(), f); err == nil {
				t.Fatal("lost reply reported success")
			}
			f.lostBeginReply = false
			f.lostAckReply = false
			if f.s.Generation != 1 || f.s.Requests != 1 {
				t.Fatal("fixture did not commit original batch")
			}
			if stage == "outcome-ack" && (!f.acknowledged || f.s.State != artifact.DownloadReady) {
				t.Fatal("fixture did not commit acknowledgement")
			}
			if _, err := o.Read(context.Background(), f); err == nil {
				t.Fatal("unknown acknowledgement exposed result")
			}
			if err := o.Prepare(context.Background(), f); !errors.Is(err, ErrDownloadMetadataUnavailable) {
				t.Fatal("unknown commit caused another attempt", err)
			}
			if f.count("begin") != 1 || f.count("native") > 1 {
				t.Fatal(f.calls)
			}
		})
	}
}
func TestContextDownloadResultSnapshotsSourceAndReturnedMetadata(t *testing.T) {
	f, cfg, o := newDownloadResultFixture(t)
	digest := ContextExpectationDigest(cfg.Request.Expectation)
	cfg.Request.Expectation.Audience[0].AssignmentID = "33333333-3333-4333-8333-333333333333"
	cfg.Request.Expectation.RetentionRules[0].Generation++
	if err := o.Prepare(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if f.nativeExpectationDigest != digest {
		t.Fatal("caller retargeted source after construction")
	}
	first, err := o.Read(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	first.Prepared.Native.Filename = "changed.json"
	first.Prepared.Scope.Version[0]++
	next, err := o.Read(context.Background(), f)
	if err != nil || next.Prepared.Native.Filename == "changed.json" || next.Prepared.Scope.Version != f.a.Scope.Version {
		t.Fatal("returned value changed cached facts", err)
	}
}
func TestContextDownloadResultFinalIdentityCheckAndShortenedDeadline(t *testing.T) {
	for _, change := range []string{"groups", "deadline"} {
		t.Run(change, func(t *testing.T) {
			f, _, o := newDownloadResultFixture(t)
			if err := o.Prepare(context.Background(), f); err != nil {
				t.Fatal(err)
			}
			short := f.now.Add(time.Second)
			f.observeChange = func() {
				if change == "groups" {
					f.identity.Groups = []string{"new"}
				} else {
					f.identity.ValidUntil = short
				}
			}
			out, err := o.Read(context.Background(), f)
			if change == "groups" {
				if err == nil {
					t.Fatal("identity changed during SQL observation")
				}
			} else if err != nil || out.ValidUntil != short {
				t.Fatal("shorter final identity interval lost", out.ValidUntil, err)
			}
		})
	}
}
func TestContextDownloadResultRejectsUnboundComposition(t *testing.T) {
	f, cfg, _ := newDownloadResultFixture(t)
	for _, change := range []string{"current-authority", "proofs", "observations", "session", "version", "worker", "key"} {
		t.Run(change, func(t *testing.T) {
			bad := cfg
			switch change {
			case "current-authority":
				bad.Worker.CurrentAuthority = nil
			case "proofs":
				bad.Proofs = nil
			case "observations":
				bad.Observations = nil
			case "session":
				bad.Request.SessionID = "33333333-3333-4333-8333-333333333333"
			case "version":
				bad.Request.Scope.Version[0]++
			case "worker":
				bad.Enrollment.Worker.Intent.Authority.Scope.Principal.Subject = "other"
			case "key":
				bad.Enrollment.PublicKeyDigest = artifact.Digest{}
			}
			if o, err := NewContextDownloadResultOwner(context.Background(), bad); err == nil {
				o.Close()
				t.Fatal("unbound result owner constructed")
			}
		})
	}
	if f.count("begin") != 0 || f.count("native") != 0 {
		t.Fatal("constructor performed native work")
	}
}

type resultProofFunc func(context.Context, string, string, artifact.Digest) (value.WorkerEnrollmentProof, error)

func (f resultProofFunc) ReadWorkerEnrollmentProof(ctx context.Context, s, w string, k artifact.Digest) (value.WorkerEnrollmentProof, error) {
	return f(ctx, s, w, k)
}
func TestContextDownloadResultProofCannotRenewOriginalIdentityInterval(t *testing.T) {
	f, _, o := newDownloadResultFixture(t)
	original := f.identity.ValidUntil
	var proofDeadline time.Time
	o.config.Proofs = resultProofFunc(func(ctx context.Context, s, w string, k artifact.Digest) (value.WorkerEnrollmentProof, error) {
		proofDeadline, _ = ctx.Deadline()
		f.refresh(f.now.Add(6 * time.Second))
		return f.ReadWorkerEnrollmentProof(ctx, s, w, k)
	})
	if err := o.Prepare(context.Background(), f); err == nil {
		t.Fatal("proof blocking renewed original human observation")
	}
	if proofDeadline.IsZero() || proofDeadline.After(original) {
		t.Fatal("proof I/O was not bounded by original identity", proofDeadline, original)
	}
	if f.count("begin") != 0 || f.count("native") != 0 {
		t.Fatal("expired preflight began native work")
	}
}
func TestContextDownloadResultConcurrentShorteningCannotBeReversed(t *testing.T) {
	f, _, o := newDownloadResultFixture(t)
	if err := o.Prepare(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	f.a.AccessUntil = f.now.Add(20 * time.Second)
	f.a.DeleteBy = f.now.Add(30 * time.Second)
	f.observationEntered = make(chan struct{})
	f.observationRelease = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := o.Read(context.WithValue(context.Background(), blockResultObservation{}, true), f)
		done <- err
	}()
	select {
	case <-f.observationEntered:
	case <-time.After(time.Second):
		t.Fatal("metadata observation did not block")
	}
	f.mu.Lock()
	short := f.now.Add(10 * time.Second)
	f.a.AccessUntil = short
	f.mu.Unlock()
	if _, err := o.Read(context.Background(), f); err != nil {
		close(f.observationRelease)
		<-done
		t.Fatal(err)
	}
	// A later/current observation with a larger limit cannot renew the first
	// effective shortening retained by this process owner.
	f.mu.Lock()
	f.a.AccessUntil = f.now.Add(20 * time.Second)
	f.mu.Unlock()
	close(f.observationRelease)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	f.refresh(f.now.Add(12 * time.Second))
	if _, err := o.Read(context.Background(), f); err == nil {
		t.Fatal("overlapping status read reversed retention shortening")
	}
	if f.count("native") != 1 || f.count("begin") != 1 {
		t.Fatal(f.calls)
	}
}
func TestContextDownloadResultDeniedPreflightDoesNotConsumeAttempt(t *testing.T) {
	f, _, o := newDownloadResultFixture(t)
	f.proofFailure = true
	if err := o.Prepare(context.Background(), f); err == nil {
		t.Fatal("missing worker proof permitted preparation")
	}
	if f.count("begin") != 0 || f.count("native") != 0 {
		t.Fatal("preflight denial spent SQL work")
	}
	f.proofFailure = false
	if err := o.Prepare(context.Background(), f); err != nil {
		t.Fatal("denied preflight prevented original attempt", err)
	}
	if f.count("begin") != 1 || f.count("native") != 1 {
		t.Fatal(f.calls)
	}
}

func TestContextDownloadResultRetainsShorteningSeenBeforeFirstReply(t *testing.T) {
	f, _, o := newDownloadResultFixture(t)
	f.shortenAfterAck = true
	if err := o.Prepare(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	f.refresh(f.now.Add(2 * time.Second))
	if _, err := o.Read(context.Background(), f); err == nil {
		t.Fatal("expired managed access disclosed retained facts")
	}
	o.mu.Lock()
	retained := o.result != nil
	closed := o.closed
	o.mu.Unlock()
	if retained || !closed {
		t.Fatal("known first-reply retention shortening did not clear the owner")
	}
}
