package evidence

import (
	"context"
	"crypto/sha256"
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

// Explicit synthetic providers/SQL for request propagation only. The actual
// browser CurrentIdentity implementation is used, with no provider token exposed.
type workerLifecycleFixture struct {
	DownloadWorkerLedger
	WorkerEnrollmentLedger
	WorkerCertificateActivator
	mu                                sync.Mutex
	now                               time.Time
	i                                 identity.Identity
	a                                 artifact.DownloadAuthority
	w                                 value.DownloadWorker
	calls                             []string
	deadlines                         map[string]time.Time
	hooks                             map[string]func()
	created, acknowledged, lostCreate bool
	enrollment                        value.WorkerEnrollment
	attempt                           value.WorkerCertificateAttempt
	certificate                       value.WorkerCertificate
}

type workerLifecycleJobs struct{ f *workerLifecycleFixture }

func (s workerLifecycleJobs) CreateDownloadWorker(c context.Context, l value.DownloadWorkerLaunch) (value.DownloadWorkerJob, error) {
	return s.f.CreateDownloadWorker(c, l)
}
func (s workerLifecycleJobs) FindDownloadWorkerJob(c context.Context, i value.DownloadWorkerIntent) (value.DownloadWorkerJob, error) {
	return s.f.FindDownloadWorkerJob(c, i)
}
func (s workerLifecycleJobs) ObserveDownloadWorker(c context.Context, i value.DownloadWorkerIntent, j value.DownloadWorkerJob) (value.DownloadWorker, error) {
	return s.f.ObserveDownloadWorker(c, i, j)
}
func (workerLifecycleJobs) ObserveDownloadWorkerTermination(context.Context, value.DownloadWorker) (value.DownloadWorkerTermination, error) {
	panic("unexpected retirement")
}
func (workerLifecycleJobs) RetireDownloadWorker(context.Context, value.DownloadWorkerTermination) (value.DownloadWorkerRetirement, error) {
	panic("unexpected retirement")
}

func (f *workerLifecycleFixture) Now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
func (f *workerLifecycleFixture) step(ctx context.Context, name string) error {
	f.mu.Lock()
	f.calls = append(f.calls, name)
	if d, ok := ctx.Deadline(); ok {
		f.deadlines[name] = d
	}
	hook := f.hooks[name]
	delete(f.hooks, name)
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return ctx.Err()
}
func (f *workerLifecycleFixture) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.calls {
		if v == name {
			n++
		}
	}
	return n
}
func (f *workerLifecycleFixture) change(fn func()) { f.mu.Lock(); defer f.mu.Unlock(); fn() }
func (f *workerLifecycleFixture) Resolve(ctx context.Context, cookie string, refresh bool) (identities.SessionView, error) {
	if cookie != "synthetic-session-cookie" || refresh || ctx.Err() != nil {
		return identities.SessionView{}, identity.ErrDenied
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.i
	i.Groups = slices.Clone(i.Groups)
	i.Scopes = slices.Clone(i.Scopes)
	i.VerifiedAt = f.now
	i.ValidUntil = identity.Earlier(i.ValidUntil, f.now.Add(5*time.Second))
	return identities.SessionView{Identity: i, ExpiresAt: f.w.Intent.RunUntil}, nil
}
func (f *workerLifecycleFixture) CheckDownloadCurrent(ctx context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	if e := f.step(ctx, "authority"); e != nil {
		return artifact.DownloadAuthority{}, e
	}
	i, e := current.ResolveIdentity(ctx)
	if e != nil {
		return artifact.DownloadAuthority{}, e
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if i.Principal != scope.Principal || scope != f.a.Scope {
		return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
	}
	a := f.a
	a.CheckedAt = f.now
	a.ValidUntil = identity.Earlier(a.ValidUntil, f.now.Add(5*time.Second))
	a.Environment.ObservedAt = f.now
	a.Environment.ValidUntil = a.ValidUntil
	a.Retention.ObservedAt = f.now
	a.Retention.ValidUntil = a.ValidUntil
	return a, nil
}
func (f *workerLifecycleFixture) CheckDownload(context.Context, string, artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	panic("typed lifecycle used a bearer credential")
}
func workerReceipt(key string) audit.Receipt {
	return audit.Receipt{Key: key, Version: "synthetic-original-version", ETag: "synthetic", Bytes: 1, SHA256: artifact.Digest{1}}
}
func (f *workerLifecycleFixture) ReserveDownloadWorker(ctx context.Context, session, id string, a artifact.DownloadAuthority, p value.DownloadWorkerProfile) (value.DownloadWorkerIntent, error) {
	if err := f.step(ctx, "reserve-worker"); err != nil {
		return value.DownloadWorkerIntent{}, err
	}
	if session != f.w.Intent.SessionID || id != f.w.Intent.ID || p != f.w.Intent.Profile || a.Scope != f.w.Intent.Authority.Scope {
		return value.DownloadWorkerIntent{}, artifact.ErrIntegrity
	}
	return f.w.Intent, nil
}
func (f *workerLifecycleFixture) ReadDownloadWorkerIntentReceipt(ctx context.Context, i value.DownloadWorkerIntent) (audit.Receipt, bool, error) {
	e := f.step(ctx, "read-worker-audit")
	return workerReceipt(audit.DownloadWorkerAuditKey(i)), f.acknowledged, e
}
func (f *workerLifecycleFixture) WriteDownloadWorkerIntent(ctx context.Context, i value.DownloadWorkerIntent) (audit.Receipt, error) {
	e := f.step(ctx, "write-worker-audit")
	return workerReceipt(audit.DownloadWorkerAuditKey(i)), e
}
func (f *workerLifecycleFixture) AcknowledgeDownloadWorkerIntent(ctx context.Context, _ value.DownloadWorkerIntent, _ audit.Receipt) error {
	e := f.step(ctx, "ack-worker-audit")
	if e == nil {
		f.acknowledged = true
	}
	return e
}
func (f *workerLifecycleFixture) ClaimDownloadWorker(ctx context.Context, i value.DownloadWorkerIntent, a artifact.DownloadAuthority) (value.DownloadWorkerLaunch, error) {
	e := f.step(ctx, "claim-worker")
	return value.DownloadWorkerLaunch{Intent: i, CheckedAt: f.Now(), MayCreate: !f.created, Until: a.ValidUntil}, e
}
func (f *workerLifecycleFixture) CreateDownloadWorker(ctx context.Context, _ value.DownloadWorkerLaunch) (value.DownloadWorkerJob, error) {
	e := f.step(ctx, "create-job")
	f.created = true
	if f.lostCreate {
		f.lostCreate = false
		return value.DownloadWorkerJob{}, artifact.ErrDownloadUnavailable
	}
	return f.w.Job, e
}
func (f *workerLifecycleFixture) FindDownloadWorkerJob(ctx context.Context, _ value.DownloadWorkerIntent) (value.DownloadWorkerJob, error) {
	e := f.step(ctx, "find-job")
	return f.w.Job, e
}
func (f *workerLifecycleFixture) RecordDownloadWorkerJob(ctx context.Context, _ value.DownloadWorkerIntent, _ value.DownloadWorkerJob) error {
	return f.step(ctx, "record-job")
}
func (f *workerLifecycleFixture) ObserveDownloadWorker(ctx context.Context, _ value.DownloadWorkerIntent, _ value.DownloadWorkerJob) (value.DownloadWorker, error) {
	e := f.step(ctx, "observe-job")
	return f.w, e
}
func (f *workerLifecycleFixture) BindDownloadWorker(ctx context.Context, _ value.DownloadWorker, _ artifact.DownloadAuthority) error {
	return f.step(ctx, "bind-worker")
}
func (f *workerLifecycleFixture) ReadDownloadWorker(ctx context.Context, _ string, _ artifact.DownloadAuthority) (value.DownloadWorker, error) {
	e := f.step(ctx, "read-worker")
	return f.w, e
}
func (f *workerLifecycleFixture) ReadDownloadWorkerEnrollment(ctx context.Context, session, worker string) (value.DownloadWorkerIdentity, error) {
	e := f.step(ctx, "read-enrollment")
	if session != f.w.Intent.SessionID || worker != f.w.Intent.ID {
		return value.DownloadWorkerIdentity{}, artifact.ErrInvalid
	}
	n := f.Now()
	return value.DownloadWorkerIdentity{Worker: f.w, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, e
}
func (f *workerLifecycleFixture) EnrollmentKey(csr []byte) (artifact.Digest, error) {
	return sha256.Sum256(csr), nil
}
func (f *workerLifecycleFixture) ReadWorkerEnrollmentProof(ctx context.Context, session, worker string, key artifact.Digest) (value.WorkerEnrollmentProof, error) {
	e := f.step(ctx, "proof")
	n := f.Now()
	if session != f.w.Intent.SessionID || worker != f.w.Intent.ID {
		return value.WorkerEnrollmentProof{}, artifact.ErrInvalid
	}
	return value.WorkerEnrollmentProof{Worker: f.w, PublicKeyDigest: key, TokenDigest: artifact.Digest{1}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, e
}
func (f *workerLifecycleFixture) ClaimWorkerEnrollment(ctx context.Context, p value.WorkerEnrollmentProof) (value.WorkerEnrollment, audit.Receipt, bool, error) {
	e := f.step(ctx, "claim-enrollment")
	if f.enrollment.PublicKeyDigest == (artifact.Digest{}) {
		f.enrollment = value.WorkerEnrollment{Worker: p.Worker, PublicKeyDigest: p.PublicKeyDigest, ClaimedAt: f.Now()}
	}
	return f.enrollment, audit.Receipt{}, false, e
}
func (f *workerLifecycleFixture) WriteWorkerEnrollment(ctx context.Context, e value.WorkerEnrollment) (audit.Receipt, error) {
	err := f.step(ctx, "write-enrollment-audit")
	return workerReceipt(audit.WorkerEnrollmentKey(e)), err
}
func (f *workerLifecycleFixture) AcknowledgeWorkerEnrollment(ctx context.Context, _ value.WorkerEnrollment, _ audit.Receipt) error {
	return f.step(ctx, "ack-enrollment-audit")
}
func (f *workerLifecycleFixture) PrepareWorkerCertificate(ctx context.Context, p value.WorkerEnrollmentProof) (value.WorkerCertificateProgress, error) {
	e := f.step(ctx, "prepare-certificate")
	n := f.Now()
	epoch, until, err := value.WorkerCertificateEpoch(f.w, n)
	if err != nil {
		return value.WorkerCertificateProgress{}, err
	}
	f.attempt = value.WorkerCertificateAttempt{ID: f.w.Intent.ID, Epoch: epoch, Ordinal: 1, Enrollment: f.enrollment, Proof: p, RecoveryEpoch: p.Worker.Intent.Authority.Environment.RecoveryEpoch, EnrollmentAudit: artifact.Digest{1}, CheckedAt: n, SignBefore: p.FreshUntil, CertificateNotAfter: until}
	return value.WorkerCertificateProgress{Attempt: f.attempt, MaySign: true}, e
}
func (f *workerLifecycleFixture) SignWorkerCertificate(ctx context.Context, a value.WorkerCertificateAttempt, _ []byte) (value.WorkerCertificate, error) {
	e := f.step(ctx, "sign")
	der := []byte("synthetic-certificate-not-a-real-provider")
	return value.WorkerCertificate{DER: der, ChainDER: [][]byte{}, Peer: value.KeyPeer{InstallationID: f.w.Binding.InstallationID, Role: "acquisition", PeerID: f.w.Binding.PodUID, Certificate: sha256.Sum256(der), NotBefore: f.Now().Add(-time.Second), NotAfter: a.CertificateNotAfter}}, e
}
func (f *workerLifecycleFixture) StoreWorkerCertificate(ctx context.Context, _ value.WorkerCertificateAttempt, c value.WorkerCertificate) error {
	e := f.step(ctx, "store-certificate")
	f.certificate = c
	return e
}
func (f *workerLifecycleFixture) ReadWorkerCertificateReceipt(ctx context.Context, _ audit.WorkerCertificate) (audit.Receipt, bool, error) {
	return audit.Receipt{}, false, f.step(ctx, "read-certificate-audit")
}
func (f *workerLifecycleFixture) WriteWorkerCertificate(ctx context.Context, c audit.WorkerCertificate) (audit.Receipt, error) {
	e := f.step(ctx, "write-certificate-audit")
	return workerReceipt(audit.WorkerCertificateKey(c)), e
}
func (f *workerLifecycleFixture) AcknowledgeWorkerCertificate(ctx context.Context, _ audit.WorkerCertificate, _ audit.Receipt) error {
	return f.step(ctx, "ack-certificate-audit")
}
func (f *workerLifecycleFixture) ActivateWorkerCertificate(ctx context.Context, _ value.WorkerEnrollmentProof, _ value.WorkerCertificateAttempt) (value.WorkerCertificate, error) {
	return f.certificate, f.step(ctx, "activate")
}
func newWorkerLifecycleFixture(t *testing.T) (*workerLifecycleFixture, *DownloadDispatcher, WorkerEnrollmentCoordinator, identities.CurrentIdentity) {
	t.Helper()
	cf, _ := newDownloadControlFixture(t)
	w := routeTestWorker(t, 1)
	w.Intent.Authority = cf.a
	w.Intent.CreatedAt = cf.now
	w.Intent.RunUntil = cf.now.Add(time.Minute)
	w.Intent.Authority.Environment.InstallationID = w.Binding.InstallationID
	f := &workerLifecycleFixture{now: cf.now, i: cf.i, a: w.Intent.Authority, w: w, hooks: map[string]func(){}, deadlines: map[string]time.Time{}}
	d := &DownloadDispatcher{Ledger: f, Jobs: workerLifecycleJobs{f}, Audit: f, Acknowledgements: f, Authority: f, CurrentAuthority: f, Profile: w.Intent.Profile, Now: f.Now}
	service := WorkerEnrollmentCoordinator{CSR: f, Proofs: f, Ledger: f, Activation: f, Audit: f, Acknowledgements: f, Issuer: f, Authority: f, CurrentAuthority: f, Now: f.Now}
	current, _, err := identities.NewBrowserRequest(context.Background(), f, "synthetic-session-cookie", false, f.Now)
	if err != nil {
		t.Fatal(err)
	}
	return f, d, service, current
}

func TestWorkerCurrentBrowserSessionReachesDispatchAndEnrollmentWithoutBearer(t *testing.T) {
	f, d, service, current := newWorkerLifecycleFixture(t)
	w, err := d.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope)
	if err != nil || w != f.w {
		t.Fatal("browser current identity did not dispatch", err)
	}
	cert, err := service.EnrollCurrent(context.Background(), current, w.Intent.SessionID, w.Intent.ID, f.a.Scope, []byte("same-process-csr"))
	if err != nil || cert.Peer.Role != "acquisition" || f.count("sign") != 1 {
		t.Fatal("browser current identity did not enroll", err)
	}
}
func currentWorkerOperation(t *testing.T, f *workerLifecycleFixture, service WorkerEnrollmentCoordinator, current identities.CurrentIdentity) *WorkerEnrollmentOperation {
	t.Helper()
	op, err := NewCurrentWorkerEnrollmentOperation(context.Background(), service, func(tokens DownloadPeerToken) (WorkerEnrollmentProofReader, error) {
		b, e := tokens.ReadDownloadPeerToken(context.Background())
		defer clear(b)
		if e != nil || string(b) != "pod-token" {
			return nil, artifact.ErrInvalid
		}
		return f, nil
	}, current, workerTarget(f.w), f.a.Scope)
	if err != nil {
		t.Fatal(err)
	}
	return op
}
func currentWorkerOwners(t *testing.T, f *workerLifecycleFixture, op *WorkerEnrollmentOperation) (*WorkerRequestOwners, *WorkerOwnerRegistration) {
	t.Helper()
	router, err := NewWorkerEnrollmentRouter(context.Background(), f.w.Binding.InstallationID, f, f.Now, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(router.Close)
	var lease value.WorkerOwnerLease
	store := testWorkerOwnerStore{claim: func(ctx context.Context, r value.WorkerOwnerRequest) (value.WorkerOwnerLease, error) {
		e := f.step(ctx, "claim-owner")
		lease = value.WorkerOwnerLease{Request: r, Fence: 1, Started: f.Now()}
		return lease, e
	}, read: func(ctx context.Context, _, _ string) (value.WorkerOwnerLease, error) {
		return lease, f.step(ctx, "read-owner")
	}, release: func(ctx context.Context, _ value.WorkerOwnerLease) error { return f.step(ctx, "release-owner") }}
	owners := &WorkerRequestOwners{Router: router, Store: store, PodUID: f.w.Binding.PodUID, ProcessEpoch: f.w.Intent.ID, NewID: func() string { return f.w.Intent.ID }}
	h, err := owners.Register(context.Background(), op)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := h.Close(context.Background()); e != nil {
			t.Error(e)
		}
	})
	return owners, h
}
func TestWorkerCurrentOriginalCheckTraversesConstructorRouterLocatorAndDelivery(t *testing.T) {
	f, _, s, current := newWorkerLifecycleFixture(t)
	op := currentWorkerOperation(t, f, s, current)
	first := op.pinned
	until := first.Deadline()
	f.change(func() { f.now = f.now.Add(time.Second) })
	owners, h := currentWorkerOwners(t, f, op)
	if h.Lease().Request.Until.After(until) || op.pinned != first {
		t.Fatal("registration renewed or replaced the original identity check")
	}
	d, err := owners.BeginOwnedWorkerEnrollment(context.Background(), h.Lease(), []byte("pod-token"), []byte("same-csr"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	bound, ok := d.Context().Deadline()
	if !ok || bound.After(until) {
		t.Fatal("delivery outlived original check")
	}
	if f.count("sign") != 1 {
		t.Fatal("no actual enrollment effects")
	}
	for _, name := range []string{"claim-owner", "claim-enrollment", "prepare-certificate", "sign", "activate"} {
		if f.deadlines[name].IsZero() || f.deadlines[name].After(until) {
			t.Fatal("effect renewed original interval", name, f.deadlines[name], until)
		}
	}
}
func TestWorkerCurrentDispatchReusesObservationOnlyWithinOriginalInterval(t *testing.T) {
	for _, phase := range []string{"read-worker-audit", "claim-worker", "observe-job", "read-worker"} {
		for _, change := range []string{"groups", "scopes", "policy", "expiry"} {
			t.Run(phase+"/"+change, func(t *testing.T) {
				f, d, _, current := newWorkerLifecycleFixture(t)
				original := f.a.ValidUntil
				f.hooks[phase] = func() {
					f.change(func() {
						switch change {
						case "groups":
							f.i.Groups = []string{"changed"}
						case "scopes":
							f.i.Scopes = []string{"evidence:read"}
						case "policy":
							f.i.Policy.Generation++
						case "expiry":
							f.now = f.now.Add(6 * time.Second)
							f.i.VerifiedAt, f.i.ValidUntil = f.now, f.now.Add(5*time.Second)
							f.a.CheckedAt, f.a.ValidUntil = f.now, f.now.Add(5*time.Second)
						}
					})
				}
				_, err := d.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope)
				if change != "expiry" {
					if err != nil || f.count("authority") != 1 || f.count("create-job") != 1 || f.count("bind-worker") != 1 {
						t.Fatal("bounded operation repeated authority or lost its admitted effects", err, f.calls)
					}
					for name, until := range f.deadlines {
						if until.After(original) {
							t.Fatal("effect renewed original interval", name, until)
						}
					}
					if _, err = newWorkerCurrentCheck(context.Background(), current, f, f.a.Scope, f.Now); err == nil {
						t.Fatal("a new operation reused the old identity after a changed claim")
					}
					return
				}
				if err == nil {
					t.Fatal("expired operation accepted")
				}
				if phase == "read-worker-audit" && f.count("write-worker-audit") != 0 {
					t.Fatal("audit after original expiry")
				}
				if phase == "claim-worker" && f.count("create-job") != 0 {
					t.Fatal("create after original expiry")
				}
				if phase == "observe-job" && f.count("bind-worker") != 0 {
					t.Fatal("bind after original expiry")
				}
			})
		}
	}
}

func TestWorkerCurrentEnrollmentReusesItsOriginalIdentityObservation(t *testing.T) {
	for _, phase := range []string{"proof", "prepare-certificate", "sign", "activate"} {
		t.Run(phase, func(t *testing.T) {
			f, _, service, current := newWorkerLifecycleFixture(t)
			original := f.a.ValidUntil
			f.hooks[phase] = func() { f.change(func() { f.i.Groups = []string{"revoked-group"} }) }
			cert, err := service.EnrollCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope, []byte("csr"))
			if err != nil || cert.Peer.Role != "acquisition" || f.count("authority") != 1 || f.count("sign") != 1 || f.count("activate") != 1 {
				t.Fatal("enrollment repeated its original human authority", err, f.calls)
			}
			for name, until := range f.deadlines {
				if until.After(original) {
					t.Fatal("effect renewed original interval", name, until)
				}
			}
			if _, err = newWorkerCurrentCheck(context.Background(), current, f, f.a.Scope, f.Now); err == nil {
				t.Fatal("new operation did not observe changed identity")
			}
		})
	}
}

func TestWorkerCurrentLostCreateReplyUsesExactLookupWithoutAnotherCreate(t *testing.T) {
	f, d, _, current := newWorkerLifecycleFixture(t)
	f.lostCreate = true
	if _, err := d.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope); err == nil {
		t.Fatal("lost create reply fabricated success")
	}
	w, err := d.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope)
	if err != nil || w != f.w || f.count("create-job") != 1 || f.count("find-job") != 1 || f.count("write-worker-audit") != 1 {
		t.Fatal("retry replaced original creation/audit", err, f.calls)
	}
}
func TestWorkerCurrentLocatorClaimKeepsOriginalObservationAndDeadline(t *testing.T) {
	for _, change := range []string{"expiry", "groups", "shorter"} {
		t.Run(change, func(t *testing.T) {
			f, _, service, current := newWorkerLifecycleFixture(t)
			op := currentWorkerOperation(t, f, service, current)
			original := op.bound()
			router, err := NewWorkerEnrollmentRouter(context.Background(), f.w.Binding.InstallationID, f, f.Now, 1)
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			released := 0
			store := testWorkerOwnerStore{claim: func(ctx context.Context, request value.WorkerOwnerRequest) (value.WorkerOwnerLease, error) {
				lease := value.WorkerOwnerLease{Request: request, Fence: 1, Started: f.Now()}
				f.change(func() {
					switch change {
					case "expiry":
						f.now = f.now.Add(6 * time.Second)
					case "groups":
						f.i.Groups = []string{"changed"}
					case "shorter":
						f.i.ValidUntil = f.now.Add(time.Second)
					}
				})
				return lease, nil
			}, release: func(context.Context, value.WorkerOwnerLease) error { released++; return nil }}
			owners := &WorkerRequestOwners{Router: router, Store: store, PodUID: f.w.Binding.PodUID, ProcessEpoch: f.w.Intent.ID, NewID: func() string { return f.w.Intent.ID }}
			handle, err := owners.Register(context.Background(), op)
			if change == "expiry" {
				if err == nil || handle != nil {
					t.Fatal("expired locator returned")
				}
			} else {
				if err != nil || handle == nil || handle.Lease().Request.Until.After(original) || op.bound() != original || f.count("authority") != 1 {
					t.Fatal("locator failed to use its original bounded observation", err)
				}
				if err = handle.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if released != 1 {
				t.Fatal("exact claim was not released", released)
			}
			router.mu.Lock()
			used := router.used
			router.mu.Unlock()
			if used != 0 {
				t.Fatal("joined registration retained local slot")
			}
		})
	}
}

type workerCurrentGateFunc func(context.Context, identities.CurrentIdentity, artifact.DownloadScope) (artifact.DownloadAuthority, error)

func (f workerCurrentGateFunc) CheckDownloadCurrent(c context.Context, i identities.CurrentIdentity, s artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	return f(c, i, s)
}

type workerCurrentSourceFunc func(context.Context) (identity.Identity, error)

func (f workerCurrentSourceFunc) ResolveIdentity(c context.Context) (identity.Identity, error) {
	return f(c)
}
func TestWorkerCurrentConcurrentLocalChecksCannotRestoreShorterBound(t *testing.T) {
	f, _, _, current := newWorkerLifecycleFixture(t)
	check, err := newWorkerCurrentCheck(context.Background(), current, f, f.a.Scope, f.Now)
	if err != nil {
		t.Fatal(err)
	}
	original, short := check.Deadline(), f.Now().Add(time.Second)
	var work sync.WaitGroup
	for n := 0; n < 32; n++ {
		work.Add(1)
		go func(n int) {
			defer work.Done()
			until := original
			if n == 0 {
				until = short
			}
			if _, err := check.narrow(until); err != nil {
				t.Error(err)
			}
			if _, err := check.Check(context.Background()); err != nil {
				t.Error(err)
			}
		}(n)
	}
	work.Wait()
	a, err := check.Check(context.Background())
	if err != nil || a.ValidUntil != short || check.Deadline() != short || f.count("authority") != 1 {
		t.Fatal("local checks restored the original bound or repeated authority", err, a.ValidUntil, f.calls)
	}
}

func TestWorkerCurrentOwningRequestCancellationStopsBackgroundCheck(t *testing.T) {
	f, _, _, current := newWorkerLifecycleFixture(t)
	owner, cancel := context.WithCancel(context.Background())
	defer cancel()
	check, err := newWorkerCurrentCheck(owner, current, f, f.a.Scope, f.Now)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err = check.Check(context.Background()); err == nil {
		t.Fatal("Background detached the cancelled owner")
	}
	if f.count("authority") != 1 {
		t.Fatal("cancelled local check performed authority I/O")
	}
}

func TestWorkerCurrentObservationDoesNotFollowCallerMutation(t *testing.T) {
	for _, field := range []string{"groups", "scopes", "authority"} {
		t.Run(field, func(t *testing.T) {
			f, _, _, _ := newWorkerLifecycleFixture(t)
			f.i.Groups = []string{"original"}
			raw := f.i
			source := workerCurrentSourceFunc(func(context.Context) (identity.Identity, error) { return raw, nil })
			check, first, err := newWorkerCurrentObservation(context.Background(), source, f, f.a.Scope, f.Now)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "groups":
				raw.Groups[0] = "changed"
			case "scopes":
				raw.Scopes[0] = "changed"
			case "authority":
				f.a.AccessUntil = f.now.Add(30 * time.Second)
			}
			got, err := check.Check(context.Background())
			if err != nil || got != first || f.count("authority") != 1 {
				t.Fatal("caller mutation replaced the owned observation", err)
			}
		})
	}
}

func TestWorkerCurrentOriginalShorterObservationBoundsEveryEffect(t *testing.T) {
	for _, step := range []string{"dispatch", "enrollment"} {
		t.Run(step, func(t *testing.T) {
			f, dispatcher, service, current := newWorkerLifecycleFixture(t)
			short := f.Now().Add(time.Second)
			f.change(func() { f.i.ValidUntil = short })
			var err error
			if step == "dispatch" {
				_, err = dispatcher.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope)
			} else {
				_, err = service.EnrollCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope, []byte("csr"))
			}
			if err != nil {
				t.Fatal(err)
			}
			for name, until := range f.deadlines {
				if until.IsZero() || until.After(short) {
					t.Fatal("effect lost original shorter bound", name, until, short)
				}
			}
		})
	}
}

func TestWorkerCurrentCheckCannotStartOverAfterBlockingProof(t *testing.T) {
	f, _, s, current := newWorkerLifecycleFixture(t)
	op := currentWorkerOperation(t, f, s, current)
	until := op.bound()
	f.hooks["proof"] = func() {
		f.change(func() {
			f.now = f.now.Add(6 * time.Second)
			f.i.VerifiedAt = f.now
			f.i.ValidUntil = f.now.Add(5 * time.Second)
			f.a.CheckedAt = f.now
			f.a.ValidUntil = f.now.Add(5 * time.Second)
		})
	}
	if _, err := op.EnrollWorker(context.Background(), op.target.InstallationID, op.target.SessionID, op.target.WorkerID, []byte("pod-token"), []byte("csr")); err == nil {
		t.Fatal("proof observation renewed request")
	}
	if f.count("claim-enrollment") != 0 || op.bound().After(until) {
		t.Fatal("expired operation gained effects")
	}
}
func TestWorkerCurrentExplicitShorteningBoundsCertificateDelivery(t *testing.T) {
	f, _, s, current := newWorkerLifecycleFixture(t)
	op := currentWorkerOperation(t, f, s, current)
	short := f.Now().Add(time.Second)
	f.hooks["activate"] = func() {
		if _, err := op.pinned.narrow(short); err != nil {
			t.Error(err)
		}
	}
	d, err := op.BeginWorkerEnrollment(context.Background(), op.target.InstallationID, op.target.SessionID, op.target.WorkerID, []byte("pod-token"), []byte("csr"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	until, ok := d.Context().Deadline()
	if !ok || until.After(short) {
		t.Fatal("delivery ignored the explicitly narrowed operation", until, short)
	}
}

func TestWorkerCurrentRouterAndOwnerUseShorterCurrentBound(t *testing.T) {
	f, _, s, current := newWorkerLifecycleFixture(t)
	op := currentWorkerOperation(t, f, s, current)
	short := f.Now().Add(time.Second)
	if _, err := op.pinned.narrow(short); err != nil {
		t.Fatal(err)
	}
	_, h := currentWorkerOwners(t, f, op)
	if got, ok := h.route.ctx.Deadline(); !ok || got.After(short) {
		t.Fatal("route retained longer bound", got)
	}
	if got := f.deadlines["claim-owner"]; got.IsZero() || got.After(short) {
		t.Fatal("locator claim retained longer bound", got)
	}
}

func TestWorkerCurrentInitialObservationRequiresIdentityScopesAndAuthority(t *testing.T) {
	for _, which := range []string{"read-scope", "download-scope", "principal", "authority-scope", "environment", "retention", "expired", "cancelled", "authority-denied"} {
		t.Run(which, func(t *testing.T) {
			f, _, _, _ := newWorkerLifecycleFixture(t)
			source := workerCurrentSourceFunc(func(context.Context) (identity.Identity, error) { return f.i, nil })
			owner, cancel := context.WithCancel(t.Context())
			defer cancel()
			scope := f.a.Scope
			gate := workerCurrentGateFunc(func(context.Context, identities.CurrentIdentity, artifact.DownloadScope) (artifact.DownloadAuthority, error) {
				if which == "authority-denied" {
					return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
				}
				return f.a, nil
			})
			switch which {
			case "read-scope":
				f.i.Scopes = []string{"evidence:download"}
			case "download-scope":
				f.i.Scopes = []string{"evidence:read"}
			case "principal":
				f.i.Principal.Subject = "another-user"
			case "authority-scope":
				f.a.Scope.Principal.Subject = "another-user"
			case "environment":
				f.a.Environment = artifact.DownloadEnvironment{}
			case "retention":
				f.a.Retention = artifact.RetentionProof{}
			case "expired":
				f.a.ValidUntil = f.now
			case "cancelled":
				cancel()
			}
			if _, err := newWorkerCurrentCheck(owner, source, gate, scope, f.Now); err == nil {
				t.Fatal("incomplete initial observation admitted", which)
			}
		})
	}
}

func TestWorkerCurrentNewOperationObservesRevocation(t *testing.T) {
	f, _, _, current := newWorkerLifecycleFixture(t)
	denied := false
	calls := 0
	gate := workerCurrentGateFunc(func(ctx context.Context, source identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
		calls++
		if denied {
			return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
		}
		return f.CheckDownloadCurrent(ctx, source, scope)
	})
	check, first, err := newWorkerCurrentObservation(t.Context(), current, gate, f.a.Scope, f.Now)
	if err != nil {
		t.Fatal(err)
	}
	denied = true
	for range 4 {
		got, err := check.Check(t.Context())
		if err != nil || got != first {
			t.Fatal("operation did not retain its original observation", err)
		}
	}
	if calls != 1 {
		t.Fatal("local operation repeated the authorizer", calls)
	}
	if _, err := newWorkerCurrentCheck(t.Context(), current, gate, f.a.Scope, f.Now); err == nil || calls != 2 {
		t.Fatal("next operation reused the old authorization", err, calls)
	}
	f.change(func() { f.now = first.ValidUntil })
	if _, err := check.Check(t.Context()); err == nil || calls != 2 {
		t.Fatal("expired operation renewed its observation", err, calls)
	}
}
