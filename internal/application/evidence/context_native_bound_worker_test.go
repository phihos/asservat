package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Synthetic current SQL/Pod observations exercise continuation orchestration.
// They are not Kubernetes proof or native preparation qualification.
type boundWorkerAttachments struct {
	*contextAttachmentFixture
	before func(int)
	err    error
}

func (s *boundWorkerAttachments) ReadContextDownloadAttachment(ctx context.Context, session string, a artifact.DownloadAuthority) (ContextDownloadAttachment, error) {
	if s.before != nil {
		s.before(s.reads + 1)
	}
	if s.err != nil {
		s.reads++
		return ContextDownloadAttachment{}, s.err
	}
	return s.contextAttachmentFixture.ReadContextDownloadAttachment(ctx, session, a)
}

type boundWorkerJobs struct {
	workerLifecycleJobs
	err error
}

func (s *boundWorkerJobs) ObserveDownloadWorker(ctx context.Context, intent value.DownloadWorkerIntent, job value.DownloadWorkerJob) (value.DownloadWorker, error) {
	if intent != s.f.w.Intent || job != s.f.w.Job {
		return value.DownloadWorker{}, artifact.ErrIntegrity
	}
	w, e := s.workerLifecycleJobs.ObserveDownloadWorker(ctx, intent, job)
	if s.err != nil {
		return value.DownloadWorker{}, s.err
	}
	return w, e
}

type boundWorkerFixture struct {
	f      *downloadResultFixture
	launch *workerLifecycleFixture
	lookup *boundWorkerAttachments
	jobs   *boundWorkerJobs
	r      *ContextNativeRuntime
	source ContextDownloadSource
}

func newBoundWorkerFixture(t *testing.T) boundWorkerFixture {
	t.Helper()
	f, lookup, runtime, _ := warmContextRuntimeFixture(t)
	f.s.State = artifact.DownloadPreparing
	lookup.value.State = f.s.State
	lookup.value.MetadataAttempted = false
	lookup.value.Preparation = nil
	lookup.value.Enrollment = nil
	lookup.value.NativeTransitions = 8
	launch, dispatcher, service, _ := newWorkerLifecycleFixture(t)
	launch.now, launch.i, launch.a, launch.w = f.now, f.identity, f.a, f.enrollment.Worker
	launch.created, launch.acknowledged = true, true
	dispatcher.Profile = launch.w.Intent.Profile
	jobs := &boundWorkerJobs{workerLifecycleJobs: workerLifecycleJobs{launch}}
	dispatcher.Jobs = jobs
	look := &boundWorkerAttachments{contextAttachmentFixture: lookup}
	runtime.config.Dispatcher, runtime.config.Workers = dispatcher, look
	runtime.config.Enrollments = service
	runtime.config.Proofs = func(DownloadPeerToken) (WorkerEnrollmentProofReader, error) { return launch, nil }
	runtime.config.NewID = func() string { return launch.w.Intent.ID }
	router, e := NewWorkerEnrollmentRouter(context.Background(), launch.w.Binding.InstallationID, launch, launch.Now, 1)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(router.Close)
	store := testWorkerOwnerStore{claim: func(ctx context.Context, request value.WorkerOwnerRequest) (value.WorkerOwnerLease, error) {
		e := launch.step(ctx, "claim-owner")
		return value.WorkerOwnerLease{Request: request, Fence: 1, Started: launch.Now()}, e
	}, release: func(ctx context.Context, _ value.WorkerOwnerLease) error { return launch.step(ctx, "release-owner") }}
	runtime.config.Requests = &WorkerRequestOwners{Router: router, Store: store, PodUID: launch.w.Binding.PodUID, ProcessEpoch: launch.w.Intent.ID, NewID: runtime.config.NewID}
	control, _ := newDownloadControlFixture(t)
	source := control.source
	source.ObservedAt, source.ValidUntil = f.now, f.a.ValidUntil
	if source.Scope != f.s.Scope || !source.Valid(f.now) || !lookup.value.Valid(f.now) {
		t.Fatal("bound-worker fixture scope or observation invalid")
	}
	return boundWorkerFixture{f, launch, look, jobs, runtime, source}
}

func (f boundWorkerFixture) advance(d time.Duration) {
	f.f.mu.Lock()
	f.f.now = f.f.now.Add(d)
	f.f.mu.Unlock()
	f.launch.change(func() { f.launch.now = f.launch.now.Add(d) })
}

func (f boundWorkerFixture) noLaunchEffects(t *testing.T) {
	t.Helper()
	for _, name := range []string{"reserve-worker", "read-worker-audit", "write-worker-audit", "ack-worker-audit", "claim-worker", "create-job", "find-job", "record-job", "bind-worker", "read-worker"} {
		if f.launch.count(name) != 0 {
			t.Errorf("already-bound continuation replayed %s", name)
		}
	}
}

func TestContextRuntimeBoundWorkerAvoidsCompletedLaunchReplay(t *testing.T) {
	f := newBoundWorkerFixture(t)
	original := *f.lookup.value.Worker
	f.lookup.before = func(_ int) {
		if f.launch.count("claim-owner") > 0 {
			f.advance(1100 * time.Millisecond)
		}
	}
	out, err := f.r.ContinueContextDownload(context.Background(), f.f, f.f.s, f.source)
	if err != nil || !out.Pending {
		t.Fatal("current original worker did not reach bounded enrollment wait", err)
	}
	f.noLaunchEffects(t)
	if f.launch.count("observe-job") != 1 || f.lookup.reads < 3 || f.launch.count("claim-owner") != 1 || f.launch.count("release-owner") != 1 || *f.lookup.value.Worker != original {
		t.Fatal("current Pod/SQL observation or joined original registration missing", f.launch.calls, f.lookup.reads)
	}
	for phase, deadline := range f.launch.deadlines {
		if phase == "release-owner" {
			// Restrictive release has its own bounded cleanup context; it
			// cannot perform preparation and has already joined above.
			if deadline.After(time.Now().Add(5 * time.Second)) {
				t.Fatal("owner release exceeded its separate cleanup bound")
			}
			continue
		}
		if deadline.After(f.source.ValidUntil) {
			t.Fatalf("%s extended original source deadline", phase)
		}
	}
}

func TestContextRuntimeBoundWorkerRechecksNegativeObservations(t *testing.T) {
	for _, mode := range []string{"revoked-before", "pod-replaced", "job-replaced", "multiple-pods", "bound-pending", "terminated", "binding-removed", "sql-worker-replaced", "busy", "uncertain", "cancelled", "expired-after-pod", "expired-after-sql"} {
		t.Run(mode, func(t *testing.T) {
			f := newBoundWorkerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "revoked-before":
				f.f.failure = "current-authority"
			case "pod-replaced":
				f.launch.hooks["observe-job"] = func() { f.launch.w.Binding.PodUID = "replacement-pod" }
			case "job-replaced":
				f.launch.hooks["observe-job"] = func() { f.launch.w.Job.UID = "replacement-job" }
			case "multiple-pods":
				// The real Kubernetes adapter rejects >1 Pod; the caller must not
				// fall back to a stored binding or relaunch when that port denies.
				f.jobs.err = artifact.ErrDownloadUnavailable
			case "bound-pending":
				f.jobs.err = &DownloadWorkerPending{Intent: f.launch.w.Intent, Job: f.launch.w.Job, ObservedAt: f.f.now, ValidUntil: f.source.ValidUntil}
			case "terminated":
				// The current SQL attachment rejects observed termination/retirement.
				f.lookup.before = func(n int) {
					if n == 2 {
						f.lookup.err = artifact.ErrDownloadUnavailable
					}
				}
			case "binding-removed":
				f.lookup.before = func(n int) {
					if n == 2 {
						f.lookup.value.Worker = nil
					}
				}
			case "sql-worker-replaced":
				f.lookup.before = func(n int) {
					if n == 2 {
						w := *f.lookup.value.Worker
						w.Binding.PodUID = "replacement-pod"
						f.lookup.value.Worker = &w
					}
				}
			case "busy":
				f.lookup.before = func(n int) {
					if n == 2 {
						f.lookup.value.NativeBusy = true
					}
				}
			case "uncertain":
				f.lookup.value.NativeUncertain = true
			case "cancelled":
				f.launch.hooks["observe-job"] = cancel
			case "expired-after-pod":
				f.launch.hooks["observe-job"] = func() { f.advance(6 * time.Second) }
			case "expired-after-sql":
				f.lookup.before = func(n int) {
					if n == 2 {
						f.advance(6 * time.Second)
					}
				}
			}
			if _, err := f.r.ContinueContextDownload(ctx, f.f, f.f.s, f.source); err == nil {
				t.Fatal("negative current observation admitted continuation")
			}
			f.noLaunchEffects(t)
			if f.launch.count("claim-owner") != 0 || f.f.count("begin") != 0 {
				t.Fatal("denial reached new owner/preparation effect")
			}
			if mode == "revoked-before" && (f.lookup.reads != 0 || f.launch.count("observe-job") != 0) {
				t.Fatal("ineligible identity caused catalog/Pod lookup")
			}
		})
	}
}

func TestContextRuntimeBoundWorkerPreservesShorterParentDeadline(t *testing.T) {
	for _, phase := range []string{"pod", "sql"} {
		t.Run(phase, func(t *testing.T) {
			f := newBoundWorkerFixture(t)
			until := f.f.now.Add(300 * time.Millisecond)
			ctx, cancel := context.WithDeadline(context.Background(), until)
			defer cancel()
			if phase == "pod" {
				f.launch.hooks["observe-job"] = func() { f.advance(400 * time.Millisecond) }
			} else {
				f.lookup.before = func(n int) {
					if n == 2 {
						f.advance(400 * time.Millisecond)
					}
				}
			}
			if _, err := f.r.ContinueContextDownload(ctx, f.f, f.f.s, f.source); err == nil {
				t.Fatal("completed blocking observation renewed original parent interval")
			}
			f.noLaunchEffects(t)
			if f.launch.count("observe-job") != 1 || f.launch.count("claim-owner") != 0 || f.launch.deadlines["observe-job"].After(until) {
				t.Fatal("original parent deadline did not reach current Pod observation", f.launch.calls)
			}
		})
	}
}

func TestContextRuntimeUnboundWorkerStillUsesLaunchRecovery(t *testing.T) {
	f := newBoundWorkerFixture(t)
	f.lookup.value.Worker = nil
	// Stop at the existing reservation seam; this test proves the branch keeps
	// using the original launch path instead of a fabricated current worker.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.launch.hooks["reserve-worker"] = cancel
	_, err := f.r.ContinueContextDownload(ctx, f.f, f.f.s, f.source)
	if !errors.Is(err, context.Canceled) || f.launch.count("reserve-worker") != 1 || f.launch.count("observe-job") != 0 {
		t.Fatal("unbound launch bypassed original recovery", err, f.launch.calls)
	}
}

// Native16 regression: an enrollment produced during this request's own
// registration ends the request as Preparing. Native preparation is the next
// deliberate continuation's work under its own current identity.
func TestContextRuntimeNewEnrollmentDefersPreparationToNextContinuation(t *testing.T) {
	f := newBoundWorkerFixture(t)
	en := f.f.enrollment
	peer := value.KeyPeer{InstallationID: en.Worker.Binding.InstallationID, PeerID: en.Worker.Binding.PodUID, Role: "acquisition", Certificate: artifact.Digest{31}, NotBefore: f.f.now.Add(-time.Second), NotAfter: en.Worker.Intent.RunUntil.UTC().Truncate(time.Second)}
	f.lookup.before = func(_ int) {
		if f.launch.count("claim-owner") > 0 && f.lookup.value.Enrollment == nil {
			f.lookup.value.Enrollment, f.lookup.value.ActivatedPeer = &en, &peer
		}
	}
	out, err := f.r.ContinueContextDownload(context.Background(), f.f, f.f.s, f.source)
	if err != nil || !out.Pending {
		t.Fatal("new enrollment did not end the original request as Preparing", err)
	}
	if f.f.count("begin") != 0 || f.launch.count("claim-owner") != 1 || f.launch.count("release-owner") != 1 {
		t.Fatal("same request started native preparation or kept its registration", f.f.count("begin"), f.launch.calls)
	}
	f.noLaunchEffects(t)
}

// Native21-23 regression: the one-second arrival window must not close a
// registration whose worker enrollment exchange is still in flight.
func TestContextRuntimeKeepsRegistrationDuringInFlightEnrollment(t *testing.T) {
	f := newBoundWorkerFixture(t)
	en := f.f.enrollment
	peer := value.KeyPeer{InstallationID: en.Worker.Binding.InstallationID, PeerID: en.Worker.Binding.PodUID, Role: "acquisition", Certificate: artifact.Digest{31}, NotBefore: f.f.now.Add(-time.Second), NotAfter: en.Worker.Intent.RunUntil.UTC().Truncate(time.Second)}
	router := f.r.config.Requests.Router
	setBusy := func(v bool) {
		router.mu.Lock()
		defer router.mu.Unlock()
		for _, e := range router.entries {
			e.busy = v
		}
	}
	reads := 0
	f.lookup.before = func(_ int) {
		if f.launch.count("claim-owner") == 0 {
			return
		}
		reads++
		switch reads {
		case 1:
			setBusy(true) // the worker's exchange is in flight
			f.advance(1100 * time.Millisecond)
		case 3:
			setBusy(false)
			f.lookup.value.Enrollment, f.lookup.value.ActivatedPeer = &en, &peer
		}
	}
	out, err := f.r.ContinueContextDownload(context.Background(), f.f, f.f.s, f.source)
	if err != nil || !out.Pending || reads < 3 || f.launch.count("release-owner") != 1 {
		t.Fatal("registration closed under an in-flight enrollment exchange", reads, err)
	}
}

// Native30 regression: SQL shows the new enrollment once activation commits,
// while the exchange still delivers its certificate. The request must not
// close (and so cancel) that exchange before it ends.
func TestContextRuntimeNewEnrollmentWaitsForDeliveryToEnd(t *testing.T) {
	f := newBoundWorkerFixture(t)
	en := f.f.enrollment
	peer := value.KeyPeer{InstallationID: en.Worker.Binding.InstallationID, PeerID: en.Worker.Binding.PodUID, Role: "acquisition", Certificate: artifact.Digest{31}, NotBefore: f.f.now.Add(-time.Second), NotAfter: en.Worker.Intent.RunUntil.UTC().Truncate(time.Second)}
	router := f.r.config.Requests.Router
	setBusy := func(v bool) {
		router.mu.Lock()
		defer router.mu.Unlock()
		for _, e := range router.entries {
			e.busy = v
		}
	}
	reads := 0
	f.lookup.before = func(_ int) {
		if f.launch.count("claim-owner") == 0 {
			return
		}
		reads++
		switch reads {
		case 1: // activation committed; certificate delivery still in flight
			setBusy(true)
			f.lookup.value.Enrollment, f.lookup.value.ActivatedPeer = &en, &peer
		case 3:
			setBusy(false)
		}
	}
	out, err := f.r.ContinueContextDownload(context.Background(), f.f, f.f.s, f.source)
	if err != nil || !out.Pending || reads < 3 || f.f.count("begin") != 0 || f.launch.count("release-owner") != 1 {
		t.Fatal("request closed its registration during certificate delivery", reads, err)
	}
}

// A failed later authorizer observation is learned by the next operation. The
// existing SQL/Pod reads remain real calls in this operation and can still deny.
func TestContextRuntimeBoundWorkerReusesOneAuthorityObservation(t *testing.T) {
	for _, phase := range []string{"pod", "sql"} {
		t.Run(phase, func(t *testing.T) {
			f := newBoundWorkerFixture(t)
			if phase == "pod" {
				f.launch.hooks["observe-job"] = func() { f.f.failure = "current-authority" }
			}
			f.lookup.before = func(n int) {
				if phase == "sql" && n == 2 {
					f.f.failure = "current-authority"
				}
				if f.launch.count("claim-owner") > 0 {
					f.advance(1100 * time.Millisecond)
				}
			}
			out, err := f.r.ContinueContextDownload(t.Context(), f.f, f.f.s, f.source)
			if err != nil || !out.Pending || f.f.count("current-authority") != 1 || f.launch.count("claim-owner") != 1 || f.launch.count("release-owner") != 1 {
				t.Fatal("bounded continuation repeated its authorization", err, f.launch.calls)
			}
			f.noLaunchEffects(t)
			reads := f.lookup.reads
			if _, err = f.r.ContinueContextDownload(t.Context(), f.f, f.f.s, f.source); err == nil || f.lookup.reads != reads {
				t.Fatal("next operation bypassed the changed authorizer", err)
			}
		})
	}
}
