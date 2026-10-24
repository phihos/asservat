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
	launch, dispatcher, _, _ := newWorkerLifecycleFixture(t)
	launch.now, launch.i, launch.a, launch.w = f.now, f.identity, f.a, f.enrollment.Worker
	launch.created, launch.acknowledged = true, true
	dispatcher.Profile = launch.w.Intent.Profile
	jobs := &boundWorkerJobs{workerLifecycleJobs: workerLifecycleJobs{launch}}
	dispatcher.Jobs = jobs
	look := &boundWorkerAttachments{contextAttachmentFixture: lookup}
	runtime.config.Dispatcher, runtime.config.Workers = dispatcher, look
	runtime.config.NewID = func() string { return launch.w.Intent.ID }
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
	out, err := f.r.ContinueContextDownload(context.Background(), f.f, f.f.s, f.source)
	if err != nil || !out.Pending {
		t.Fatal("current original worker did not return pending independent enrollment", err)
	}
	f.noLaunchEffects(t)
	if f.launch.count("observe-job") != 1 || f.lookup.reads != 2 || f.launch.count("claim-owner") != 0 || f.launch.count("release-owner") != 0 || *f.lookup.value.Worker != original {
		t.Fatal("current Pod/SQL observation missing or human registration performed", f.launch.calls, f.lookup.reads)
	}
	for phase, deadline := range f.launch.deadlines {
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

// ADR221: an independently activated peer observed during this request does
// not introduce a human certificate owner or extend the original preparation.
// A subsequent deliberate continuation may consume the active peer.
func TestContextRuntimeNewEnrollmentReturnsPendingWithoutOwner(t *testing.T) {
	f := newBoundWorkerFixture(t)
	en := f.f.enrollment
	peer := value.KeyPeer{InstallationID: en.Worker.Binding.InstallationID, PeerID: en.Worker.Binding.PodUID, Role: "acquisition", Certificate: artifact.Digest{31}, NotBefore: f.f.now.Add(-time.Second), NotAfter: en.Worker.Intent.RunUntil.UTC().Truncate(time.Second)}
	f.lookup.before = func(n int) {
		if n == 2 {
			f.lookup.value.Enrollment, f.lookup.value.ActivatedPeer = &en, &peer
		}
	}
	out, err := f.r.ContinueContextDownload(context.Background(), f.f, f.f.s, f.source)
	if err != nil || !out.Pending || f.lookup.reads != 2 || f.f.count("begin") != 0 || f.launch.count("claim-owner") != 0 {
		t.Fatal("independent activation caused same-request preparation or ownership", out.Pending, err, f.launch.calls)
	}
	f.noLaunchEffects(t)
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
			}
			out, err := f.r.ContinueContextDownload(t.Context(), f.f, f.f.s, f.source)
			if err != nil || !out.Pending || f.f.count("current-authority") != 1 || f.launch.count("claim-owner") != 0 || f.launch.count("release-owner") != 0 {
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
