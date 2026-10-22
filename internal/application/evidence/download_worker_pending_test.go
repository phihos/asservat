package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"errors"
	"testing"
	"time"
)

type pendingWorkerJobs struct {
	workerLifecycleJobs
	ready       bool
	unavailable bool
	mutate      func(*DownloadWorkerPending)
}

func (s *pendingWorkerJobs) ObserveDownloadWorker(ctx context.Context, i value.DownloadWorkerIntent, job value.DownloadWorkerJob) (value.DownloadWorker, error) {
	if s.ready {
		return s.workerLifecycleJobs.ObserveDownloadWorker(ctx, i, job)
	}
	p := &DownloadWorkerPending{Intent: i, Job: job, ObservedAt: s.f.Now(), ValidUntil: s.f.Now().Add(5 * time.Second)}
	if e := s.f.step(ctx, "observe-job"); e != nil {
		return value.DownloadWorker{}, e
	}
	if s.unavailable {
		return value.DownloadWorker{}, artifact.ErrDownloadUnavailable
	}
	if s.mutate != nil {
		s.mutate(p)
	}
	return value.DownloadWorker{}, p
}
func TestWorkerPendingContinuationRetainsOneOriginalCreateAndAudit(t *testing.T) {
	f, d, _, current := newWorkerLifecycleFixture(t)
	jobs := &pendingWorkerJobs{workerLifecycleJobs: workerLifecycleJobs{f}}
	d.Jobs = jobs
	_, err := d.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope)
	var pending *DownloadWorkerPending
	if !errors.As(err, &pending) || !pending.Valid(f.Now()) || pending.Intent != f.w.Intent || pending.Job != f.w.Job {
		t.Fatal("positive startup observation missing", err)
	}
	if f.count("bind-worker") != 0 || f.count("create-job") != 1 || f.count("write-worker-audit") != 1 {
		t.Fatal("pending startup created a binding or repeated work")
	}
	// An explicitly new caller and independently fresh synthetic observations
	// model a later prepare POST; the old CurrentIdentity is not renewed.
	f.change(func() {
		f.now = f.now.Add(6 * time.Second)
		f.i.ValidUntil = f.now.Add(30 * time.Second)
		f.a.ValidUntil = f.now.Add(5 * time.Second)
	})
	fresh, _, err := identities.NewBrowserRequest(context.Background(), f, "synthetic-session-cookie", false, f.Now)
	if err != nil {
		t.Fatal(err)
	}
	jobs.ready = true
	w, err := d.EnsureCurrent(context.Background(), fresh, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope)
	if err != nil || w != f.w {
		t.Fatal("exact later startup did not bind original worker", err)
	}
	if f.count("create-job") != 1 || f.count("find-job") != 1 || f.count("write-worker-audit") != 1 || f.count("bind-worker") != 1 {
		t.Fatal("continuation repeated original work", f.calls)
	}
}
func TestWorkerPendingCannotMaskUnknownOrInvalidObservation(t *testing.T) {
	for _, mode := range []string{"unknown", "intent", "job", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f, d, _, current := newWorkerLifecycleFixture(t)
			jobs := &pendingWorkerJobs{workerLifecycleJobs: workerLifecycleJobs{f}}
			d.Jobs = jobs
			switch mode {
			case "unknown":
				jobs.unavailable = true
			case "intent":
				jobs.mutate = func(p *DownloadWorkerPending) { p.Intent.Generation++ }
			case "job":
				jobs.mutate = func(p *DownloadWorkerPending) { p.Job.UID = "another-job" }
			case "expired":
				jobs.mutate = func(p *DownloadWorkerPending) { p.ValidUntil = p.ObservedAt }
			}
			_, err := d.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope)
			var pending *DownloadWorkerPending
			if err == nil || errors.As(err, &pending) {
				t.Fatal("unknown or denied work became pending", err)
			}
			if f.count("bind-worker") != 0 {
				t.Fatal("pending/unknown worker was bound")
			}
		})
	}
}

// A later provider change does not mutate the operation's already observed
// authority. It is learned by a new operation, which keeps its own original
// cutoff. These synthetic ports do not replace the independent SQL fences.
func TestWorkerPendingReusesOriginalAuthorityAndReobservesNextOperation(t *testing.T) {
	for _, mode := range []string{"revoked", "shortened"} {
		t.Run(mode, func(t *testing.T) {
			f, d, _, current := newWorkerLifecycleFixture(t)
			d.Jobs = &pendingWorkerJobs{workerLifecycleJobs: workerLifecycleJobs{f}}
			original := f.a.ValidUntil
			f.hooks["observe-job"] = func() {
				f.change(func() {
					if mode == "revoked" {
						f.i.Scopes = []string{"evidence:read"}
					} else {
						f.a.ValidUntil = f.now.Add(time.Second)
					}
				})
			}
			_, err := d.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope)
			var pending *DownloadWorkerPending
			if !errors.As(err, &pending) || !pending.Valid(f.Now()) || !pending.ValidUntil.Equal(original) || f.count("authority") != 1 {
				t.Fatal("pending startup did not retain one original authority observation", err, f.calls)
			}
			for phase, until := range f.deadlines {
				if until.After(original) {
					t.Fatal("pending startup renewed an effect deadline", phase, until)
				}
			}
			if f.count("bind-worker") != 0 || f.count("create-job") != 1 || f.count("write-worker-audit") != 1 {
				t.Fatal("pending startup bound a worker or repeated an effect", f.calls)
			}
			if mode == "shortened" {
				// The next operation really observes the shorter interval. Completing a
				// blocking Pod read after that original cutoff cannot yield Pending.
				f.hooks["observe-job"] = func() { f.change(func() { f.now = f.a.ValidUntil.Add(time.Millisecond) }) }
			}
			_, err = d.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope)
			pending = nil
			if err == nil || errors.As(err, &pending) {
				t.Fatal("new operation ignored revocation or its newly observed shorter cutoff", err)
			}
			if mode == "revoked" {
				if f.count("authority") != 1 || f.count("reserve-worker") != 1 || f.count("observe-job") != 1 {
					t.Fatal("revoked new operation reached worker lookups/effects", f.calls)
				}
			} else {
				if !errors.Is(err, artifact.ErrDownloadExpired) || f.count("authority") != 2 || f.count("observe-job") != 2 || f.count("find-job") != 1 {
					t.Fatal("new shortened operation failed outside the retained pending boundary", err, f.calls)
				}
				if f.deadlines["observe-job"].After(f.a.ValidUntil) {
					t.Fatal("new operation extended observed shorter authority")
				}
			}
			if f.count("bind-worker") != 0 || f.count("create-job") != 1 || f.count("write-worker-audit") != 1 {
				t.Fatal("new operation repeated original create/audit or bound denied work", f.calls)
			}
		})
	}
}

func TestWorkerPendingClipsActuallyObservedBounds(t *testing.T) {
	for _, mode := range []string{"authority", "pending-observation"} {
		t.Run(mode, func(t *testing.T) {
			f, d, _, current := newWorkerLifecycleFixture(t)
			jobs := &pendingWorkerJobs{workerLifecycleJobs: workerLifecycleJobs{f}}
			d.Jobs = jobs
			shorter := f.Now().Add(time.Second)
			if mode == "authority" {
				f.change(func() { f.a.ValidUntil = shorter })
			} else {
				jobs.mutate = func(p *DownloadWorkerPending) { p.ValidUntil = shorter }
			}
			_, err := d.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope)
			var pending *DownloadWorkerPending
			if !errors.As(err, &pending) || !pending.Valid(f.Now()) || !pending.ValidUntil.Equal(shorter) || f.count("authority") != 1 || f.count("bind-worker") != 0 {
				t.Fatal("pending response outlived an actually observed shorter bound", err)
			}
		})
	}
}
