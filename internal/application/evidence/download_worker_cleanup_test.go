package evidence

import (
	"context"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Synthetic ports for native download worker retirement. Real Job/Pod
// termination evidence and SQL row locks are covered by adapter/native suites.
type downloadCleanupFixture struct {
	now      func() time.Time
	rows     []DownloadCleanupCandidate
	finished map[string]bool
	charged  map[string]bool
	calls    []string
}

func (f *downloadCleanupFixture) term(w value.DownloadWorker) value.DownloadWorkerTermination {
	n := f.now()
	return value.DownloadWorkerTermination{Worker: w, TerminationDigest: artifact.Digest{9}, ObservedAt: n, FreshUntil: n.Add(time.Second)}
}
func (f *downloadCleanupFixture) UnretiredDownloadWorkers(ctx context.Context) ([]DownloadCleanupCandidate, error) {
	f.calls = append(f.calls, "download-list")
	out := []DownloadCleanupCandidate{}
	for _, r := range f.rows {
		if f.charged[r.Worker.Intent.ID] {
			out = append(out, r)
		}
	}
	return out, ctx.Err()
}
func (f *downloadCleanupFixture) ConfirmDownloadWorkerTermination(ctx context.Context, t value.DownloadWorkerTermination) (value.DownloadWorkerTermination, error) {
	f.calls = append(f.calls, "download-persist")
	return t, ctx.Err()
}
func (f *downloadCleanupFixture) RetireDownloadWorker(ctx context.Context, p value.DownloadWorkerRetirement) error {
	f.calls = append(f.calls, "download-retire")
	delete(f.charged, p.Termination.Worker.Intent.ID)
	return ctx.Err()
}

type downloadCleanupJobs struct{ f *downloadCleanupFixture }

func (j downloadCleanupJobs) ObserveDownloadWorkerTermination(ctx context.Context, w value.DownloadWorker) (value.DownloadWorkerTermination, error) {
	j.f.calls = append(j.f.calls, "download-observe")
	if !j.f.finished[w.Intent.ID] {
		return value.DownloadWorkerTermination{}, artifact.ErrDownloadUnavailable
	}
	return j.f.term(w), ctx.Err()
}
func (j downloadCleanupJobs) RetireDownloadWorker(ctx context.Context, t value.DownloadWorkerTermination) (value.DownloadWorkerRetirement, error) {
	j.f.calls = append(j.f.calls, "download-delete-and-prove")
	n := j.f.now()
	return value.DownloadWorkerRetirement{Termination: t, ObservedAt: n, FreshUntil: n.Add(time.Second)}, ctx.Err()
}

type noExpiredQueryWorkers struct{ ProjectionCleanupLedger }

func (noExpiredQueryWorkers) ExpiredProjectionWorkers(ctx context.Context) ([]ProjectionCleanupCandidate, error) {
	return nil, ctx.Err()
}

func newDownloadCleanup(now func() time.Time, workers ...value.DownloadWorker) (*downloadCleanupFixture, *ProjectionWorkerCleanup) {
	f := &downloadCleanupFixture{now: now, finished: map[string]bool{}, charged: map[string]bool{}}
	for _, w := range workers {
		f.rows = append(f.rows, DownloadCleanupCandidate{Worker: w})
		f.charged[w.Intent.ID] = true
	}
	return f, &ProjectionWorkerCleanup{Ledger: noExpiredQueryWorkers{}, Jobs: &projectionCleanupFixture{}, Downloads: f, DownloadJobs: downloadCleanupJobs{f}, Now: now}
}

func TestDownloadCleanupRetiresFinishedWorkerAndKeepsActiveCharged(t *testing.T) {
	finished, active := routeTestWorker(t, 1), routeTestWorker(t, 2)
	f, s := newDownloadCleanup(time.Now, finished, active)
	f.finished[finished.Intent.ID] = true
	var reports []string
	s.Report = func(stage string) { reports = append(reports, stage) }
	s.CleanupProjectionWorkers(context.Background())
	s.CleanupProjectionWorkers(context.Background())
	want := []string{"download-list", "download-observe", "download-persist", "download-delete-and-prove", "download-retire", "download-list", "download-observe"}
	if !reflect.DeepEqual(f.calls, want) || f.charged[finished.Intent.ID] || !f.charged[active.Intent.ID] {
		t.Fatal("download cleanup did not retire only the finished worker", f.calls, f.charged)
	}
	if len(reports) != 0 {
		t.Fatal("a running download before RunUntil was reported as a cleanup failure", reports)
	}
}

func TestDownloadCleanupResumesPersistedTerminationWithoutObserving(t *testing.T) {
	w := routeTestWorker(t, 1)
	f, s := newDownloadCleanup(time.Now, w)
	f.rows[0].Termination = f.term(w)
	s.CleanupProjectionWorkers(context.Background())
	if !reflect.DeepEqual(f.calls, []string{"download-list", "download-delete-and-prove", "download-retire"}) || f.charged[w.Intent.ID] {
		t.Fatal("persisted termination was not resumed", f.calls)
	}
}

// Capacity is released only by the admission-time cleanup: two finished
// downloads hold both shared slots until the next admission retires one.
type capacityWorkerLedger struct {
	*workerLifecycleFixture
	charged map[string]bool
}

func (l capacityWorkerLedger) ReserveDownloadWorker(ctx context.Context, session, id string, a artifact.DownloadAuthority, p value.DownloadWorkerProfile) (value.DownloadWorkerIntent, error) {
	if len(l.charged) >= 2 {
		return value.DownloadWorkerIntent{}, artifact.ErrDownloadUnavailable
	}
	return l.workerLifecycleFixture.ReserveDownloadWorker(ctx, session, id, a, p)
}

func TestDownloadAdmissionRetiresFinishedWorkerBeforeReservingSlot(t *testing.T) {
	f, d, _, current := newWorkerLifecycleFixture(t)
	first, second := routeTestWorker(t, 11), routeTestWorker(t, 12)
	cleanup, s := newDownloadCleanup(f.Now, first, second)
	cleanup.finished[first.Intent.ID], cleanup.finished[second.Intent.ID] = true, true
	d.Ledger = capacityWorkerLedger{f, cleanup.charged}
	if _, err := d.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope); err == nil {
		t.Fatal("third download admitted while both slots were charged")
	}
	d.ProjectionCleanup = s
	w, err := d.EnsureCurrent(context.Background(), current, f.w.Intent.SessionID, f.w.Intent.ID, f.a.Scope)
	if err != nil || w != f.w || len(cleanup.charged) != 1 || cleanup.calls[len(cleanup.calls)-1] != "download-retire" {
		t.Fatal("admission did not free a finished download worker's slot", err, cleanup.calls)
	}
}

type refusedRetirementJobs struct {
	downloadCleanupJobs
	step string
}

func (j refusedRetirementJobs) RetireDownloadWorker(context.Context, value.DownloadWorkerTermination) (value.DownloadWorkerRetirement, error) {
	return value.DownloadWorkerRetirement{}, retirementDiagnosticFixture{j.step}
}

type retirementDiagnosticFixture struct{ step string }

func (e retirementDiagnosticFixture) Error() string     { return "provider-private-detail" }
func (e retirementDiagnosticFixture) Unwrap() error     { return artifact.ErrDownloadUnavailable }
func (e retirementDiagnosticFixture) FixedStep() string { return e.step }

func TestDownloadCleanupRetirementDiagnosticsRemainClosedAndCharged(t *testing.T) {
	for _, step := range []string{"retirement/delete", "retirement/job-present", "retirement/pods-present", "retirement/current", "provider-private-detail"} {
		t.Run(step, func(t *testing.T) {
			now := time.Now
			w := routeTestWorker(t, 11)
			f, cleanup := newDownloadCleanup(now, w)
			f.finished[w.Intent.ID] = true
			cleanup.DownloadJobs = refusedRetirementJobs{downloadCleanupJobs{f}, step}
			var logs []string
			cleanup.Report = func(s string) { logs = append(logs, s) }
			cleanup.CleanupProjectionWorkers(t.Context())
			want := "download-delete-proof"
			if step != "provider-private-detail" {
				want += "/" + step
			}
			if len(logs) != 1 || logs[0] != want || !f.charged[w.Intent.ID] {
				t.Fatal("retirement refusal leaked or released uncertain capacity", logs, f.charged)
			}
		})
	}
}
