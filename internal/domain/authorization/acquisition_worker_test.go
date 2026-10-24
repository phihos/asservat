package authorization

import (
	"testing"
	"time"
)

func TestAcquisitionIdentityPreservesDownloadWorker(t *testing.T) {
	w := enrollmentWorkerFixture(t)
	a := w.Acquisition()
	if !a.Valid() || a.Intent.Parent != (AcquisitionParent{Purpose: AcquisitionDownload, ID: w.Intent.SessionID}) ||
		a.Intent.ID != w.Intent.ID || a.Intent.JobName() != w.Intent.JobName() || a.Job != w.Job ||
		!a.Intent.CreatedAt.Equal(w.Intent.CreatedAt) || !a.Intent.RunUntil.Equal(w.Intent.RunUntil) {
		t.Fatal("native worker identity changed", a)
	}
	for _, offset := range []time.Duration{0, 19 * time.Minute, 39 * time.Minute, 7*time.Hour + 59*time.Minute} {
		now := w.Intent.CreatedAt.Add(offset)
		gotEpoch, gotEnd, gotErr := a.CertificateEpoch(now)
		wantEpoch, wantEnd, wantErr := WorkerCertificateEpoch(w, now)
		if gotEpoch != wantEpoch || !gotEnd.Equal(wantEnd) || gotErr != wantErr {
			t.Fatal("original native signing interval changed", offset)
		}
	}
}

func TestAcquisitionProjectionHasNoDownloadParent(t *testing.T) {
	a := enrollmentWorkerFixture(t).Acquisition()
	a.Intent.Parent = AcquisitionParent{Purpose: AcquisitionProjection, ID: "20000000-0000-4000-8000-000000000002"}
	a.Binding.Parent = a.Intent.Parent
	a.Binding.Job = a.Intent.JobName()
	if !a.Valid() || a.Intent.Parent.Purpose == AcquisitionDownload {
		t.Fatal("approved worker needs a download parent")
	}
	for _, mutate := range []func(*AcquisitionWorker){
		func(w *AcquisitionWorker) { w.Binding.Parent.Purpose = AcquisitionDownload },
		func(w *AcquisitionWorker) { w.Binding.Parent.ID = "30000000-0000-4000-8000-000000000003" },
		func(w *AcquisitionWorker) {
			w.Intent.Parent.Purpose = "arbitrary-query"
			w.Binding.Parent = w.Intent.Parent
		},
		func(w *AcquisitionWorker) { w.Intent.Parent.ID = ""; w.Binding.Parent = w.Intent.Parent },
		func(w *AcquisitionWorker) { w.Binding.Job = "asservat-download-" + w.Intent.ID },
		func(w *AcquisitionWorker) { w.Intent.RunUntil = w.Intent.CreatedAt },
	} {
		bad := a
		mutate(&bad)
		if bad.Valid() {
			t.Fatal("substituted acquisition parent/identity accepted", bad)
		}
	}
}
