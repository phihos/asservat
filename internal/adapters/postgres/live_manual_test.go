package postgres

import (
	"encoding/json"
	"errors"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/targets"
)

func liveManualMatchFixture(t *testing.T) (app.APIContextWork, value.APIExecution, time.Time) {
	t.Helper()
	f, r, _ := apiCompletedFixture(t)
	var e artifact.ContextExpectation
	if err := json.Unmarshal(f.ContextCapture.ExpectationJson, &e); err != nil {
		t.Fatal(err)
	}
	e.NativeType, e.DataClass, e.ActionID = artifact.PCAPNGArtifact, "metadata", "a111111111111111111111111"
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	e.Recording = &artifact.Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: []byte(`{}`), DurationMillis: 10000, MaxBytes: 64 << 10, Snaplen: 134}
	if err := e.Validate(); err != nil {
		t.Fatal("finite metadata expectation", err)
	}
	r.Phase = "started"
	r.AcquiredAt, r.CompletedAt, r.Copies = time.Time{}, time.Time{}, artifact.Copies{}
	r.Binding.ActionID, r.Binding.NativeBytes = e.ActionID, e.Registration.NativeLimit
	r.Binding.AuditDigest = artifact.Digest{19}
	r.ExpectationDigest = evidence.ContextExpectationDigest(e)
	w := app.APIContextWork{Actor: previewTestValue(t).Actor, IntentDigest: r.Binding.AuditDigest,
		Accepted: capture.Accepted{CaptureID: e.CaptureUID, State: capture.IntentAudited, Expectation: e, ScopeDigest: e.PlanDigest, Deadline: f.ContextCapture.Deadline.Time},
		Target:   targets.Request{ClusterID: e.Registration.Location.ClusterID, Namespace: previewTestValue(t).Target.Namespace, Workload: previewTestValue(t).Target.Workload, PodUID: e.PodUID}}
	w.Target.Namespace.UID, w.Target.Workload.UID = e.NamespaceUID, e.WorkloadUID
	// The regional preparation's original five seconds have ended while this
	// accepted ten-second source can still be held by its actual node. The SQL
	// provenance matcher must not mistake preparation expiry for source end.
	now := r.Binding.NotAfter.Add(time.Second)
	if !r.Valid() || !liveManualMatches(w, r, now) {
		t.Fatal("original started finite metadata fixture refused")
	}
	return w, r, now
}

func TestLiveManualMatchesOriginalFiniteExecutionWithoutInventedSession(t *testing.T) {
	w, r, now := liveManualMatchFixture(t)
	for name, change := range map[string]func(*app.APIContextWork, *value.APIExecution){
		"pending-intent": func(w *app.APIContextWork, _ *value.APIExecution) { w.Accepted.State = capture.PendingAudit },
		"requested-stop": func(w *app.APIContextWork, _ *value.APIExecution) { w.CancellationRequested = true },
		"policy-executor": func(w *app.APIContextWork, _ *value.APIExecution) {
			w.Actor = authorization.PolicyPrincipal(r.RootID, "source")
		},
		"capture":               func(_ *app.APIContextWork, r *value.APIExecution) { r.Binding.CaptureID = r.Binding.AttemptID },
		"action":                func(_ *app.APIContextWork, r *value.APIExecution) { r.Binding.ActionID = "other" },
		"attempt":               func(_ *app.APIContextWork, r *value.APIExecution) { r.Binding.AttemptID = r.Binding.CaptureID },
		"target":                func(w *app.APIContextWork, _ *value.APIExecution) { w.Target.PodUID = r.RootID },
		"scope":                 func(_ *app.APIContextWork, r *value.APIExecution) { r.Binding.ScopeDigest[0]++ },
		"intent":                func(_ *app.APIContextWork, r *value.APIExecution) { r.Binding.AuditDigest[0]++ },
		"expectation":           func(_ *app.APIContextWork, r *value.APIExecution) { r.ExpectationDigest[0]++ },
		"capacity":              func(_ *app.APIContextWork, r *value.APIExecution) { r.Binding.NativeBytes-- },
		"future-start":          func(_ *app.APIContextWork, r *value.APIExecution) { r.StartedAt = now.Add(time.Second) },
		"original-accepted-end": func(w *app.APIContextWork, _ *value.APIExecution) { w.Accepted.Deadline = now },
		"original-write-end": func(w *app.APIContextWork, _ *value.APIExecution) {
			w.Accepted.Expectation.Registration.WriteUntil = now
		},
		"profile": func(w *app.APIContextWork, _ *value.APIExecution) {
			w.Accepted.Expectation.Profile = &artifact.GoProfileAcquisition{}
		},
		"logs": func(w *app.APIContextWork, _ *value.APIExecution) {
			w.Accepted.Expectation.Logs = &artifact.LogCapture{}
		},
		"saved-snapshot": func(w *app.APIContextWork, _ *value.APIExecution) {
			w.Accepted.Expectation.Snapshot = &artifact.SourceSnapshotRequest{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed, execution := w, r
			change(&changed, &execution)
			if liveManualMatches(changed, execution, now) {
				t.Fatal("replacement, cancelled, unsupported or ended finite execution accepted")
			}
		})
	}
}

func TestLiveManualBatchRejectsDuplicateOrUnboundedCaptureIDs(t *testing.T) {
	id := "10000000-0000-4000-8000-000000000001"
	if ids, ok := liveManualIDs([]string{id}); !ok || len(ids) != 1 {
		t.Fatal("bounded original capture refused")
	}
	for _, input := range [][]string{nil, {id, id}, {"not-a-capture"}, make([]string, 17)} {
		if _, ok := liveManualIDs(input); ok {
			t.Fatal("duplicate/malformed/unbounded capture query accepted")
		}
	}
}

func TestLiveManualKnownEndedSessionIsOmittedWithoutPoisoningInventory(t *testing.T) {
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	until := at.Add(5 * time.Second)
	for _, field := range []string{"session", "lease"} {
		for _, delta := range []time.Duration{-time.Microsecond, 0, time.Microsecond} {
			t.Run(field+delta.String(), func(t *testing.T) {
				row := custodydb.PolicyObservationSession{SessionUntil: ts(until), LeaseUntil: ts(until)}
				if field == "session" {
					row.SessionUntil = ts(at.Add(delta))
				} else {
					row.LeaseUntil = ts(at.Add(delta))
				}
				got, err := liveManualObservationUntil(row, at, until)
				if delta <= 0 {
					if !errors.Is(err, value.ErrDenied) {
						t.Fatal("known-ended original source would poison the whole inventory instead of being omitted", err)
					}
				} else if err != nil || !got.Equal(at.Add(delta)) {
					t.Fatal("live original end renewed or rejected", got, err)
				}
			})
		}
	}
}
