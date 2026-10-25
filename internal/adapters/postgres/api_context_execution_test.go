package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
)

func apiCompletedFixture(t *testing.T) (custodydb.ReadContextProgressFactsRow, value.APIExecution, custodydb.ContextExecution) {
	t.Helper()
	f := progressFactsFixture(t, "audited")
	a, err := admittedRecord(f.ContextCapture)
	if err != nil {
		t.Fatal(err)
	}
	e := a.Expectation
	e.ExecutionClass = artifact.ContextAPIExecution
	e.NodeUID = ""
	e.NodeBootID = ""
	e.PodUID = e.OccurrenceID
	e.NamespaceUID = e.CaptureUID
	e.WorkloadUID = e.CaseID
	f.ContextCapture.ExpectationJson, _ = json.Marshal(e)
	intent, err := captureIntent(f.ContextCapture)
	if err != nil {
		t.Fatal(err)
	}
	f.ContextCapture.IntentDigest = digest(intent)
	p := value.APIProcessBinding{InstallationID: uid(f.ContextCapture.RootID), ClusterID: e.Registration.Location.ClusterID, IssuerEpoch: uid(f.ContextCapture.PermissionEpoch), NamespaceUID: e.NamespaceUID, AccountUID: e.PodUID, PodUID: e.WorkloadUID, ProcessEpoch: e.CaseID, StartupDigest: artifact.Digest{1}, ImageDigest: e.CollectorImageDigest}
	b := value.Binding{ExecutionClass: artifact.ContextAPIExecution, ExecutorPodUID: p.PodUID, ExecutorAccountUID: p.AccountUID, OperationID: e.CaptureUID, CaptureID: e.CaptureUID, ActionID: e.ActionID, AttemptID: e.Registration.Location.AttemptID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PodUID: e.PodUID, CollectorEpoch: p.ProcessEpoch, ScopeDigest: e.PlanDigest, AuthorityDigest: artifact.Digest{1}, BudgetDigest: artifact.Digest{2}, AuditDigest: artifact.Digest{3}, NativeBytes: artifact.MaxContextBytes, NotBefore: f.ContextCapture.CreatedAt.Time.UTC(), NotAfter: f.ContextCapture.CreatedAt.Time.UTC().Add(5 * time.Second)}
	r := value.APIExecution{RootID: uid(f.ContextCapture.RootID), Binding: b, Process: p, ExpectationDigest: evidence.ContextExpectationDigest(e), ObjectUID: e.CaseID, Phase: "stored", StartedAt: b.NotBefore.Add(time.Second), AcquiredAt: b.NotBefore.Add(2 * time.Second), CompletedAt: b.NotBefore.Add(3 * time.Second)}
	for i := range r.Copies {
		r.Copies[i] = artifact.CopyReceipt{VersionID: "v1", ETag: "synthetic", Bytes: 100, SHA256: artifact.Digest{byte(i + 1)}}
	}
	if !validCompletedAPI(r, e) {
		t.Fatal("invalid completed fixture")
	}
	bj, _ := json.Marshal(b)
	pj, _ := json.Marshal(p)
	cj, _ := json.Marshal(r.Copies)
	row := custodydb.ContextExecution{RootID: f.ContextCapture.RootID, CaptureID: f.ContextCapture.ID, AttemptID: f.ContextCapture.AttemptID, BindingJson: bj, ProcessJson: pj, ExpectationDigest: r.ExpectationDigest[:], CreatedAt: f.ContextCapture.CreatedAt, NotBefore: ts(b.NotBefore), NotAfter: ts(b.NotAfter), ObjectUid: id(r.ObjectUID), Phase: r.Phase, StartedAt: ts(r.StartedAt), AcquiredAt: ts(r.AcquiredAt), CompletedAt: ts(r.CompletedAt), CopiesJson: cj, CopiesDigest: digest(r.Copies)}
	return f, r, row
}
func TestAPIExecutionStoredResultDecodingRejectsSubstitution(t *testing.T) {
	_, expected, row := apiCompletedFixture(t)
	got, err := apiExecution(row)
	if err != nil || app.APIExecutionDigest(got) != app.APIExecutionDigest(expected) {
		t.Fatal(got, err)
	}
	for name, change := range map[string]func(*custodydb.ContextExecution){"copies-digest": func(r *custodydb.ContextExecution) { r.CopiesDigest = digest("different") }, "capture": func(r *custodydb.ContextExecution) { r.CaptureID = r.AttemptID }, "interval": func(r *custodydb.ContextExecution) { r.NotAfter = ts(r.NotAfter.Time.Add(time.Second)) }, "unstarted-result": func(r *custodydb.ContextExecution) { r.StartedAt.Valid = false }, "late-acquisition": func(r *custodydb.ContextExecution) { r.AcquiredAt = r.NotAfter }} {
		t.Run(name, func(t *testing.T) {
			r := row
			change(&r)
			if _, err := apiExecution(r); err == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
}
func TestAPIVerificationAuditRequiresExactCompletedResult(t *testing.T) {
	f, r, _ := apiCompletedFixture(t)
	e, err := acceptedPublication(f.ContextCapture)
	if err != nil {
		t.Fatal(err)
	}
	ad := app.APIExecutionDigest(r)
	v := custodydb.ContextVerification{CaptureID: f.ContextCapture.ID, RootID: f.ContextCapture.RootID, VerifiedAt: ts(r.CompletedAt.Add(time.Second)), ExpectationDigest: digest(e), CopiesDigest: digest(r.Copies), IntentDigest: f.ContextCapture.IntentDigest, AuthorityDigest: ad[:], PermissionEpoch: f.ContextCapture.PermissionEpoch, PermissionSequence: 1}
	record, err := verificationRecord(f.ContextCapture, v, r)
	if err != nil || record.APIOutcome == nil || record.APIOutcome.StartObjectUID != r.ObjectUID || !record.Valid() {
		t.Fatal("completed provenance omitted", err)
	}
	if _, err = verificationRecord(f.ContextCapture, v); err == nil {
		t.Fatal("missing result accepted")
	}
	wrong := r
	wrong.Process.ProcessEpoch = e.OccurrenceID
	wrong.Binding.CollectorEpoch = wrong.Process.ProcessEpoch
	if _, err = verificationRecord(f.ContextCapture, v, wrong); err == nil {
		t.Fatal("other process outcome accepted")
	}
	wrong = r
	wrong.Copies[0].SHA256[0]++
	if _, err = verificationRecord(f.ContextCapture, v, wrong); err == nil {
		t.Fatal("other result accepted")
	}
	v.VerifiedAt = ts(r.AcquiredAt)
	if _, err = verificationRecord(f.ContextCapture, v, r); err == nil {
		t.Fatal("verification predates completed result")
	}
}
func TestAPIExecutionProgressUsesItsDurableOutcome(t *testing.T) {
	f, r, _ := apiCompletedFixture(t)
	for _, tc := range []struct{ state, phase, reason string }{{"prepared", "Pending", "DispatchUnconfirmed"}, {"started", "Running", "AcquisitionStarted"}, {"captureFailed", "Failed", "AcquisitionFailed"}, {"targetGone", "Failed", "PinnedPodGone"}, {"denied", "Failed", "PodStatusDenied"}, {"storeUnconfirmed", "Indeterminate", "StorageOutcomeUnconfirmed"}, {"stored", "Finalizing", "VerificationPending"}} {
		t.Run(tc.state, func(t *testing.T) {
			x := r
			x.Phase = tc.state
			if tc.state != "stored" {
				x.Copies = artifact.Copies{}
			}
			if tc.state == "prepared" {
				x.ObjectUID = ""
				x.StartedAt = time.Time{}
			}
			if tc.state == "started" || tc.state == "prepared" {
				x.AcquiredAt = time.Time{}
				x.CompletedAt = time.Time{}
			}
			if tc.state == "captureFailed" || tc.state == "targetGone" || tc.state == "denied" {
				x.AcquiredAt = time.Time{}
			}
			out, err := progressFacts(f, x)
			if err != nil || out.Phase != tc.phase || out.ReasonCode != tc.reason {
				t.Fatal(out, err)
			}
		})
	}
}

// A start whose outcome never reaches SQL (for example a lost regional
// completion reply) stays Running until the deadline observer marks it; it
// then reports Indeterminate rather than an inferred failure or success.
func TestAPIExecutionUnrecordedOutcomeEndsIndeterminateAfterDeadline(t *testing.T) {
	f, r, _ := apiCompletedFixture(t)
	for _, phase := range []string{"prepared", "started"} {
		t.Run(phase, func(t *testing.T) {
			x := r
			x.Phase, x.Copies, x.AcquiredAt, x.CompletedAt = phase, artifact.Copies{}, time.Time{}, time.Time{}
			if phase == "prepared" {
				x.ObjectUID, x.StartedAt = "", time.Time{}
			}
			g := f
			g.ContextCapture.DeadlineObservedAt = ts(g.ContextCapture.Deadline.Time.Add(time.Second))
			out, err := progressFacts(g, x)
			if err != nil || out.Phase != "Indeterminate" || out.ActionPhase != "Indeterminate" || out.ReasonCode != "DeadlineOutcomeUnconfirmed" {
				t.Fatal(out, err)
			}
		})
	}
	x := r
	x.Phase = "unknown"
	if _, err := progressFacts(f, x); err == nil {
		t.Fatal("unknown execution phase projected")
	}
}
