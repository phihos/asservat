package postgres

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"testing"
	"time"
)

// A failed/unknown attempted response can have both local SQL owners closed.
// Those closes join local I/O only; they cannot revive the stopped remote worker
// or turn the retained uncertainty into metadata-observation admission.
func TestFirstContextClosedLocalOwnersDoNotClearUncertainResponse(t *testing.T) {
	c := contextNativeControl{remaining: 32, uncertain: true}
	if c.canObserve() {
		t.Fatal("closed local owners admitted another native observation despite retained failed/unknown output")
	}
	if c.canRespond() {
		t.Fatal("failed response permitted another content admission")
	}
	c.uncertain = false
	if !c.canObserve() {
		t.Fatal("known eligible bounded retry denied")
	}
}

func TestFirstContextRetryRequiresExactIndependentSuccessfulOutcome(t *testing.T) {
	n := time.Now().UTC()
	id := "10000000-0000-4000-8000-000000000001"
	a := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}}, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{2}, DecisionDigest: artifact.Digest{3}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: artifact.Digest{4}}, CheckedAt: n, ValidUntil: n.Add(5 * time.Second), AccessUntil: n.Add(time.Hour)}
	r := artifact.DownloadResponse{ID: id, SessionID: id, OwnerID: id, Generation: 2, Plan: artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Offset: 1, Length: 16, Partial: true}, WindowReadLimit: 4 << 20}, StartedAt: n, Until: n.Add(time.Minute), WindowCount: 1, CompletedWindows: 1, EmittedBytes: 16, Closed: true}
	w := artifact.DownloadWindow{ID: id, ResponseID: id, SessionID: id, OwnerID: id, AuditStoreID: id, Generation: 2, Ordinal: 1, Offset: 1, Length: 16, ReadLimit: 4 << 20, StartedAt: n, WriteUntil: n.Add(time.Minute), Authority: a, IntentAcknowledged: true, OutcomeAcknowledged: true, Outcome: &artifact.DownloadWindowOutcome{EmittedBytes: 16, Success: true, VerifiedFinal: true, RecordedAt: n}}
	if !firstContextResponseOutcome(r, []artifact.DownloadWindow{w}) {
		t.Fatal("qualified partial retry rejected")
	}
	for _, test := range []struct {
		name   string
		change func(*artifact.DownloadWindow)
	}{
		{"missing outcome", func(w *artifact.DownloadWindow) { w.Outcome = nil; w.OutcomeAcknowledged = false }},
		{"unknown audit", func(w *artifact.DownloadWindow) { w.OutcomeAcknowledged = false }},
		{"failed full write", func(w *artifact.DownloadWindow) { w.Outcome.Success = false; w.Outcome.VerifiedFinal = false }},
		{"unverified final", func(w *artifact.DownloadWindow) { w.Outcome.VerifiedFinal = false }},
		{"partial write", func(w *artifact.DownloadWindow) {
			w.Outcome.Success = false
			w.Outcome.VerifiedFinal = false
			w.Outcome.EmittedBytes = 8
		}},
		{"different response", func(w *artifact.DownloadWindow) { w.ResponseID = "10000000-0000-4000-8000-000000000002" }},
		{"different owner", func(w *artifact.DownloadWindow) { w.OwnerID = "10000000-0000-4000-8000-000000000002" }},
		{"different generation", func(w *artifact.DownloadWindow) { w.Generation++ }},
		{"different range", func(w *artifact.DownloadWindow) { w.Offset++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := w
			out := *w.Outcome
			candidate.Outcome = &out
			test.change(&candidate)
			if firstContextResponseOutcome(r, []artifact.DownloadWindow{candidate}) {
				t.Fatal("closed local owners certified unknown/foreign output")
			}
		})
	}
	for _, windows := range [][]artifact.DownloadWindow{nil, {w, w}} {
		if firstContextResponseOutcome(r, windows) {
			t.Fatal("missing/multiple window history permitted retry")
		}
	}
	r.CompletedWindows = 0
	if firstContextResponseOutcome(r, []artifact.DownloadWindow{w}) {
		t.Fatal("uncommitted response outcome permitted retry")
	}
}
