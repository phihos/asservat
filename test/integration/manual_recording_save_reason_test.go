//go:build cgo && libpcap

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	captureapp "asservat.local/asservat/internal/application/capture"
	planningapp "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

func TestManualRecordingSaveReasonWithRealServices(t *testing.T) {
	qualifySourceSnapshotServices(t, true, false, false, true)
}

// Short preview/admission profile for the reason fixture.
func configureManualReasonCapacity(f *capacitySQLFixture) {
	f.qualification.RootBacking.AdmissionSeconds = 300
}

type reasonFixtureIdentity struct{ who identity.Identity }

func (i reasonFixtureIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return i.who, ctx.Err()
}

// ADR-330 D8: the reason is plain SQL data on the preview blueprint and the
// accepted capture row. Admission copies it in the same transaction as the
// capture's audit_event row; status reads it back after current authorization.
func qualifyManualRecordingSaveReason(t *testing.T, ctx context.Context, f *capacitySQLFixture, admissions *postgres.ContextAdmissions, policy policySourceAcceptedFixture, source captureapp.PolicySourceAdmission, fresh captureapp.PolicySourceCheck, intents captureapp.ContextAcceptedIntents) {
	t.Helper()
	before := readManualSaveCounters(t, ctx, f, policy)
	snapshot := prepareManualRecordingSaveFixture(t, ctx, f.roles["hub-runtime"], policy, source, fresh, 64<<10)
	a, p := snapshot.Admission, snapshot.Preview
	scope := bytes.Clone(p.CanonicalScope)
	scopeDigest := p.ScopeDigest
	// 512 Unicode scalars, including whitespace/newline which must not normalize.
	reason := " \n\t" + strings.Repeat("🙂", 509)
	p.Intent.Reason = &reason
	// A tighter selection lifetime proves accepted work survives selection expiry.
	p.SelectionUntil = p.CreatedAt.Add(time.Second)
	if !captureapp.ValidContextPreview(p) || !bytes.Equal(p.CanonicalScope, scope) || p.ScopeDigest != scopeDigest {
		t.Fatal("reason changed reviewed collection scope")
	}
	accepted, err := admissions.AdmitReviewedContext(ctx, p, a)
	if err != nil {
		t.Fatal("actual reason admission", err)
	}
	var stored string
	var audits int
	if err = f.admin.QueryRow(ctx, `SELECT c.reason,(SELECT count(*) FROM audit_event e WHERE e.operation_id=c.id AND e.kind='capture.start') FROM context_capture c WHERE c.root_id=$1 AND c.id=$2`, a.RootID, accepted.CaptureID).Scan(&stored, &audits); err != nil || stored != reason || audits != 1 {
		t.Fatal("admission did not store reason with its audit row", err, audits)
	}
	if _, err = f.admin.Exec(ctx, `UPDATE context_capture SET reason='changed' WHERE root_id=$1 AND id=$2`, a.RootID, accepted.CaptureID); capacitySQLState(err) != "23514" {
		t.Fatal("accepted reason mutable", err)
	}
	after := readManualSaveCounters(t, ctx, f, policy)
	if after.Executions != before.Executions+1 || after.Reservations != before.Reservations+1 || after.Observed != before.Observed || after.Shares != before.Shares {
		t.Fatal("descriptive reason changed resource/grant units")
	}
	snapshot.Accepted = accepted
	snapshot.Admission.Plan, snapshot.Admission.Registration, err = planningapp.ReanchorRecordingSave(a.Plan, a.Registration, accepted.CreatedAt, policy.Authority.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Preview = p
	draft, err := captureapp.HistoryDraftFromPreview(p, accepted)
	if err != nil || draft.RecordingSave == nil {
		t.Fatal("reason-free fresh-selection repeat settings", err)
	}
	draftBytes, err := json.Marshal(draft)
	if err != nil || bytes.Contains(draftBytes, []byte("Reason")) || bytes.Contains(draftBytes, []byte(reason)) {
		t.Fatal("repeat restored reason", err)
	}
	// Expire selection before native start without changing acquisition dates.
	waitReasonFixtureUntil(t, ctx, f, p.SelectionUntil.Add(time.Millisecond))
	t.Run("native-after-selection-expiry", func(t *testing.T) { qualifySourceSnapshotCompletion(t, ctx, f, policy, snapshot, intents) })
	f.refreshBase(t)
	replayIdentity := snapshot.Admission.RecordingSave.Initiator.VerifiedIdentity
	replayIdentity.VerifiedAt = time.Now().UTC().Truncate(time.Microsecond)
	replayIdentity.ValidUntil = replayIdentity.VerifiedAt.Add(5 * time.Second)
	replay, found, err := admissions.LookupContextAdmission(ctx, value.ReplayQuery{RootID: a.RootID, PreviewID: p.ID, IdempotencyKey: a.IdempotencyKey, SubmissionDigest: a.SubmissionDigest, Identity: replayIdentity})
	if err != nil || !found || replay.CaptureID != accepted.CaptureID || !replay.CreatedAt.Equal(accepted.CreatedAt) || readManualSaveCounters(t, ctx, f, policy) != after {
		t.Fatal("accepted replay depended on expired preview or changed spend", err)
	}
	qualifyReasonProgress(t, ctx, f, policy, snapshot, reason)
}

// Waits against actual UTC while maintaining the fixture's existing source
// observations. It never edits original source or capacity deadlines.
func waitReasonFixtureUntil(t *testing.T, ctx context.Context, f *capacitySQLFixture, until time.Time) {
	t.Helper()
	for time.Now().Before(until) {
		wait := min(time.Second, time.Until(until))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		f.refreshBase(t)
	}
}

func qualifyReasonProgress(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, snapshot policySourceSnapshotAdmissionFixture, reason string) {
	t.Helper()
	root := snapshot.Admission.RootID
	reader, err := postgres.NewContextProgressReads(ctx, f.roles["hub-runtime"], root)
	if err != nil {
		t.Fatal(err)
	}
	service := captureapp.ContextProgressService{RootID: root, InstallationID: policy.Authority.InstallationID, Reader: reader, Now: time.Now}
	current := func() reasonFixtureIdentity {
		f.refreshBase(t)
		who := snapshot.Admission.RecordingSave.Initiator.VerifiedIdentity
		who.VerifiedAt = time.Now().UTC().Truncate(time.Microsecond)
		who.ValidUntil = who.VerifiedAt.Add(5 * time.Second)
		return reasonFixtureIdentity{who}
	}
	t.Run("current-authorized-reason", func(t *testing.T) {
		p, err := service.Get(ctx, current(), snapshot.Accepted.CaptureID)
		if err != nil || p.Reason == nil || *p.Reason != reason || p.ReasonState != "available" {
			t.Fatal("authorized reason lost", p.ReasonState, err)
		}
		denied := current()
		denied.who.Groups = []string{"no-current-workload-rights"}
		if p, err = service.Get(ctx, denied, snapshot.Accepted.CaptureID); err == nil || p.Reason != nil {
			t.Fatal("denied status returned the reason")
		}
	})
}
