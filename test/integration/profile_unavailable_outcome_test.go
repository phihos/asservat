package integration

import (
	"context"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	execution "asservat.local/asservat/internal/domain/execution"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Uses the actual approved profile admission, SQL start and original process.
// Missing-endpoint observation is synthetic here; the native suite supplies it.
func qualifyProfileUnavailableOutcome(t *testing.T, ctx context.Context, admin, readerPool *pgxpool.Pool, s captureAdmissionScenario, executions *postgres.APIContextExecutions, running execution.APIExecution, check executionapp.APIExecutionCheck, reserved int64, grantID string) {
	t.Helper()
	terminal := running
	terminal.Phase, terminal.CompletedAt = "profileUnavailable", time.Now().UTC().Truncate(time.Microsecond)
	terminal.AcquiredAt, terminal.Copies = time.Time{}, artifact.Copies{}
	for name, change := range map[string]func(*execution.APIExecution){
		"copies":   func(r *execution.APIExecution) { r.Copies[0].Bytes = 1 },
		"acquired": func(r *execution.APIExecution) { r.AcquiredAt = r.StartedAt },
	} {
		bad := terminal
		change(&bad)
		if _, err := executions.RecordAPIOutcome(ctx, bad, check.Process); err == nil {
			t.Fatal("profile refusal accepted acquisition evidence", name)
		}
	}
	got, err := executions.RecordAPIOutcome(ctx, terminal, check.Process)
	if err != nil || !reflect.DeepEqual(got, terminal) {
		t.Fatal("profile-unavailable terminal SQL transition", err)
	}
	if replay, err := executions.RecordAPIOutcome(ctx, terminal, check.Process); err != nil || !reflect.DeepEqual(replay, got) {
		t.Fatal("same refusal replay changed execution", err)
	}
	changed := terminal
	changed.Phase = "profilerBusy"
	if _, err := executions.RecordAPIOutcome(ctx, changed, check.Process); err == nil {
		t.Fatal("terminal refusal rewritten through adapter")
	}
	if _, err := admin.Exec(ctx, "UPDATE context_execution SET phase='started',completed_at=NULL WHERE root_id=$1 AND capture_id=$2", s.a.RootID, running.Binding.CaptureID); err == nil {
		t.Fatal("terminal refusal reset through SQL")
	}
	progress, err := postgres.NewContextProgressReads(ctx, readerPool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := progress.ReadContextProgress(ctx, progressQuery(t, ctx, s))
	if err != nil || result.Phase != "Failed" || result.ActionPhase != "Failed" || result.ReasonCode != "ProfileUnavailable" {
		t.Fatal("profile refusal lost from actual authorized SQL progress", result, err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	cancelled, err := executions.RequestCaptureCancellation(ctx, capture.CancellationCheck{RootID: s.a.RootID, Request: capture.CancellationRequest{CaptureID: running.Binding.CaptureID, ExpectedRevision: result.Revision, IdempotencyKey: "already-unavailable"}, Identity: check.Eligibility.VerifiedIdentity, CheckedAt: now, ValidUntil: check.ValidUntil})
	if err != nil || cancelled.Decision.Phase != "Failed" || cancelled.Decision.Requested || cancelled.Profile != nil {
		t.Fatal("terminal endpoint refusal opened new cancellation work", cancelled.Decision, err)
	}
	var empty bool
	var charged int64
	if err := admin.QueryRow(ctx, `SELECT
 NOT EXISTS(SELECT 1 FROM context_verification WHERE capture_id=$1)
 AND NOT EXISTS(SELECT 1 FROM context_catalog WHERE capture_id=$1)
 AND NOT EXISTS(SELECT 1 FROM context_writer_completion WHERE capture_id=$1)
 AND NOT EXISTS(SELECT 1 FROM custody_copy WHERE attempt_id=$2 AND ciphertext_bytes IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM policy_observation_session WHERE capture_id=$1),
 charged_bytes FROM custody_allocation WHERE id=$3`, running.Binding.CaptureID, running.Binding.AttemptID, s.a.Registration.AllocationID).Scan(&empty, &charged); err != nil || !empty || charged != reserved {
		t.Fatal("refusal created evidence or changed conservative reservation", empty, charged, reserved, err)
	}
	installedProfileRefusalSQLCheck(t, ctx, admin, s.a.RootID)(running.Binding.CaptureID, grantID, "ProfileUnavailable")
	t.Log("actual approved profile SQL: profileUnavailable terminal/replay/immutable, Failed/ProfileUnavailable; no copies/publication/observation and original reservations retained; endpoint observation synthetic")
}
