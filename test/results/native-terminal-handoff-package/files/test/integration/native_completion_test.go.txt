package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	value "asservat.local/asservat/internal/domain/authorization"
)

// These negative tests inspect the existing real SQL owner and activated
// certificate as fixture administrator. They create no operation, certificate,
// authority or additional allowance. Positive completion is exercised by the
// normal Prepare/Observe/content conversations through the production adapter.
func nativeCompletionSnapshot(t *testing.T, ctx context.Context, f nativeExchangeFixture) (value.NativeLease, bool, [5]int64) {
	t.Helper()
	var l value.NativeLease
	var encoded, certificate []byte
	var closed bool
	var charged [5]int64
	if e := f.admin.QueryRow(ctx, `SELECT operation_json,lease_sequence,lease_started,lease_until,closed,updates,
 (SELECT count(*) FROM download_response WHERE session_id=$2),
 (SELECT reserved_responses FROM download_control_allocation WHERE id=$3),
 (SELECT reserved_windows FROM download_control_allocation WHERE id=$3),
 (SELECT coalesce(sum(used_roles),0) FROM download_native_key WHERE worker_id=$1)
 FROM download_native_owner WHERE worker_id=$1`, f.worker.Intent.ID, f.worker.Intent.SessionID, f.allocation.ID).Scan(&encoded, &l.Sequence, &l.ObservedAt, &l.Until, &closed, &charged[0], &charged[1], &charged[2], &charged[3], &charged[4]); e != nil {
		t.Fatal("completion owner snapshot", e)
	}
	if e := json.Unmarshal(encoded, &l.Operation); e != nil {
		t.Fatal("completion operation snapshot", e)
	}
	if e := f.admin.QueryRow(ctx, `SELECT certificate_sha256 FROM download_worker_certificate WHERE worker_id=$1 AND activated_at IS NOT NULL`, f.worker.Intent.ID).Scan(&certificate); e != nil || len(certificate) != len(l.Certificate) {
		t.Fatal("completion activated certificate snapshot", e)
	}
	copy(l.Certificate[:], certificate)
	return l, closed, charged
}

func qualifyNativeCompletionClosed(t *testing.T, ctx context.Context, f nativeExchangeFixture, owners *postgres.FirstContextNativeOperations) {
	t.Helper()
	l, closed, before := nativeCompletionSnapshot(t, ctx, f)
	if !closed || !l.Valid(time.Now()) || !l.Operation.CurrentValid(time.Now()) {
		t.Fatal("completed preparation must still have its original current interval for closed-state test")
	}
	if e := owners.CompleteNativeOperation(ctx, l); e == nil {
		t.Fatal("already-closed operation fabricated positive completion")
	}
	if !l.Valid(time.Now()) || !l.Operation.CurrentValid(time.Now()) {
		t.Fatal("closed-state rejection was obscured by original expiry")
	}
	_, closed, after := nativeCompletionSnapshot(t, ctx, f)
	if !closed || after != before {
		t.Fatal("already-closed completion changed retained spend")
	}
	t.Log("already-closed exact native operation denied within original current lease, charges unchanged")
}

func qualifyNativeCompletionHeld(t *testing.T, ctx context.Context, f nativeExchangeFixture, owners *postgres.FirstContextNativeOperations, expected value.NativeOperation) {
	t.Helper()
	l, closed, before := nativeCompletionSnapshot(t, ctx, f)
	if closed || !l.Operation.Equal(expected) || !l.Valid(time.Now()) || !l.Operation.CurrentValid(time.Now()) {
		t.Fatal("completion test requires exact original current open operation")
	}
	wrong := l
	wrong.Operation.Reference.Fence++
	if e := owners.CompleteNativeOperation(ctx, wrong); e == nil {
		t.Fatal("wrong generation completed current native owner")
	}
	wrong = l
	wrong.Sequence++
	if e := owners.CompleteNativeOperation(ctx, wrong); e == nil {
		t.Fatal("wrong sequence completed current native owner")
	}
	if !l.Valid(time.Now()) || !l.Operation.CurrentValid(time.Now()) {
		t.Fatal("generation/sequence rejection was obscured by original expiry")
	}
	tx, e := f.admin.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT worker_id FROM download_native_owner WHERE worker_id=$1 FOR UPDATE", expected.Reference.WorkerID); e != nil {
		t.Fatal(e)
	}
	call, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- owners.CompleteNativeOperation(call, l) }()
	waited := false
	for call.Err() == nil {
		if e = f.admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename='native_owner_runtime' AND wait_event_type='Lock')").Scan(&waited); e != nil {
			cancel()
			<-done
			t.Fatal(e)
		}
		if waited {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if e = <-done; e == nil || !waited {
		t.Fatal("held-row completion did not expire under the original caller bound", waited, e)
	}
	if e = tx.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	actual, closed, after := nativeCompletionSnapshot(t, ctx, f)
	if closed || !actual.Operation.Equal(expected) || after != before {
		t.Fatal("denied completion changed owner or retained spend")
	}
	t.Log("wrong fence/sequence and held-row original-deadline completion denied, owner and charges unchanged")
}
