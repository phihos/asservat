package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	value "asservat.local/asservat/internal/domain/capture"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Execute the real generated SQL calls against the existing output guard's
// counter semantics. This is ordering evidence, not a PostgreSQL rollback test.
type manualReservationBudget struct {
	executions, executionCalls, collectedCalls, windows, reservations, occurrences int
	bytes, limit                                                                   int64
}

func (b *manualReservationBudget) Exec(_ context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	switch {
	case strings.HasPrefix(query, "-- name: SpendPolicyExecution "):
		b.executionCalls++
		b.executions++
	case strings.HasPrefix(query, "-- name: SpendPolicyCollectedBytes "):
		b.collectedCalls++
		if !strings.Contains(query, "executions_spent>0") {
			return pgconn.CommandTag{}, errors.New("existing automatic output guard removed")
		}
		requested := args[0].(int64)
		if b.executions == 0 || requested > b.limit-b.bytes {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		b.bytes += requested
	case strings.HasPrefix(query, "-- name: UpdatePolicyWindow "):
		b.windows++
	case strings.HasPrefix(query, "-- name: InsertRecordingSaveReservation "):
		b.reservations++
	case strings.HasPrefix(query, "-- name: ReservePolicyOccurrenceOutput "):
		b.occurrences++
	default:
		return pgconn.CommandTag{}, errors.New("unexpected SQL call: " + query)
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}
func (*manualReservationBudget) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	panic("unexpected query")
}
func (*manualReservationBudget) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	panic("unexpected query row")
}

func TestManualPolicyFirstExecutionPrecedesExistingOutputGuard(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	a := value.Admission{}
	r := policyCaptureReservation{bytes: 64 << 10, manual: &manualPolicyReservation{acceptedAt: now, interval: time.Minute}}
	b := &manualReservationBudget{limit: 8 << 20}
	if err := r.spend(t.Context(), custodydb.New(b), "", "", a); err != nil {
		t.Fatal("first manual save has no detector Tick to spend execution", err)
	}
	if b.executions != 1 || b.executionCalls != 1 || b.bytes != r.bytes || b.collectedCalls != 1 || b.windows != 2 || b.reservations != 1 || b.occurrences != 0 {
		t.Fatal("manual save duplicated spend or invented occurrence", b)
	}
}
func TestAutomaticPolicyOutputUsesAlreadySpentExecution(t *testing.T) {
	r := policyCaptureReservation{bytes: 64 << 10}
	b := &manualReservationBudget{executions: 1, limit: 8 << 20}
	if err := r.spend(t.Context(), custodydb.New(b), "", "", value.Admission{}); err != nil {
		t.Fatal(err)
	}
	if b.executions != 1 || b.executionCalls != 0 || b.bytes != r.bytes || b.collectedCalls != 1 || b.windows != 0 || b.reservations != 0 || b.occurrences != 1 {
		t.Fatal("automatic Tick execution was spent twice or changed journals", b)
	}
}
func TestManualPolicyLaterOutputFailureAbortsSpend(t *testing.T) {
	r := policyCaptureReservation{bytes: 64 << 10, manual: &manualPolicyReservation{acceptedAt: time.Now().UTC(), interval: time.Minute}}
	b := &manualReservationBudget{limit: 0}
	if err := r.spend(t.Context(), custodydb.New(b), "", "", value.Admission{}); !errors.Is(err, value.ErrCapacity) {
		t.Fatal("exhausted output did not abort transaction", err)
	}
	if b.executionCalls != 1 || b.collectedCalls != 1 || b.bytes != 0 {
		t.Fatal("later output failure was not exercised", b)
	}
	// No commit or refund occurs here: the existing ledger transaction rolls
	// back the method's error. Real byte-exhaustion rollback is not qualified here.
}
