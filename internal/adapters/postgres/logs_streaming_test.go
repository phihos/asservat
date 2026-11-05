package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type logsStreamBindingDB struct {
	row          custodydb.CustodyStream
	reads, binds int
}

func (d *logsStreamBindingDB) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if !strings.HasPrefix(sql, "-- name: LockStream ") {
		panic("unexpected stream lookup")
	}
	d.reads++
	return admittedIdentityRow{value: d.row}
}
func (*logsStreamBindingDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	panic("unexpected stream query")
}
func (d *logsStreamBindingDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if !strings.HasPrefix(sql, "-- name: BindPendingStream ") || args[0].(pgtype.UUID) != d.row.AttemptID || d.row.WriterEpoch.Valid || len(d.row.PlanDigest) > 0 {
		return pgconn.NewCommandTag("UPDATE 0"), nil
	}
	d.row.WriterEpoch = args[1].(pgtype.UUID)
	d.row.PlanDigest = append([]byte(nil), args[2].([]byte)...)
	d.binds++
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

// The existing generated SQL and actual binding helper must bind a pending
// multipart obligation before a logs writer can use its process-owned journal.
// This exercises adapter effects, not PostgreSQL role/rollback qualification.
func TestLogsStreamBindsOriginalProcessBeforeOneShotWriter(t *testing.T) {
	var e artifact.ContextExpectation
	if err := json.Unmarshal(progressFactsFixture(t, "pending").ContextCapture.ExpectationJson, &e); err != nil {
		t.Fatal(err)
	}
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextAPIExecution, "", ""
	e.NativeType, e.DataClass, e.ActionID = artifact.LogsArtifact, "raw", "a111111111111111111111111"
	e.Registration.NativeLimit = artifact.LogNativeLimit
	e.Logs = &artifact.LogCapture{ActionID: e.ActionID, BeforeMillis: 10000, TimeoutMillis: 10000, Streams: "combined", MaxNativeBytes: artifact.LogNativeLimit, Composition: []byte("{}")}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	epoch := "10000000-0000-4000-8000-000000000001"
	plan := artifact.StreamingPlan{Registration: normalized(e.Registration), WriterEpoch: epoch}
	pending := custodydb.CustodyStream{AttemptID: id(e.Registration.Location.AttemptID), TemporaryBytes: plan.TemporaryBytes(), TemporaryObjects: int64(1 + plan.PartLimit()), State: []byte("{}"), Revision: 1}
	db := &logsStreamBindingDB{row: pending}
	if err := bindProfileStreamLocked(t.Context(), custodydb.New(db), e, epoch, true); err != nil || db.reads != 1 || db.binds != 1 {
		t.Fatal("logs skipped durable pending stream binding", err, db.reads, db.binds)
	}
	if err := bindProfileStreamLocked(t.Context(), custodydb.New(db), e, epoch, false); err != nil || db.binds != 1 {
		t.Fatal("replay rebound/refilled stream", err, db.binds)
	}
	other := "10000000-0000-4000-8000-000000000002"
	if err := bindProfileStreamLocked(t.Context(), custodydb.New(db), e, other, true); !errors.Is(err, privacy.ErrConflict) {
		t.Fatal("replacement writer adopted stream", err)
	}
	db.row = pending
	if err := bindProfileStreamLocked(t.Context(), custodydb.New(db), e, epoch, false); !errors.Is(err, privacy.ErrConflict) {
		t.Fatal("replay created missing original binding", err)
	}
	db.row = pending
	db.row.TemporaryBytes--
	if err := bindProfileStreamLocked(t.Context(), custodydb.New(db), e, epoch, true); !errors.Is(err, privacy.ErrConflict) {
		t.Fatal("underfunded stream bound", err)
	}
	db.row = pending
	db.row.ReleasedAt = ts(e.Registration.AnchorAt)
	if err := bindProfileStreamLocked(t.Context(), custodydb.New(db), e, epoch, true); !errors.Is(err, privacy.ErrConflict) {
		t.Fatal("released obligation reused", err)
	}
	e.Registration.NativeLimit = artifact.FrameBytes
	e.Logs.MaxNativeBytes = artifact.FrameBytes
	db.reads = 0
	if err := bindProfileStreamLocked(t.Context(), custodydb.New(db), e, epoch, true); err != nil || db.reads != 0 {
		t.Fatal("single frame acquired multipart state", err, db.reads)
	}
}
