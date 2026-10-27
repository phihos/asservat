package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Fixture-only observations, never authority. Identifiers and operation JSON
// stay in private samples; only comparisons/counts/times enter the report.
// One consumer calls Write serially. There are no observers, timers or retries.
type nativePacingOwnerObserver struct {
	ctx                                        context.Context
	admin                                      *pgxpool.Pool
	root, download                             string
	destination                                io.Writer
	first, renewed                             *nativePacingOwnerSample
	firstAttempted, renewalAttempted, finished bool
	err                                        error
	reads                                      int64
	readDuration                               time.Duration
	now                                        func() time.Time
	// A pure seam for validation tests; production fixtures use readSQL below.
	read func(context.Context, *nativePacingOwnerSample) (nativePacingOwnerSample, error)
}

type nativePacingOwnerReport struct {
	SameOwner, SameWindow, OriginalDeadlineUnchanged, Renewed              bool
	FinalOutcomeAcknowledged, ResponseClosed, OwnerClosed                  bool
	FirstObservedAt, RenewedObservedAt, FinalObservedAt                    time.Time
	OriginalStartedAt, OriginalUntil, InitialLeaseUntil, RenewedLeaseUntil time.Time
	InitialSequence, RenewedSequence, NativeKeyRows, ConsumedKeySlots      int64
	// Admin proof reads are excluded from runtime-role/KMS counter attribution.
	ProofSQLReads    int64
	ProofSQLDuration time.Duration
}

type nativePacingOwnerSample struct {
	observed, leaseStarted, leaseUntil, responseUntil                      time.Time
	worker, operation, response, window                                    string
	fence, sequence, responseSequence, generation, ordinal                 int64
	reservedWindows, windowCount, keyRows, usedRoles                       int64
	operationJSON                                                          []byte
	ownerClosed, retired, responseClosed, activeWindow                     bool
	intentAcknowledged, outcomeAcknowledged, outcomeSuccess, verifiedFinal bool
}

type nativePacingOwnerOperation struct {
	Reference struct {
		SessionID, WorkerID, OperationID string
		Fence                            int64
	}
	Kind, ParentID   string
	Generation       int64
	StartedAt, Until time.Time
}

func newNativePacingOwnerObserver(ctx context.Context, admin *pgxpool.Pool, root, download string, destination io.Writer) (*nativePacingOwnerObserver, error) {
	if ctx == nil || ctx.Err() != nil || admin == nil || !authorization.UUID(root) || !authorization.UUID(download) || destination == nil {
		return nil, errors.New("native owner measurement input unavailable")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, errors.New("native owner measurement requires original bounded context")
	}
	o := &nativePacingOwnerObserver{ctx: ctx, admin: admin, root: root, download: download, destination: destination, now: time.Now}
	o.read = o.readSQL
	return o, nil
}

// This is one statement snapshot. The first lookup uses the exact installation
// root/download, rejects ambiguous workers, and selects the active response
// window. Every later query pins the original operation/fence/response/window;
// after completion active_window is cleared, so it is deliberately not the join.
const nativePacingOwnerProjection = `SELECT clock_timestamp(),
 o.worker_id::text,o.operation_id::text,o.fence,o.operation_json,
 o.lease_sequence,o.lease_started,o.lease_until,o.closed,o.retired_at IS NOT NULL,
 r.id::text,r.generation,r.lease_sequence,r.until_at,r.closed,
 w.id::text,w.ordinal,r.reserved_windows,r.window_count,
 coalesce(r.active_window=w.id,false),
 w.intent_receipt IS NOT NULL AND w.intent_completion IS NOT NULL,
 w.outcome_receipt IS NOT NULL AND w.outcome_completion IS NOT NULL,
 coalesce((w.outcome_json->>'Success')::boolean,false),
 coalesce((w.outcome_json->>'VerifiedFinal')::boolean,false),
 (SELECT count(*) FROM download_native_key k WHERE k.root_id=o.root_id AND
  k.worker_id=o.worker_id AND k.operation_id=o.operation_id AND k.operation_fence=o.fence),
 coalesce((SELECT k.used_roles::bigint FROM download_native_key k WHERE k.root_id=o.root_id AND
  k.worker_id=o.worker_id AND k.operation_id=o.operation_id AND k.operation_fence=o.fence AND k.window_id=w.id),-1)
 FROM download_native_owner o
 JOIN download_worker dw ON dw.id=o.worker_id AND dw.root_id=o.root_id
 JOIN download_response r ON r.id=(o.operation_json->>'ParentID')::uuid
  AND r.root_id=o.root_id AND r.session_id=dw.session_id
 JOIN download_window w ON w.response_id=r.id AND w.session_id=r.session_id
 WHERE o.root_id=$1 AND dw.session_id=$2 AND o.operation_json->>'Kind'='read-context-response'`

// Resolve the actual schema and both bind shapes before spending a collector
// run. Empty-row parsing is not a positive owner/renewal/window qualification.
func TestNativePacingOwnerSQLProjectionWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("owned custody SQL fixture not selected")
	}
	var f struct{ Postgres string }
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" {
		t.Fatal("native owner SQL fixture unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(f.Postgres)
	if err != nil {
		t.Fatal("native owner SQL configuration unavailable")
	}
	cfg.MaxConns = 1
	admin, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("native owner SQL administrator unavailable")
	}
	defer admin.Close()
	const id = "00000000-0000-4000-8000-000000000001"
	for _, pinned := range []bool{false, true} {
		query := nativePacingOwnerProjection + ` AND w.id=r.active_window AND NOT o.closed AND o.retired_at IS NULL LIMIT 0`
		args := []any{id, id}
		if pinned {
			query = nativePacingOwnerProjection + ` AND o.worker_id=$3 AND o.operation_id=$4 AND o.fence=$5 AND r.id=$6 AND w.id=$7 LIMIT 0`
			args = append(args, id, id, int64(1), id, id)
		}
		rows, err := admin.Query(ctx, query, args...)
		if err != nil {
			t.Fatal("actual native owner projection SQL failed", err)
		}
		fields := len(rows.FieldDescriptions())
		rows.Close()
		if rows.Err() != nil || fields != 26 {
			t.Fatal("native owner projection changed its scanned shape", fields, rows.Err())
		}
	}
}

func (o *nativePacingOwnerObserver) readSQL(ctx context.Context, pinned *nativePacingOwnerSample) (nativePacingOwnerSample, error) {
	var sample nativePacingOwnerSample
	query := nativePacingOwnerProjection + ` AND w.id=r.active_window AND NOT o.closed AND o.retired_at IS NULL LIMIT 2`
	args := []any{o.root, o.download}
	if pinned != nil {
		query = nativePacingOwnerProjection + ` AND o.worker_id=$3 AND o.operation_id=$4 AND o.fence=$5 AND r.id=$6 AND w.id=$7 LIMIT 2`
		args = append(args, pinned.worker, pinned.operation, pinned.fence, pinned.response, pinned.window)
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := o.admin.Query(call, query, args...)
	if err != nil {
		return sample, errors.New("native owner SQL measurement unavailable")
	}
	defer rows.Close()
	if !rows.Next() {
		return sample, errors.New("native owner SQL measurement missing")
	}
	err = rows.Scan(&sample.observed, &sample.worker, &sample.operation, &sample.fence, &sample.operationJSON,
		&sample.sequence, &sample.leaseStarted, &sample.leaseUntil, &sample.ownerClosed, &sample.retired,
		&sample.response, &sample.generation, &sample.responseSequence, &sample.responseUntil, &sample.responseClosed,
		&sample.window, &sample.ordinal, &sample.reservedWindows, &sample.windowCount, &sample.activeWindow,
		&sample.intentAcknowledged, &sample.outcomeAcknowledged, &sample.outcomeSuccess, &sample.verifiedFinal, &sample.keyRows, &sample.usedRoles)
	if err != nil || rows.Next() || rows.Err() != nil {
		return nativePacingOwnerSample{}, errors.New("native owner SQL measurement ambiguous or invalid")
	}
	return sample, nil
}

func (o *nativePacingOwnerObserver) sample(ctx context.Context, pinned *nativePacingOwnerSample) (nativePacingOwnerSample, error) {
	started := time.Now()
	o.reads++
	s, err := o.read(ctx, pinned)
	o.readDuration += time.Since(started)
	return s, err
}

func (s nativePacingOwnerSample) operationValue(download string) (nativePacingOwnerOperation, error) {
	var operation nativePacingOwnerOperation
	if len(s.operationJSON) == 0 || len(s.operationJSON) > 8192 || json.Unmarshal(s.operationJSON, &operation) != nil || operation.Kind != "read-context-response" ||
		!authorization.UUID(s.worker) || !authorization.UUID(s.operation) || !authorization.UUID(s.response) || !authorization.UUID(s.window) || s.fence < 1 ||
		operation.Reference.SessionID != download || operation.Reference.WorkerID != s.worker || operation.Reference.OperationID != s.operation || operation.Reference.Fence != s.fence ||
		operation.ParentID != s.response || operation.Generation != s.generation || operation.StartedAt.IsZero() || !operation.Until.After(operation.StartedAt) || operation.Until.After(operation.StartedAt.Add(authorization.NativeConversationWindow(authorization.NativeResponse))) ||
		s.observed.IsZero() || s.sequence < 1 || s.ordinal != 1 || s.reservedWindows != 1 || s.windowCount != 1 || s.keyRows != 1 || s.usedRoles != 7 || !s.intentAcknowledged {
		return operation, errors.New("native owner/window/key measurement violates finite shape")
	}
	return operation, nil
}

func (s nativePacingOwnerSample) active(download string) error {
	op, err := s.operationValue(download)
	if err != nil {
		return err
	}
	if s.ownerClosed || s.retired || s.responseClosed || !s.activeWindow || s.outcomeAcknowledged || s.sequence != s.responseSequence || s.leaseStarted.After(s.observed) || !s.leaseUntil.After(s.observed) || s.leaseUntil.After(s.leaseStarted.Add(5*time.Second)) || s.leaseUntil.After(op.Until) || !s.responseUntil.After(s.observed) || op.Until.After(s.responseUntil) {
		return errors.New("native owner/window was not currently active at measurement")
	}
	return nil
}

func (a nativePacingOwnerSample) samePinned(b nativePacingOwnerSample) bool {
	return a.worker == b.worker && a.operation == b.operation && a.fence == b.fence && a.response == b.response && a.window == b.window && a.generation == b.generation && a.ordinal == b.ordinal && a.responseUntil.Equal(b.responseUntil) && bytes.Equal(a.operationJSON, b.operationJSON)
}

func (o *nativePacingOwnerObserver) renewalCutoff() time.Time {
	operation, _ := o.first.operationValue(o.download)
	cutoff := operation.StartedAt.Add(5 * time.Second)
	if o.first.leaseUntil.After(cutoff) {
		cutoff = o.first.leaseUntil
	}
	return cutoff
}

func (o *nativePacingOwnerObserver) Write(p []byte) (int, error) {
	if o.err != nil {
		return 0, o.err
	}
	if o.finished || o.ctx.Err() != nil {
		return 0, errors.New("native owner measurement ended")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if !o.firstAttempted {
		o.firstAttempted = true
		s, err := o.sample(o.ctx, nil)
		if err == nil {
			err = s.active(o.download)
		}
		if err != nil {
			o.err = err
			return 0, err
		}
		o.first = &s
	} else if !o.renewalAttempted && o.now().After(o.renewalCutoff()) {
		o.renewalAttempted = true
		s, err := o.sample(o.ctx, o.first)
		if err == nil {
			err = s.active(o.download)
		}
		if err == nil && (!o.first.samePinned(s) || s.sequence <= o.first.sequence || !s.observed.After(o.renewalCutoff())) {
			err = errors.New("native owner renewal did not preserve the original window/deadline")
		}
		if err != nil {
			o.err = err
			return 0, err
		}
		o.renewed = &s
	}
	n, err := o.destination.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		o.err = errors.New("native measured destination write failed")
		return n, o.err
	}
	return n, nil
}

// Call only after verified bytes and the existing public completion check. EOF
// and byte length never substitute for a positively acknowledged SQL outcome.
func (o *nativePacingOwnerObserver) Finish(ctx context.Context) (nativePacingOwnerReport, error) {
	var report nativePacingOwnerReport
	if o.finished || o.err != nil || o.first == nil || o.renewed == nil || ctx == nil || ctx.Err() != nil {
		return report, errors.New("native owner renewal measurement incomplete")
	}
	o.finished = true
	final, err := o.sample(ctx, o.first)
	if err != nil {
		return report, err
	}
	operation, err := final.operationValue(o.download)
	if err != nil {
		return report, err
	}
	if !o.first.samePinned(final) || final.sequence < o.renewed.sequence || final.observed.Before(o.renewed.observed) || !final.ownerClosed || !final.responseClosed || final.activeWindow || !final.outcomeAcknowledged || !final.outcomeSuccess || !final.verifiedFinal {
		return report, errors.New("native pinned window lacks positive final acknowledgement/closure")
	}
	report = nativePacingOwnerReport{SameOwner: true, SameWindow: true, OriginalDeadlineUnchanged: true, Renewed: true, FinalOutcomeAcknowledged: true, ResponseClosed: true, OwnerClosed: true,
		FirstObservedAt: o.first.observed, RenewedObservedAt: o.renewed.observed, FinalObservedAt: final.observed, OriginalStartedAt: operation.StartedAt, OriginalUntil: operation.Until, InitialLeaseUntil: o.first.leaseUntil, RenewedLeaseUntil: o.renewed.leaseUntil,
		InitialSequence: o.first.sequence, RenewedSequence: o.renewed.sequence, NativeKeyRows: final.keyRows, ConsumedKeySlots: 3, ProofSQLReads: o.reads, ProofSQLDuration: o.readDuration}
	return report, nil
}

// Pure validation only: these samples do not qualify SQL syntax or installed
// runtime behavior. The composed installed fixture supplies that evidence.
func TestNativePacingOwnerMeasurementPinsOriginalWindowAndRejectsFalseRenewal(t *testing.T) {
	for _, mode := range []string{"ok", "same sequence", "changed operation", "changed window", "new key", "missing key role", "closed too early", "no acknowledgement"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			id := func(n string) string { return "00000000-0000-4000-8000-0000000000" + n }
			operation := nativePacingOwnerOperation{Kind: "read-context-response", ParentID: id("04"), Generation: 1, StartedAt: now, Until: now.Add(20 * time.Second)}
			operation.Reference.SessionID = id("01")
			operation.Reference.WorkerID = id("02")
			operation.Reference.OperationID = id("03")
			operation.Reference.Fence = 1
			encoded, _ := json.Marshal(operation)
			first := nativePacingOwnerSample{observed: now.Add(time.Second), leaseStarted: now, leaseUntil: now.Add(5 * time.Second), responseUntil: now.Add(20 * time.Second), worker: id("02"), operation: id("03"), response: id("04"), window: id("05"), fence: 1, sequence: 1, responseSequence: 1, generation: 1, ordinal: 1, reservedWindows: 1, windowCount: 1, keyRows: 1, usedRoles: 7, operationJSON: encoded, activeWindow: true, intentAcknowledged: true}
			renewed := first
			renewed.observed = now.Add(6 * time.Second)
			renewed.leaseStarted = renewed.observed
			renewed.leaseUntil = now.Add(10 * time.Second)
			renewed.sequence = 2
			renewed.responseSequence = 2
			final := renewed
			final.observed = now.Add(8 * time.Second)
			final.ownerClosed = true
			final.responseClosed = true
			final.activeWindow = false
			final.outcomeAcknowledged = true
			final.outcomeSuccess = true
			final.verifiedFinal = true
			switch mode {
			case "same sequence":
				renewed.sequence = 1
				renewed.responseSequence = 1
			case "changed operation":
				changed := operation
				changed.Until = changed.Until.Add(-time.Second)
				renewed.operationJSON, _ = json.Marshal(changed)
			case "changed window":
				renewed.window = id("06")
			case "new key":
				renewed.keyRows = 2
			case "missing key role":
				renewed.usedRoles = 3
			case "closed too early":
				renewed.ownerClosed = true
			case "no acknowledgement":
				final.outcomeAcknowledged = false
			}
			samples := []nativePacingOwnerSample{first, renewed, final}
			calls := 0
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			o := &nativePacingOwnerObserver{ctx: ctx, download: id("01"), destination: io.Discard, now: func() time.Time { return now.Add(6 * time.Second) }, read: func(_ context.Context, pin *nativePacingOwnerSample) (nativePacingOwnerSample, error) {
				if calls > 0 && (pin == nil || pin.operation != first.operation || pin.window != first.window) {
					t.Fatal("query lost original pin")
				}
				s := samples[calls]
				calls++
				return s, nil
			}}
			_, firstErr := o.Write([]byte("one"))
			if firstErr != nil {
				t.Fatal(firstErr)
			}
			_, renewErr := o.Write([]byte("two"))
			_, againErr := o.Write([]byte("three")) // No second renewal callback, including failures.
			if mode != "ok" && mode != "no acknowledgement" {
				if renewErr == nil || againErr == nil || calls != 2 {
					t.Fatal("false renewal accepted or retried", calls)
				}
				return
			}
			if renewErr != nil || againErr != nil {
				t.Fatal(renewErr, againErr)
			}
			report, err := o.Finish(ctx)
			if mode == "no acknowledgement" {
				if err == nil {
					t.Fatal("EOF substituted for acknowledged outcome")
				}
				return
			}
			if err != nil || !report.Renewed || report.ConsumedKeySlots != 3 || report.ProofSQLReads != 3 || calls != 3 {
				t.Fatal("valid pure observations refused", err)
			}
			wire, _ := json.Marshal(report)
			if bytes.Contains(wire, []byte(id("01"))) || bytes.Contains(wire, []byte(id("03"))) || bytes.Contains(wire, []byte("operation_json")) {
				t.Fatal("private identifiers/operation leaked to report")
			}
			if _, err = o.Finish(ctx); err == nil || calls != 3 {
				t.Fatal("final probe repeated")
			}
		})
	}
}
