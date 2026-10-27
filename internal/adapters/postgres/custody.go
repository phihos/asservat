// Package postgres implements short, purpose-specific custody transactions.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	authvalue "asservat.local/asservat/internal/domain/authorization"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	configuration "asservat.local/asservat/internal/domain/configuration"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	identityvalue "asservat.local/asservat/internal/domain/identity"
	privacyvalue "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const currentSchemaVersion = 102

// schemaFloorComment prefixes the version table's comment that records the
// oldest binary schema the database still serves (ADR-227). Only the schema
// owner can set a comment; every role reads it without a grant.
const schemaFloorComment = "asservat:oldest-binary-schema="

// schemaCompatible reports why this binary (compiled head
// currentSchemaVersion) cannot run against the database, or "" when it can:
// the database head must be at least the binary's and the recorded floor at
// most the binary's. Without a recorded floor the head must match exactly.
func schemaCompatible(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) string {
	head, floor, err := schemaState(ctx, q.QueryRow(ctx, schemaStateQuery))
	switch {
	case err != nil:
		return "unreadable"
	case head < currentSchemaVersion:
		return "older than this binary (run installer-upgrade)"
	case floor > currentSchemaVersion:
		return "newer than this binary tolerates (use a newer image or restore from backup)"
	}
	return ""
}

// schemaRefusal keeps the caller's error class and names the reason.
func schemaRefusal(class error, reason string) error {
	return fmt.Errorf("%w: database schema %s", class, reason)
}

const schemaStateQuery = `SELECT version_id,is_applied,pg_catalog.obj_description('public.goose_db_version'::regclass,'pg_class') FROM goose_db_version ORDER BY id DESC LIMIT 1`

// schemaState decodes the database head and floor. Without a recorded floor
// the floor is the head.
func schemaState(_ context.Context, row interface{ Scan(...any) error }) (head, floor int64, err error) {
	var applied bool
	var comment *string
	if err = row.Scan(&head, &applied, &comment); err != nil || !applied || head < 1 {
		return 0, 0, configuration.ErrUnavailable
	}
	floor = head
	if comment != nil && strings.HasPrefix(*comment, schemaFloorComment) {
		n, e := strconv.ParseInt(strings.TrimPrefix(*comment, schemaFloorComment), 10, 64)
		if e != nil || n < 1 || n > head {
			return 0, 0, configuration.ErrChanged
		}
		floor = n
	}
	return head, floor, nil
}

type Ledger struct{ pool *pgxpool.Pool }

var _ privacy.CopyLedger = (*Ledger)(nil)

// New accepts an explicitly wired runtime pool, never an environment DSN or a
// migration connection. Bootstrap owns credentials and primary/restore fencing.
func New(ctx context.Context, pool *pgxpool.Pool) (*Ledger, error) {
	if pool == nil {
		return nil, artifact.ErrInvalid
	}
	c := pool.Config()
	t := c.ConnConfig.TLSConfig
	if c.MaxConns > 32 || t == nil || t.InsecureSkipVerify || t.ServerName == "" || t.MinVersion < tls.VersionTLS12 || len(c.ConnConfig.Fallbacks) != 0 || c.ConnConfig.Tracer != nil {
		return nil, artifact.ErrInvalid
	}
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var unsafeRole, replica bool
	if why := schemaCompatible(check, pool); why != "" {
		return nil, schemaRefusal(privacy.ErrUnavailable, why)
	}
	if err := pool.QueryRow(check, "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR has_schema_privilege(current_user,'public','CREATE'),pg_is_in_recovery() FROM pg_roles WHERE rolname=current_user").Scan(&unsafeRole, &replica); err != nil || unsafeRole || replica {
		return nil, privacy.ErrUnavailable
	}
	return &Ledger{pool}, nil
}

func id(s string) pgtype.UUID { var u pgtype.UUID; _ = u.Scan(s); return u }
func uid(u pgtype.UUID) string {
	s, _ := u.Value()
	if s == nil {
		return ""
	}
	return s.(string)
}
func ts(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t.UTC(), Valid: true} }
func digest(v any) []byte               { b, _ := json.Marshal(v); h := sha256.Sum256(b); return h[:] }
func normalized(r artifact.Registration) artifact.Registration {
	r.AnchorAt = r.AnchorAt.UTC()
	r.WriteUntil = r.WriteUntil.UTC()
	r.ExpiresAt = r.ExpiresAt.UTC()
	r.DeleteBy = r.DeleteBy.UTC()
	return r
}

// No callback may perform remote I/O. Only definitely aborted SQL transactions
// retry. Unknown COMMIT outcomes return unavailable for original-key replay.
func (l *Ledger) transaction(ctx context.Context, f func(*custodydb.Queries) error) error {
	// Include waiting for a pooled connection and all retries in the same bound.
	// SQL statement/lock timeouts alone do not limit pool acquisition.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		tx, err := l.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			if ctx.Err() != nil {
				return unavailableCause("begin-deadline")
			}
			return unavailableCause("begin-" + connectCause(err))
		}
		_, err = tx.Exec(ctx, "SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'; SET LOCAL idle_in_transaction_session_timeout='5s'; SET LOCAL synchronous_commit=on")
		if err == nil {
			err = f(custodydb.New(tx))
		}
		if err == nil {
			err = tx.Commit(ctx)
		}
		// Rollback does not turn an ambiguous COMMIT into permission to refund.
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		_ = tx.Rollback(rollbackCtx)
		cancel()
		if err == nil {
			return nil
		}
		for _, sentinel := range []error{identityvalue.ErrDenied, identityvalue.ErrInvalid, identityvalue.ErrSessionBusy, identityvalue.ErrSessionCapacity,
			// ADR-249 grant ledger outcomes.
			authapp.ErrGrantConflict, authapp.ErrGrantNotFound, authvalue.ErrGrantInvalid, authvalue.ErrGrantNotPending, authvalue.ErrSelfApproval,
			authvalue.ErrGrantPoolExhausted, authvalue.ErrGrantScope, authvalue.ErrGrantRevoked, authvalue.ErrGrantExpired, authvalue.ErrGrantDenied, authvalue.ErrStepUpRequired} {
			if errors.Is(err, sentinel) {
				return sentinel
			}
		}
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			if (pe.Code == "40001" || pe.Code == "40P01") && attempt < 2 {
				delay := time.Duration(10+time.Now().UnixNano()%20) * time.Millisecond
				select {
				case <-ctx.Done():
					return privacy.ErrUnavailable
				case <-time.After(delay):
					continue
				}
			}
			if pe.Code == "23505" {
				return privacy.ErrConflict
			}
		}
		for _, sentinel := range []error{fleetvalue.ErrCapacity, fleetvalue.ErrConflict, fleetvalue.ErrPending, fleetvalue.ErrInvalid, fleetvalue.ErrDenied, fleetvalue.ErrUnavailable, capturevalue.ErrSettingsUnavailable, capturevalue.ErrSettingsTooLarge, capturevalue.ErrHistoryUnavailable, capturevalue.ErrInvalid, capturevalue.ErrSharingDenied, capturevalue.ErrDenied, capturevalue.ErrChanged, capturevalue.ErrUnavailable, capturevalue.ErrCapacity, capturevalue.ErrProcessingCoverage, capturevalue.ErrConflict, artifact.ErrInvalid, artifact.ErrIntegrity, artifact.ErrLimit, artifact.ErrDownloadConflict, artifact.ErrDownloadUnavailable, artifact.ErrDownloadCapacity, artifact.ErrDownloadExpired, privacy.ErrConflict, privacy.ErrCapacity, privacy.ErrExpired, privacy.ErrFence, privacy.ErrNotDue, configuration.ErrInvalid, configuration.ErrChanged, configuration.ErrLimit, configuration.ErrDenied, configuration.ErrUnavailable, configuration.ErrRetentionHistoryBehind, configuration.ErrRetentionObservationObsolete, fleetvalue.ErrClusterCredentialDenied, fleetvalue.ErrClusterCredentialFenced} {
			if errors.Is(err, sentinel) {
				return sentinel
			}
		}
		// Never leak SQL, identities or connection details: only a closed cause
		// word (a SQLSTATE is a fixed five-character class) for diagnostics.
		switch {
		case errors.As(err, &pe) && len(pe.Code) == 5:
			return unavailableCause("sql-" + pe.Code)
		case ctx.Err() != nil:
			return unavailableCause("deadline")
		}
		return unavailableCause("client")
	}
	return unavailableCause("retries")
}

// connectCause classifies a failed connection acquisition by error type only:
// a hook's own closed step (the credential re-read before connecting names
// itself), dial (TCP), tls, server (a PostgreSQL error such as
// authentication), connect (any other connect failure) or acquire.
func connectCause(err error) string {
	var op *net.OpError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	var verify *tls.CertificateVerificationError
	var server *pgconn.PgError
	var connect *pgconn.ConnectError
	var named interface{ FixedStep() string }
	switch {
	case errors.As(err, &named):
		return named.FixedStep()
	case errors.As(err, &server):
		return "server"
	case errors.As(err, &record), errors.As(err, &alert), errors.As(err, &verify):
		return "tls"
	case errors.As(err, &op):
		return "dial"
	case errors.As(err, &connect):
		return "connect"
	}
	return "acquire"
}

// ledgerCause is privacy.ErrUnavailable with a closed cause word; callers keep
// matching the sentinel, and step labels can name the cause (FixedStep).
type ledgerCause struct{ cause string }

func (e ledgerCause) Error() string     { return privacy.ErrUnavailable.Error() }
func (e ledgerCause) Unwrap() error     { return privacy.ErrUnavailable }
func (e ledgerCause) FixedStep() string { return e.cause }

func unavailableCause(cause string) error { return ledgerCause{cause} }

// Lock root, allocation, then attempt. The unlocked root lookup is only a hint;
// allocation moves are forbidden and are checked again under its row lock.
func lockAllocation(ctx context.Context, q *custodydb.Queries, allocation string) (custodydb.CustodyPool, custodydb.CustodyAllocation, error) {
	root, err := q.FindPool(ctx, id(allocation))
	if err != nil {
		return custodydb.CustodyPool{}, custodydb.CustodyAllocation{}, err
	}
	p, err := q.LockPool(ctx, root)
	if err != nil {
		return p, custodydb.CustodyAllocation{}, err
	}
	a, err := q.LockAllocation(ctx, id(allocation))
	if err == nil && a.PoolID != root {
		err = privacy.ErrFence
	}
	return p, a, err
}

func current(ctx context.Context, q *custodydb.Queries, p custodydb.CustodyPool, a custodydb.CustodyAllocation, r artifact.Registration, effective time.Time) error {
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return err
	}
	if p.StoreID != id(r.StoreID) || p.Revision != r.PoolRevision || a.Revision != r.AllocationRevision {
		return privacy.ErrFence
	}
	if p.Paused || a.Paused || !n.Time.Before(p.ValidUntil.Time) || !n.Time.Before(a.ValidUntil.Time) || n.Time.Before(r.AnchorAt) || !n.Time.Before(r.WriteUntil) || !n.Time.Before(r.ExpiresAt) || !n.Time.Before(effective) {
		return privacy.ErrExpired
	}
	return nil
}

func record(ctx context.Context, q *custodydb.Queries, row custodydb.CustodyAttempt, store string) (privacy.Record, error) {
	r := privacy.Record{State: row.State, Effective: privacyvalue.Deadlines{AnchorAt: row.AnchorAt.Time, ExpiresAt: row.EffectiveExpiresAt.Time, DeleteBy: row.EffectiveDeleteBy.Time}, Registration: artifact.Registration{Location: artifact.Location{ClusterID: uid(row.ClusterID), ArtifactID: uid(row.ArtifactID), AttemptID: uid(row.ID)}, StoreID: store, AllocationID: uid(row.AllocationID), PoolRevision: row.PoolRevision, AllocationRevision: row.AllocationRevision, NativeLimit: row.NativeLimit, AnchorAt: row.AnchorAt.Time, WriteUntil: row.WriteUntil.Time, ExpiresAt: row.ExpiresAt.Time, DeleteBy: row.DeleteBy.Time}}
	copies, err := q.ReadCopies(ctx, row.ID)
	if err != nil {
		return r, err
	}
	if len(copies) != 4 {
		return r, privacy.ErrUnavailable
	}
	for i, c := range copies {
		if int(c.Role) != i {
			return r, privacy.ErrUnavailable
		}
		r.Copies[i] = artifact.CopyReceipt{VersionID: c.VersionID.String, ETag: c.Etag.String, Bytes: c.CiphertextBytes.Int64}
		copy(r.Copies[i].SHA256[:], c.CiphertextSha256)
	}
	return r, nil
}

func (l *Ledger) Register(ctx context.Context, r artifact.Registration) (privacy.Record, error) {
	var result privacy.Record
	// Above one frame the temporary multipart obligation must be charged too:
	// only RegisterStreaming may create such an attempt (ADR-166).
	if r.Validate() != nil || r.NativeLimit > artifact.FrameBytes {
		return result, artifact.ErrInvalid
	}
	r = normalized(r)
	err := l.transaction(ctx, func(q *custodydb.Queries) error {
		p, a, err := lockAllocation(ctx, q, r.AllocationID)
		if err != nil {
			return err
		}
		result, err = registerLocked(ctx, q, p, a, r)
		return err
	})
	return result, err
}

// Lookup is internal control metadata only, not a catalog or access check.
func (l *Ledger) Lookup(ctx context.Context, loc artifact.Location) (privacy.Record, error) {
	var result privacy.Record
	if loc.Validate() != nil {
		return result, artifact.ErrInvalid
	}
	err := l.transaction(ctx, func(q *custodydb.Queries) error {
		hint, err := q.ReadAttempt(ctx, id(loc.AttemptID))
		if err != nil {
			return err
		}
		p, _, err := lockAllocation(ctx, q, uid(hint.AllocationID))
		if err != nil {
			return err
		}
		row, err := q.LockAttempt(ctx, id(loc.AttemptID))
		if err != nil {
			return err
		}
		if row.ClusterID != id(loc.ClusterID) || row.ArtifactID != id(loc.ArtifactID) {
			return privacy.ErrConflict
		}
		result, err = record(ctx, q, row, uid(p.StoreID))
		return err
	})
	return result, err
}

func (l *Ledger) CheckVerification(ctx context.Context, r artifact.Registration) error {
	if r.Validate() != nil {
		return artifact.ErrInvalid
	}
	r = normalized(r)
	return l.transaction(ctx, func(q *custodydb.Queries) error {
		p, a, err := lockAllocation(ctx, q, r.AllocationID)
		if err != nil {
			return err
		}
		row, err := q.LockAttempt(ctx, id(r.Location.AttemptID))
		if err != nil {
			return err
		}
		if !bytes.Equal(row.RequestDigest, digest(r)) {
			return privacy.ErrConflict
		}
		if row.State != artifact.Reserved && row.State != artifact.StoredUnpublished {
			return privacy.ErrExpired
		}
		return current(ctx, q, p, a, r, row.EffectiveExpiresAt.Time)
	})
}

func (l *Ledger) StoreCopies(ctx context.Context, r artifact.Registration, copies artifact.Copies) error {
	if r.Validate() != nil || copies.Validate(r) != nil {
		return artifact.ErrInvalid
	}
	r = normalized(r)
	return l.transaction(ctx, func(q *custodydb.Queries) error {
		p, a, err := lockAllocation(ctx, q, r.AllocationID)
		if err != nil {
			return err
		}
		row, err := q.LockAttempt(ctx, id(r.Location.AttemptID))
		if err != nil {
			return err
		}
		if !bytes.Equal(row.RequestDigest, digest(r)) {
			return privacy.ErrConflict
		}
		if err = current(ctx, q, p, a, r, row.EffectiveExpiresAt.Time); err != nil {
			return err
		}
		if row.State == artifact.StoredUnpublished {
			if bytes.Equal(row.CopiesDigest, digest(copies)) {
				return nil
			}
			return privacy.ErrConflict
		}
		if row.State != artifact.Reserved {
			return privacy.ErrExpired
		}
		for i, c := range copies {
			err = q.StoreCopy(ctx, custodydb.StoreCopyParams{AttemptID: row.ID, Role: int16(i), CiphertextBytes: pgtype.Int8{Int64: c.Bytes, Valid: true}, CiphertextSha256: c.SHA256[:], Etag: pgtype.Text{String: c.ETag, Valid: true}, VersionID: pgtype.Text{String: c.VersionID, Valid: c.VersionID != ""}})
			if err != nil {
				return err
			}
		}
		if err = q.MarkStored(ctx, custodydb.MarkStoredParams{ID: row.ID, CopiesDigest: digest(copies)}); err != nil {
			return err
		}
		if err = q.InsertEvent(ctx, custodydb.InsertEventParams{AttemptID: row.ID, Phase: "stored"}); err != nil {
			return err
		}
		return current(ctx, q, p, a, r, row.EffectiveExpiresAt.Time)
	})
}

func (l *Ledger) ClaimDeletion(ctx context.Context, loc artifact.Location) (privacy.Deletion, error) {
	var result privacy.Deletion
	if loc.Validate() != nil {
		return result, artifact.ErrInvalid
	}
	err := l.transaction(ctx, func(q *custodydb.Queries) error {
		hint, err := q.ReadAttempt(ctx, id(loc.AttemptID))
		if err != nil {
			return err
		}
		p, _, err := lockAllocation(ctx, q, uid(hint.AllocationID))
		if err != nil {
			return err
		}
		row, err := q.LockAttempt(ctx, id(loc.AttemptID))
		if err != nil {
			return err
		}
		if row.ClusterID != id(loc.ClusterID) || row.ArtifactID != id(loc.ArtifactID) {
			return privacy.ErrConflict
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if row.State == artifact.Deleted || n.Time.Before(row.EffectiveExpiresAt.Time) {
			return privacy.ErrNotDue
		}
		if row.LeaseUntil.Valid && n.Time.Before(row.LeaseUntil.Time) {
			return privacy.ErrFence
		}
		rec, err := record(ctx, q, row, uid(p.StoreID))
		if err != nil {
			return err
		}
		until := n.Time.Add(30 * time.Second)
		f, err := q.ClaimDeletion(ctx, custodydb.ClaimDeletionParams{ID: row.ID, LeaseUntil: ts(until)})
		if err != nil {
			return err
		}
		result = privacy.Deletion{Registration: rec.Registration, Effective: rec.Effective, Fence: f, LeaseUntil: until}
		return nil
	})
	return result, err
}

func (l *Ledger) FinishDeletion(ctx context.Context, d privacy.Deletion) error {
	r := normalized(d.Registration)
	if r.Validate() != nil || d.Fence < 1 {
		return artifact.ErrInvalid
	}
	return l.transaction(ctx, func(q *custodydb.Queries) error {
		pinned, err := q.ContextRequiresPositiveDeletion(ctx, id(r.Location.AttemptID))
		if err != nil {
			return err
		}
		if pinned {
			return privacy.ErrFence
		}
		_, a, err := lockAllocation(ctx, q, r.AllocationID)
		if err != nil {
			return err
		}
		row, err := q.LockAttempt(ctx, id(r.Location.AttemptID))
		if err != nil {
			return err
		}
		if !bytes.Equal(row.RequestDigest, digest(r)) || row.DeletionFence != d.Fence {
			return privacy.ErrFence
		}
		if row.State == artifact.Deleted {
			return nil
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if row.State != artifact.Deleting || !row.LeaseUntil.Valid || !row.LeaseUntil.Time.Equal(d.LeaseUntil) || !n.Time.Before(row.LeaseUntil.Time) {
			return privacy.ErrFence
		}
		changed, err := q.ReleaseCharge(ctx, custodydb.ReleaseChargeParams{ID: a.ID, ChargedBytes: row.ReservedBytes})
		if err != nil {
			return err
		}
		if changed != 1 {
			return privacy.ErrUnavailable
		}
		if row.NativeLimit > artifact.FrameBytes {
			// The attempt purge proved every object and multipart upload under the
			// prefix absent, so an unreleased temporary charge (for example after an
			// uncertain completion) is released exactly once with the attempt.
			if err = releaseStreamWithAttempt(ctx, q, a.ID, row.ID, n.Time); err != nil {
				return err
			}
		}
		if err = q.ClearReceipts(ctx, row.ID); err != nil {
			return err
		}
		if err = q.MarkDeleted(ctx, custodydb.MarkDeletedParams{ID: row.ID, DeletedAt: n}); err != nil {
			return err
		}
		return q.InsertEvent(ctx, custodydb.InsertEventParams{AttemptID: row.ID, Phase: "deleted"})
	})
}

// registerLocked participates in larger named transactions. The caller holds
// pool then allocation locks; it acquires the attempt lock and never remote I/O.
func registerLocked(ctx context.Context, q *custodydb.Queries, p custodydb.CustodyPool, a custodydb.CustodyAllocation, r artifact.Registration) (privacy.Record, error) {
	row, err := q.LockAttempt(ctx, id(r.Location.AttemptID))
	if err == nil {
		if !bytes.Equal(row.RequestDigest, digest(r)) {
			return privacy.Record{}, privacy.ErrConflict
		}
		// Replay reports custody only, even after expiry; never starts work.
		return record(ctx, q, row, uid(p.StoreID))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return privacy.Record{}, err
	}
	if err = current(ctx, q, p, a, r, r.ExpiresAt); err != nil {
		return privacy.Record{}, err
	}
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return privacy.Record{}, err
	}
	overdue, err := q.Overdue(ctx, custodydb.OverdueParams{AllocationID: a.ID, EffectiveDeleteBy: n})
	if err != nil {
		return privacy.Record{}, err
	}
	if overdue {
		return privacy.Record{}, privacy.ErrCapacity
	}
	changed, err := q.Charge(ctx, custodydb.ChargeParams{ID: a.ID, ChargedBytes: r.ReservedBytes()})
	if err != nil {
		return privacy.Record{}, err
	}
	if changed != 1 {
		return privacy.Record{}, privacy.ErrCapacity
	}
	err = q.InsertAttempt(ctx, custodydb.InsertAttemptParams{ID: id(r.Location.AttemptID), ClusterID: id(r.Location.ClusterID), ArtifactID: id(r.Location.ArtifactID), AllocationID: a.ID, RequestDigest: digest(r), PoolRevision: r.PoolRevision, AllocationRevision: r.AllocationRevision, NativeLimit: r.NativeLimit, ReservedBytes: r.ReservedBytes(), AnchorAt: ts(r.AnchorAt), WriteUntil: ts(r.WriteUntil), ExpiresAt: ts(r.ExpiresAt), DeleteBy: ts(r.DeleteBy)})
	if err != nil {
		return privacy.Record{}, err
	}
	for i, n := range r.Limits() {
		if err = q.InsertCopy(ctx, custodydb.InsertCopyParams{AttemptID: id(r.Location.AttemptID), Role: int16(i), ByteLimit: n}); err != nil {
			return privacy.Record{}, err
		}
	}
	// Unique insert contention can block after earlier locks. Recheck time.
	if err = current(ctx, q, p, a, r, r.ExpiresAt); err != nil {
		return privacy.Record{}, err
	}
	if err = q.InsertEvent(ctx, custodydb.InsertEventParams{AttemptID: id(r.Location.AttemptID), Phase: "registered"}); err != nil {
		return privacy.Record{}, err
	}
	return privacy.Record{Registration: r, Effective: privacyvalue.Deadlines{AnchorAt: r.AnchorAt, ExpiresAt: r.ExpiresAt, DeleteBy: r.DeleteBy}, State: artifact.Reserved}, nil
}
