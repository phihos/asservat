package postgres

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// OwnerConfigurationReadCheck names a fixed local statement or predicate. It
// contains no row values, query text, identities, credentials or error strings.
type OwnerConfigurationReadCheck uint8

const (
	ownerReadTransaction OwnerConfigurationReadCheck = iota
	ownerReadFleet
	ownerReadHead
	ownerReadHeadSource
	ownerReadHeadGeneration
	ownerReadRevision
	ownerReadSnapshotDecode
	ownerReadSnapshotBinding
	ownerReadSnapshotSuspended
	ownerReadSnapshotGeneration
	ownerReadSnapshotIssuer
	ownerReadAuditDecode
	ownerReadAuditBinding
	ownerReadClock
	ownerReadRecoverySuspended
	ownerReadRecoveryBlocked
	ownerReadRecoveryFleetInterval
	ownerReadRecoveryIdentity
	ownerReadRecoveryProofInterval
	ownerReadRecoveryOther
	ownerReadObservationConfiguration
	ownerReadObservationInterval
)

func (c OwnerConfigurationReadCheck) String() string {
	names := [...]string{
		"transaction", "share-fleet", "share-owner", "head-source", "head-generation",
		"revision", "snapshot-decode", "snapshot-binding", "snapshot-suspended",
		"snapshot-generation", "snapshot-issuer", "audit-decode", "audit-binding",
		"database-time", "recovery-suspended", "recovery-blocked", "fleet-interval",
		"recovery-identity", "recovery-proof-interval", "recovery-other",
		"owner-configuration", "owner-interval",
	}
	if int(c) >= len(names) {
		return "unknown"
	}
	return names[c]
}

// OwnerConfigurationReadReason reports only a fixed error/interval class. Even
// a PostgreSQL error code is mapped to this closed vocabulary before storage.
type OwnerConfigurationReadReason uint8

const (
	ownerReadUnspecified OwnerConfigurationReadReason = iota
	ownerReadPredicate
	ownerReadNoRows
	ownerReadLockTimeout
	ownerReadQueryCancelled
	ownerReadPermission
	ownerReadCancelled
	ownerReadDeadline
	ownerReadDriver
	ownerReadMissingStart
	ownerReadFutureStart
	ownerReadClosedInterval
	ownerReadLongInterval
	ownerReadExpiredInterval
)

func (r OwnerConfigurationReadReason) String() string {
	names := [...]string{
		"unspecified", "predicate", "no-rows", "lock-timeout", "query-cancelled",
		"permission", "cancelled", "deadline", "driver", "missing-start",
		"future-start", "closed-interval", "overlong-interval", "expired-interval",
	}
	if int(r) >= len(names) {
		return "unknown"
	}
	return names[r]
}

// OwnerConfigurationReadFailure wraps only Ledger.transaction's existing
// sanitized result. The diagnostic never retains the raw query error; errors.Is
// remains identical to the former public reader return. Native consumers may
// continue normalizing it without exposing diagnostics to public interfaces.
type OwnerConfigurationReadFailure struct {
	check  OwnerConfigurationReadCheck
	reason OwnerConfigurationReadReason
	cause  error
}

func (e *OwnerConfigurationReadFailure) Error() string {
	return "owner configuration read: " + e.check.String() + ": " + e.reason.String()
}
func (e *OwnerConfigurationReadFailure) Unwrap() error                        { return e.cause }
func (e *OwnerConfigurationReadFailure) Check() OwnerConfigurationReadCheck   { return e.check }
func (e *OwnerConfigurationReadFailure) Reason() OwnerConfigurationReadReason { return e.reason }

type ownerConfigurationReadDiagnostic struct {
	check  OwnerConfigurationReadCheck
	reason OwnerConfigurationReadReason
}

func (d *ownerConfigurationReadDiagnostic) reset() { *d = ownerConfigurationReadDiagnostic{} }
func (d ownerConfigurationReadDiagnostic) failure(sanitized error) error {
	if sanitized == nil {
		return nil
	}
	return &OwnerConfigurationReadFailure{check: d.check, reason: d.reason, cause: sanitized}
}
func (d *ownerConfigurationReadDiagnostic) reject(check OwnerConfigurationReadCheck) error {
	*d = ownerConfigurationReadDiagnostic{check, ownerReadPredicate}
	return value.ErrUnavailable
}
func (d *ownerConfigurationReadDiagnostic) query(check OwnerConfigurationReadCheck, err error) error {
	d.reset()
	var p *pgconn.PgError
	if errors.As(err, &p) && (p.Code == "40001" || p.Code == "40P01") {
		// Ledger may retry, then fail before reentering the callback. Do not keep
		// a previous attempt's statement or error class in that final result.
		// Exhausted retryable failures deliberately use transaction/unspecified.
		return err
	}
	d.check, d.reason = check, ownerReadDriver
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		d.reason = ownerReadNoRows
	case errors.Is(err, context.Canceled):
		d.reason = ownerReadCancelled
	case errors.Is(err, context.DeadlineExceeded):
		d.reason = ownerReadDeadline
	case p != nil:
		switch p.Code {
		case "55P03":
			d.reason = ownerReadLockTimeout
		case "57014":
			d.reason = ownerReadQueryCancelled
		case "42501":
			d.reason = ownerReadPermission
		}
	}
	return err
}

// Called only after the unchanged recoveryState rejects these same inputs.
// Preserve its ordered predicates and the original SQL clock, without reading
// the view again or trying to infer the components of its derived recovery bit.
func ownerReadRecoveryFailure(row custodydb.FleetCurrentTrust, started, now time.Time) ownerConfigurationReadDiagnostic {
	if row.Suspended {
		return ownerConfigurationReadDiagnostic{ownerReadRecoverySuspended, ownerReadPredicate}
	}
	if row.RecoveryBlocked {
		return ownerConfigurationReadDiagnostic{ownerReadRecoveryBlocked, ownerReadPredicate}
	}
	if !identity.Fresh(row.ObservedAt.Time, row.FreshUntil.Time, now, 30*time.Second) {
		return ownerConfigurationReadDiagnostic{ownerReadRecoveryFleetInterval, ownerReadIntervalFailure(row.ObservedAt.Time, row.FreshUntil.Time, now, 30*time.Second)}
	}
	if !authorization.UUID(uid(row.InstallationID)) || !authorization.UUID(uid(row.IssuerEpoch)) || !trustRevision(row).Valid() {
		return ownerConfigurationReadDiagnostic{ownerReadRecoveryIdentity, ownerReadPredicate}
	}
	until := identity.Earlier(started.Add(5*time.Second), row.FreshUntil.Time)
	if !identity.Fresh(started, until, now, 5*time.Second) {
		return ownerConfigurationReadDiagnostic{ownerReadRecoveryProofInterval, ownerReadIntervalFailure(started, until, now, 5*time.Second)}
	}
	return ownerConfigurationReadDiagnostic{ownerReadRecoveryOther, ownerReadUnspecified}
}

func ownerReadObservationFailure(out value.OwnerConfigurationObservation, now time.Time) ownerConfigurationReadDiagnostic {
	if !out.Configuration.Valid() {
		return ownerConfigurationReadDiagnostic{ownerReadObservationConfiguration, ownerReadPredicate}
	}
	return ownerConfigurationReadDiagnostic{ownerReadObservationInterval, ownerReadIntervalFailure(out.ObservedAt, out.FreshUntil, now, 5*time.Second)}
}

// Ordered like identity.Fresh. This is diagnostic classification only, never a
// second authority decision, replacement clock or new observation interval.
func ownerReadIntervalFailure(started, until, now time.Time, maximum time.Duration) OwnerConfigurationReadReason {
	switch {
	case started.IsZero():
		return ownerReadMissingStart
	case started.After(now):
		return ownerReadFutureStart
	case !until.After(started):
		return ownerReadClosedInterval
	case until.After(started.Add(maximum)):
		return ownerReadLongInterval
	case !now.Before(until):
		return ownerReadExpiredInterval
	default:
		return ownerReadUnspecified
	}
}
