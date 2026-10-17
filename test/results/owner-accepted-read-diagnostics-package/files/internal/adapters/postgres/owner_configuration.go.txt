package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type OwnerConfigurations struct {
	ledger                                   *Ledger
	installation, cluster, namespace, source string
}

var _ app.OwnerConfigurationLedger = (*OwnerConfigurations)(nil)
var _ app.OwnerConfigurationReader = (*OwnerConfigurations)(nil)
var _ auditapp.OwnerConfigurationAcknowledgements = (*OwnerConfigurations)(nil)

func NewOwnerConfigurations(ctx context.Context, pool *pgxpool.Pool, installation, cluster, namespace, source string) (*OwnerConfigurations, error) {
	for _, v := range []string{installation, cluster, namespace, source} {
		if !authorization.UUID(v) {
			return nil, value.ErrInvalid
		}
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &OwnerConfigurations{l, installation, cluster, namespace, source}, nil
}
func (s *OwnerConfigurations) matches(c value.OwnerConfiguration) bool {
	return c.Valid() && c.Pool.InstallationID == s.installation && c.Pool.ClusterID == s.cluster && c.Pool.NamespaceUID == s.namespace && c.Revision.UID == s.source
}

// SQL stores microsecond timestamps. Normalize before comparisons so a replay
// cannot masquerade as a later observation by its discarded nanoseconds.
func ownerTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

func (s *OwnerConfigurations) ObserveOwnerConfiguration(ctx context.Context, o value.OwnerConfigurationObservation) (audit.Receipt, bool, error) {
	var receipt audit.Receipt
	var ack bool
	if s == nil || ctx == nil || !o.Valid(o.ObservedAt) || !s.matches(o.Configuration) {
		return receipt, false, value.ErrInvalid
	}
	o.Configuration = o.Configuration.Clone()
	o.ObservedAt, o.FreshUntil = ownerTime(o.ObservedAt), ownerTime(o.FreshUntil)
	ctx, end := context.WithDeadline(ctx, o.FreshUntil)
	defer end()
	c := o.Configuration
	b, err := json.Marshal(c)
	if err != nil || len(b) > 64<<10 {
		return receipt, false, value.ErrInvalid
	}
	var rejected error
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		receipt, ack, rejected = audit.Receipt{}, false, nil
		trust, e := q.ShareFleetTrust(ctx, id(s.installation))
		if e != nil {
			return e
		}
		check := func() error {
			n, e := q.CurrentTime(ctx)
			if e != nil {
				return e
			}
			r, e := recoveryState(trust, o.ObservedAt, n.Time)
			if e != nil || !o.Valid(n.Time) || r.IssuerEpoch != c.Pool.IssuerEpoch {
				return value.ErrUnavailable
			}
			return nil
		}
		if e = check(); e != nil {
			return e
		}
		// This provisional unavailable row is never externally visible. Existing
		// failure rows keep their watermark and cannot be renewed at equal time.
		_, e = q.InsertOwnerConfiguration(ctx, custodydb.InsertOwnerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster), SourceUid: id(s.source), ObservedAt: ts(o.ObservedAt.Add(-time.Microsecond))})
		if e != nil {
			return e
		}
		h, e := q.LockOwnerConfiguration(ctx, custodydb.LockOwnerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster)})
		if e != nil {
			return e
		}
		if e = check(); e != nil {
			return e
		}
		if uid(h.SourceUid) != s.source {
			return value.ErrDenied
		}
		if o.ObservedAt.Before(h.ObservedAt.Time) {
			return value.ErrConflict
		}
		// Commit a known negative observation before reporting its rejection.
		// Returning the rejection from the callback would undo the fence.
		fence := func(reason error) error {
			rejected = reason
			return q.FenceOwnerConfiguration(ctx, custodydb.FenceOwnerConfigurationParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, ObservedAt: ts(o.ObservedAt)})
		}
		if c.Revision.Generation < h.Generation {
			return fence(value.ErrConflict)
		}
		if o.ObservedAt.Equal(h.ObservedAt.Time) && (!h.FreshUntil.Time.After(h.ObservedAt.Time) || o.FreshUntil.After(h.FreshUntil.Time)) {
			return value.ErrConflict
		}
		old, e := q.ReadOwnerConfigurationRevision(ctx, custodydb.ReadOwnerConfigurationRevisionParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, Generation: c.Revision.Generation})
		if e == nil {
			if !bytes.Equal(old.SnapshotJson, b) {
				return fence(value.ErrConflict)
			}
			if old.AuditReceiptJson != nil {
				if json.Unmarshal(old.AuditReceiptJson, &receipt) != nil || !receipt.ValidOwnerConfiguration(c) {
					return fence(value.ErrDenied)
				}
				ack = true
			}
		} else if errors.Is(e, pgx.ErrNoRows) {
			n, e := q.CountOwnerConfigurationRevisions(ctx, custodydb.CountOwnerConfigurationRevisionsParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid})
			if e != nil {
				return e
			}
			if n >= 1024 {
				return fence(value.ErrCapacity)
			}
			e = q.InsertOwnerConfigurationRevision(ctx, custodydb.InsertOwnerConfigurationRevisionParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, Generation: c.Revision.Generation, SnapshotJson: b})
			if e != nil {
				return e
			}
		} else {
			return e
		}
		e = q.ObserveOwnerConfiguration(ctx, custodydb.ObserveOwnerConfigurationParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, Generation: c.Revision.Generation, ObservedAt: ts(o.ObservedAt), FreshUntil: ts(o.FreshUntil)})
		if e != nil {
			return e
		}
		return check()
	})
	if err != nil {
		return audit.Receipt{}, false, err
	}
	if rejected != nil {
		return audit.Receipt{}, false, rejected
	}
	return receipt, ack, nil
}

func (s *OwnerConfigurations) FenceOwnerConfiguration(ctx context.Context, at time.Time) error {
	if s == nil || ctx == nil || at.IsZero() {
		return value.ErrInvalid
	}
	at = ownerTime(at)
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		// Negative observations remain possible while recovery is blocked.
		if _, e := q.ShareFleetTrust(ctx, id(s.installation)); e != nil {
			return e
		}
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if at.After(n.Time) {
			return value.ErrInvalid
		}
		_, e = q.InsertOwnerConfiguration(ctx, custodydb.InsertOwnerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster), SourceUid: id(s.source), ObservedAt: ts(at)})
		if e != nil {
			return e
		}
		h, e := q.LockOwnerConfiguration(ctx, custodydb.LockOwnerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster)})
		if e != nil {
			return e
		}
		if uid(h.SourceUid) != s.source {
			return value.ErrDenied
		}
		return q.FenceOwnerConfiguration(ctx, custodydb.FenceOwnerConfigurationParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, ObservedAt: ts(at)})
	})
}

func (s *OwnerConfigurations) AcknowledgeOwnerConfiguration(ctx context.Context, c value.OwnerConfiguration, r audit.Receipt) error {
	if s == nil || ctx == nil || !s.matches(c) || !r.ValidOwnerConfiguration(c) {
		return value.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		h, e := q.LockOwnerConfiguration(ctx, custodydb.LockOwnerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster)})
		if e != nil {
			return e
		}
		if uid(h.SourceUid) != s.source {
			return value.ErrDenied
		}
		v, e := q.ReadOwnerConfigurationRevision(ctx, custodydb.ReadOwnerConfigurationRevisionParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, Generation: c.Revision.Generation})
		if e != nil {
			return e
		}
		b, _ := json.Marshal(c)
		if !bytes.Equal(b, v.SnapshotJson) {
			return value.ErrDenied
		}
		b, _ = json.Marshal(r)
		if v.AuditReceiptJson != nil {
			if !bytes.Equal(b, v.AuditReceiptJson) {
				return value.ErrConflict
			}
			return nil
		}
		n, e := q.AcknowledgeOwnerConfiguration(ctx, custodydb.AcknowledgeOwnerConfigurationParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, Generation: c.Revision.Generation, AuditReceiptJson: b})
		if e != nil {
			return e
		}
		if n != 1 {
			return value.ErrConflict
		}
		return nil
	})
}

func (s *OwnerConfigurations) ReadOwnerConfiguration(ctx context.Context) (value.OwnerConfigurationObservation, error) {
	var out value.OwnerConfigurationObservation
	if s == nil || ctx == nil {
		return out, value.ErrInvalid
	}
	var diagnostic ownerConfigurationReadDiagnostic
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		var e error
		out, e = s.readOwnerConfiguration(ctx, q, &diagnostic)
		return e
	})
	if err != nil {
		return value.OwnerConfigurationObservation{}, diagnostic.failure(err)
	}
	return out, nil
}

// This is the original transaction body. Diagnostics use only the already-read
// rows, the original query errors and its one database clock sample. The caller
// still owns the same transaction, lock order, retries and sanitized sentinel.
func (s *OwnerConfigurations) readOwnerConfiguration(ctx context.Context, q *custodydb.Queries, diagnostic *ownerConfigurationReadDiagnostic) (value.OwnerConfigurationObservation, error) {
	var out value.OwnerConfigurationObservation
	diagnostic.reset()
	trust, e := q.ShareFleetTrust(ctx, id(s.installation))
	if e != nil {
		return out, diagnostic.query(ownerReadFleet, e)
	}
	h, e := q.ShareOwnerConfiguration(ctx, custodydb.ShareOwnerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster)})
	if e != nil {
		return out, diagnostic.query(ownerReadHead, e)
	}
	if uid(h.SourceUid) != s.source {
		return out, diagnostic.reject(ownerReadHeadSource)
	}
	if h.Generation == 0 {
		return out, diagnostic.reject(ownerReadHeadGeneration)
	}
	v, e := q.ReadOwnerConfigurationRevision(ctx, custodydb.ReadOwnerConfigurationRevisionParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, Generation: h.Generation})
	if e != nil {
		return out, diagnostic.query(ownerReadRevision, e)
	}
	var c value.OwnerConfiguration
	var r audit.Receipt
	// Preserve the original conjunction's exact short-circuit order.
	if json.Unmarshal(v.SnapshotJson, &c) != nil {
		return out, diagnostic.reject(ownerReadSnapshotDecode)
	}
	if !s.matches(c) {
		return out, diagnostic.reject(ownerReadSnapshotBinding)
	}
	if c.Suspended {
		return out, diagnostic.reject(ownerReadSnapshotSuspended)
	}
	if c.Revision.Generation != h.Generation {
		return out, diagnostic.reject(ownerReadSnapshotGeneration)
	}
	if c.Pool.IssuerEpoch != uid(trust.IssuerEpoch) {
		return out, diagnostic.reject(ownerReadSnapshotIssuer)
	}
	if json.Unmarshal(v.AuditReceiptJson, &r) != nil {
		return out, diagnostic.reject(ownerReadAuditDecode)
	}
	if !r.ValidOwnerConfiguration(c) {
		return out, diagnostic.reject(ownerReadAuditBinding)
	}
	n, e := q.CurrentTime(ctx)
	if e != nil {
		return out, diagnostic.query(ownerReadClock, e)
	}
	recovery, e := recoveryState(trust, h.ObservedAt.Time, n.Time)
	if e != nil {
		*diagnostic = ownerReadRecoveryFailure(trust, h.ObservedAt.Time, n.Time)
		return out, e
	}
	out = value.OwnerConfigurationObservation{Configuration: c, ObservedAt: h.ObservedAt.Time, FreshUntil: identity.Earlier(h.FreshUntil.Time, recovery.FreshUntil)}
	if !out.Valid(n.Time) {
		*diagnostic = ownerReadObservationFailure(out, n.Time)
		return out, value.ErrUnavailable
	}
	// A later COMMIT error must not be attributed to a previous callback or
	// predicate. Begin/SET failures and exhausted serialization/deadlock retries
	// deliberately retain only the generic transaction classification.
	diagnostic.reset()
	return out, nil
}
