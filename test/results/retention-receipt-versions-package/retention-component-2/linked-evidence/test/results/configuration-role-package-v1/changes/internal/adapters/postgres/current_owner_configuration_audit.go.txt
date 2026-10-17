package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This installed reconciler facet retains current recovery/source checks around
// the separate acknowledgement. Historical exact acknowledgement remains on
// OwnerConfigurations; no caller option can select that older path here.
type CurrentOwnerConfigurationAcknowledgements struct{ configuration *OwnerConfigurations }

var _ auditapp.OwnerConfigurationAcknowledgements = (*CurrentOwnerConfigurationAcknowledgements)(nil)

func NewCurrentOwnerConfigurationAcknowledgements(ctx context.Context, pool *pgxpool.Pool, installation, cluster, namespace, source string) (*CurrentOwnerConfigurationAcknowledgements, error) {
	c, e := NewOwnerConfigurations(ctx, pool, installation, cluster, namespace, source)
	if e != nil {
		return nil, e
	}
	return &CurrentOwnerConfigurationAcknowledgements{configuration: c}, nil
}
func (s *CurrentOwnerConfigurationAcknowledgements) AcknowledgeOwnerConfiguration(ctx context.Context, c value.OwnerConfiguration, r audit.Receipt) error {
	if s == nil || s.configuration == nil || ctx == nil || ctx.Err() != nil || !s.configuration.matches(c) || c.Suspended || !r.ValidOwnerConfiguration(c) {
		return value.ErrInvalid
	}
	base := s.configuration
	c = c.Clone()
	started := time.Now()
	live, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	// The transaction's own context must expire at a shorter source bound too,
	// including COMMIT after the callback. Join the cancellation callback before
	// releasing the operation; cancelling only the query child is insufficient.
	var sourceEnd context.CancelFunc
	var sourceStop func() bool
	var sourceJoined chan struct{}
	defer func() {
		if sourceStop != nil && !sourceStop() {
			<-sourceJoined
		}
		if sourceEnd != nil {
			sourceEnd()
		}
	}()
	return base.ledger.transaction(live, func(q *custodydb.Queries) error {
		trust, e := q.ShareFleetTrust(live, id(base.installation))
		if e != nil {
			return e
		}
		h, e := q.LockOwnerConfiguration(live, custodydb.LockOwnerConfigurationParams{InstallationID: id(base.installation), ClusterID: id(base.cluster)})
		if e != nil {
			return e
		}
		until := identity.Earlier(trust.FreshUntil.Time, h.FreshUntil.Time)
		bound, cancel := context.WithDeadline(live, until)
		sourceEnd = cancel
		sourceJoined = make(chan struct{})
		sourceStop = context.AfterFunc(bound, func() { end(); close(sourceJoined) })
		check := func() error {
			n, e := q.CurrentTime(bound)
			if e != nil {
				return e
			}
			recovery, e := recoveryState(trust, started, n.Time)
			if e != nil || recovery.IssuerEpoch != c.Pool.IssuerEpoch || uid(h.SourceUid) != base.source || h.Generation != c.Revision.Generation || !identity.Fresh(h.ObservedAt.Time, h.FreshUntil.Time, n.Time, 5*time.Second) || bound.Err() != nil {
				return value.ErrUnavailable
			}
			return nil
		}
		if e = check(); e != nil {
			return e
		}
		v, e := q.ReadOwnerConfigurationRevision(bound, custodydb.ReadOwnerConfigurationRevisionParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, Generation: c.Revision.Generation})
		if e != nil {
			return e
		}
		original, e := json.Marshal(c)
		if e != nil || !bytes.Equal(original, v.SnapshotJson) {
			return value.ErrDenied
		}
		receipt, e := json.Marshal(r)
		if e != nil {
			return value.ErrInvalid
		}
		if v.AuditReceiptJson != nil {
			if !bytes.Equal(receipt, v.AuditReceiptJson) {
				return value.ErrConflict
			}
			return check()
		}
		if e = check(); e != nil {
			return e
		}
		count, e := q.AcknowledgeOwnerConfiguration(bound, custodydb.AcknowledgeOwnerConfigurationParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, Generation: c.Revision.Generation, AuditReceiptJson: receipt})
		if e != nil {
			return e
		}
		if count != 1 {
			return value.ErrConflict
		}
		return check()
	})
}
