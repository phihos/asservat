package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type WorkerConfigurations struct {
	ledger                                   *Ledger
	installation, cluster, namespace, source string
}

var _ evidence.WorkerConfigurationLedger = (*WorkerConfigurations)(nil)
var _ evidence.WorkerConfigurationGuard = (*WorkerConfigurations)(nil)
var _ auditapp.WorkerConfigurationAcknowledgements = (*WorkerConfigurations)(nil)

func NewWorkerConfigurations(ctx context.Context, pool *pgxpool.Pool, installation, cluster, namespace, source string) (*WorkerConfigurations, error) {
	if !value.UUID(installation) || !value.UUID(cluster) || !value.UUID(source) || !identity.Text(namespace, 64) {
		return nil, artifact.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &WorkerConfigurations{l, installation, cluster, namespace, source}, nil
}
func (s *WorkerConfigurations) matches(p value.DownloadWorkerProfile) bool {
	return p.Valid() && p.InstallationID == s.installation && p.ClusterID == s.cluster && p.NamespaceUID == s.namespace && p.Configuration.UID == s.source
}
func (s *WorkerConfigurations) ObserveWorkerConfiguration(ctx context.Context, o value.DownloadWorkerObservation) (audit.Receipt, bool, error) {
	var receipt audit.Receipt
	var ack bool
	if s == nil || ctx == nil || !o.Valid(o.ObservedAt) || !s.matches(o.Configuration.Profile) {
		return receipt, false, artifact.ErrInvalid
	}
	ctx, end := context.WithDeadline(ctx, o.FreshUntil)
	defer end()
	c := o.Configuration
	p := c.Profile
	b, e := json.Marshal(c)
	if e != nil || len(b) > 16384 {
		return receipt, false, artifact.ErrInvalid
	}
	e = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, e := q.ShareFleetTrust(ctx, id(s.installation))
		if e != nil {
			return e
		}
		check := func() error {
			n, e := q.CurrentTime(ctx)
			if e != nil {
				return e
			}
			recovery, e := recoveryState(trust, o.ObservedAt, n.Time)
			if e != nil || !o.Valid(n.Time) || recovery.IssuerEpoch != c.RecoveryEpoch {
				return artifact.ErrDownloadExpired
			}
			return nil
		}
		if e = check(); e != nil {
			return e
		}
		if e = q.InsertWorkerConfiguration(ctx, custodydb.InsertWorkerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster), SourceUid: id(s.source), Generation: p.Configuration.Generation, ObservedAt: ts(o.ObservedAt), FreshUntil: ts(o.FreshUntil)}); e != nil {
			return e
		}
		head, e := q.LockWorkerConfiguration(ctx, custodydb.LockWorkerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster), SourceUid: id(s.source)})
		if e != nil {
			return e
		}
		if e = check(); e != nil {
			return e
		}
		if head.Generation > p.Configuration.Generation || o.ObservedAt.Before(head.ObservedAt.Time) {
			return artifact.ErrDownloadConflict
		}
		old, e := q.ReadWorkerConfigurationRevision(ctx, custodydb.ReadWorkerConfigurationRevisionParams{InstallationID: head.InstallationID, ClusterID: head.ClusterID, SourceUid: head.SourceUid, Generation: p.Configuration.Generation})
		if e == nil {
			if !bytes.Equal(old.SnapshotJson, b) {
				return artifact.ErrDownloadConflict
			}
			if old.AuditReceiptJson != nil {
				if json.Unmarshal(old.AuditReceiptJson, &receipt) != nil || !receipt.ValidWorkerConfiguration(c) {
					return artifact.ErrIntegrity
				}
				ack = true
			}
		} else if errors.Is(e, pgx.ErrNoRows) {
			count, e := q.CountWorkerConfigurationRevisions(ctx, custodydb.CountWorkerConfigurationRevisionsParams{InstallationID: head.InstallationID, ClusterID: head.ClusterID, SourceUid: head.SourceUid})
			if e != nil {
				return e
			}
			if count >= 1024 {
				return artifact.ErrDownloadCapacity
			}
			if e = q.InsertWorkerConfigurationRevision(ctx, custodydb.InsertWorkerConfigurationRevisionParams{InstallationID: head.InstallationID, ClusterID: head.ClusterID, SourceUid: head.SourceUid, Generation: p.Configuration.Generation, SnapshotJson: b}); e != nil {
				return e
			}
		} else {
			return e
		}
		if e = q.ObserveWorkerConfiguration(ctx, custodydb.ObserveWorkerConfigurationParams{InstallationID: head.InstallationID, ClusterID: head.ClusterID, SourceUid: head.SourceUid, Generation: p.Configuration.Generation, ObservedAt: ts(o.ObservedAt), FreshUntil: ts(o.FreshUntil)}); e != nil {
			return e
		}
		return check()
	})
	if e != nil {
		return audit.Receipt{}, false, e
	}
	return receipt, ack, nil
}
func (s *WorkerConfigurations) AcknowledgeWorkerConfiguration(ctx context.Context, c value.DownloadWorkerConfiguration, r audit.Receipt) error {
	if s == nil || ctx == nil || !s.matches(c.Profile) || !r.ValidWorkerConfiguration(c) {
		return artifact.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		head, e := q.LockWorkerConfiguration(ctx, custodydb.LockWorkerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster), SourceUid: id(s.source)})
		if e != nil {
			return e
		}
		old, e := q.ReadWorkerConfigurationRevision(ctx, custodydb.ReadWorkerConfigurationRevisionParams{InstallationID: head.InstallationID, ClusterID: head.ClusterID, SourceUid: head.SourceUid, Generation: c.Profile.Configuration.Generation})
		if e != nil {
			return e
		}
		b, _ := json.Marshal(c)
		if !bytes.Equal(old.SnapshotJson, b) {
			return artifact.ErrIntegrity
		}
		receipt, _ := json.Marshal(r)
		if old.AuditReceiptJson != nil {
			if !bytes.Equal(old.AuditReceiptJson, receipt) {
				return artifact.ErrIntegrity
			}
			return nil
		}
		n, e := q.AcknowledgeWorkerConfiguration(ctx, custodydb.AcknowledgeWorkerConfigurationParams{InstallationID: head.InstallationID, ClusterID: head.ClusterID, SourceUid: head.SourceUid, Generation: c.Profile.Configuration.Generation, AuditReceiptJson: receipt})
		if e != nil {
			return e
		}
		if n != 1 {
			return artifact.ErrDownloadConflict
		}
		return nil
	})
}
func (s *WorkerConfigurations) FenceWorkerConfiguration(ctx context.Context, started time.Time) error {
	if s == nil || ctx == nil || started.IsZero() {
		return artifact.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if started.After(n.Time) {
			return artifact.ErrInvalid
		}
		return q.FenceWorkerConfiguration(ctx, custodydb.FenceWorkerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster), SourceUid: id(s.source), ObservedAt: ts(started)})
	})
}

// Called with the current recovery row locked. The shared head lock prevents
// configuration changes until the enclosing effect completes. Check time again
// after every blocking lock and before commit; no old lease is renewed here.
func currentWorkerConfiguration(ctx context.Context, q *custodydb.Queries, p value.DownloadWorkerProfile, epoch string) (time.Time, error) {
	var zero time.Time
	if !p.Valid() {
		return zero, artifact.ErrInvalid
	}
	head, e := q.ShareWorkerConfiguration(ctx, custodydb.ShareWorkerConfigurationParams{InstallationID: id(p.InstallationID), ClusterID: id(p.ClusterID), SourceUid: id(p.Configuration.UID)})
	if e != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	r, e := q.ReadWorkerConfigurationRevision(ctx, custodydb.ReadWorkerConfigurationRevisionParams{InstallationID: head.InstallationID, ClusterID: head.ClusterID, SourceUid: head.SourceUid, Generation: head.Generation})
	if e != nil {
		return zero, e
	}
	var c value.DownloadWorkerConfiguration
	var receipt audit.Receipt
	if json.Unmarshal(r.SnapshotJson, &c) != nil || !c.Valid() || c.Suspended || c.Profile != p || c.RecoveryEpoch != epoch || json.Unmarshal(r.AuditReceiptJson, &receipt) != nil || !receipt.ValidWorkerConfiguration(c) {
		return zero, artifact.ErrDownloadUnavailable
	}
	n, e := q.CurrentTime(ctx)
	if e != nil {
		return zero, e
	}
	if !identity.Fresh(head.ObservedAt.Time, head.FreshUntil.Time, n.Time, 5*time.Second) {
		return zero, artifact.ErrDownloadExpired
	}
	return head.FreshUntil.Time, nil
}
func (s *WorkerConfigurations) CurrentWorkerConfiguration(ctx context.Context, p value.DownloadWorkerProfile) (time.Time, error) {
	var until time.Time
	if s == nil || ctx == nil || !s.matches(p) {
		return until, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	e := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, e := q.ShareFleetTrust(ctx, id(s.installation))
		if e != nil {
			return e
		}
		start, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		until, e = currentWorkerConfiguration(ctx, q, p, uid(trust.IssuerEpoch))
		if e != nil {
			return e
		}
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		recovery, e := recoveryState(trust, start.Time, n.Time)
		if e != nil || !n.Time.Before(until) {
			return artifact.ErrDownloadExpired
		}
		until = identity.Earlier(until, recovery.FreshUntil)
		return nil
	})
	if e != nil {
		return time.Time{}, e
	}
	return until, nil
}
