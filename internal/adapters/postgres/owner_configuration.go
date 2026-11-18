package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"

	app "asservat.local/asservat/internal/application/fleet"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/apimachinery/pkg/util/resourceversion"
)

type OwnerConfigurations struct {
	ledger                                   *Ledger
	installation, cluster, namespace, source string
}

var _ app.OwnerConfigurationLedger = (*OwnerConfigurations)(nil)
var _ app.OwnerConfigurationReader = (*OwnerConfigurations)(nil)

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

// ApplyOwnerConfiguration publishes one complete ConfigMap LIST or confirmed deletion.
// The shared head orders writers by Kubernetes cursor, independent of their clocks.
func (s *OwnerConfigurations) ApplyOwnerConfiguration(ctx context.Context, rv string, o value.OwnerConfigurationObservation) error {
	if s == nil || ctx == nil {
		return value.ErrInvalid
	}
	if _, err := resourceversion.CompareResourceVersion(rv, rv); err != nil {
		return value.ErrInvalid
	}
	present := !o.ObservedAt.IsZero()
	c := o.Configuration
	var body []byte
	if present {
		if !s.matches(c) || !o.CurrentSource(o.ObservedAt) {
			return value.ErrInvalid
		}
		var err error
		body, err = json.Marshal(c)
		if err != nil || len(body) > 64<<10 {
			return value.ErrInvalid
		}
	}
	var refusal error
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		refusal = nil
		_, err := q.InsertOwnerConfiguration(ctx, custodydb.InsertOwnerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster), SourceUid: id(s.source)})
		if err != nil {
			return err
		}
		h, err := q.LockOwnerConfiguration(ctx, custodydb.LockOwnerConfigurationParams{InstallationID: id(s.installation), ClusterID: id(s.cluster)})
		if err != nil {
			return err
		}
		if uid(h.SourceUid) != s.source {
			return value.ErrDenied
		}
		order := 1
		if h.SourceVersion != "" {
			order, err = resourceversion.CompareResourceVersion(rv, h.SourceVersion)
			if err != nil {
				return value.ErrUnavailable
			}
		}
		// A later published LIST or deletion already covers a superseded cursor.
		if order < 0 {
			return nil
		}
		fence := func(reason error) error {
			refusal = reason
			count, err := q.FenceOwnerConfiguration(ctx, custodydb.FenceOwnerConfigurationParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, SourceVersion: rv})
			if err == nil && count != 1 {
				return value.ErrUnavailable
			}
			return err
		}
		if !present {
			return fence(nil)
		}
		if order == 0 && !h.FreshUntil.Time.After(h.ObservedAt.Time) {
			refusal = value.ErrConflict
			return nil
		}
		if c.Revision.Generation < h.Generation {
			return fence(value.ErrConflict)
		}
		old, err := q.ReadOwnerConfigurationRevision(ctx, custodydb.ReadOwnerConfigurationRevisionParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, Generation: c.Revision.Generation})
		if err == nil {
			if !bytes.Equal(old.SnapshotJson, body) {
				return fence(value.ErrConflict)
			}
			if order == 0 {
				if c.Revision.Generation != h.Generation || ownerTime(o.FreshUntil).After(h.FreshUntil.Time) {
					refusal = value.ErrConflict
				}
				return nil
			}
		} else if errors.Is(err, pgx.ErrNoRows) && order > 0 {
			err = q.InsertOwnerConfigurationRevision(ctx, custodydb.InsertOwnerConfigurationRevisionParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, Generation: c.Revision.Generation, SnapshotJson: body})
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		return q.ObserveOwnerConfiguration(ctx, custodydb.ObserveOwnerConfigurationParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, SourceVersion: rv, Generation: c.Revision.Generation, FreshUntil: ts(o.FreshUntil)})
	})
	if err != nil {
		return err
	}
	return refusal
}

func (s *OwnerConfigurations) ReadOwnerConfiguration(ctx context.Context) (value.OwnerConfigurationObservation, error) {
	var out value.OwnerConfigurationObservation
	if s == nil || ctx == nil {
		return out, value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
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
	localStart := time.Now()
	n, e := q.CurrentTime(ctx)
	if e != nil {
		return out, diagnostic.query(ownerReadClock, e)
	}
	out = value.OwnerConfigurationObservation{Configuration: c, ObservedAt: h.ObservedAt.Time, FreshUntil: h.FreshUntil.Time}
	out = out.ForOperation(n.Time)
	if !out.Valid(n.Time) {
		*diagnostic = ownerReadObservationFailure(out, n.Time)
		return out, value.ErrUnavailable
	}
	offset := clockOffsetAt(localStart, n.Time)
	out.ObservedAt, out.FreshUntil = offset.at(out.ObservedAt), offset.at(out.FreshUntil)
	if until, ok := ctx.Deadline(); ok && until.Before(out.FreshUntil) {
		out.FreshUntil = until
	}
	// A later COMMIT error must not be attributed to a previous callback or
	// predicate. Begin/SET failures and exhausted serialization/deadlock retries
	// deliberately retain only the generic transaction classification.
	diagnostic.reset()
	return out, nil
}
