package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/authorization"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Only the isolated key service uses this facet, with independently enrolled
// source pins. It receives fingerprints, never the private Secret payload.
type LocalKeyConfigurations struct {
	ledger                     *Ledger
	scope                      value.KeyScope
	cluster, namespace, source string
}

var _ app.KeyConfigurationLedger = (*LocalKeyConfigurations)(nil)

func NewLocalKeyConfigurations(ctx context.Context, pool *pgxpool.Pool, scope value.KeyScope, cluster, namespace, source string) (*LocalKeyConfigurations, error) {
	if !scope.Valid() || !value.UUID(cluster) || !identity.Text(namespace, 64) || !identity.Text(source, 64) {
		return nil, app.ErrKeyUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &LocalKeyConfigurations{l, scope, cluster, namespace, source}, nil
}
func (s *LocalKeyConfigurations) ObserveLocalKeys(ctx context.Context, c value.LocalKeyConfiguration) (time.Time, error) {
	if s == nil || ctx == nil || !c.Valid(c.ObservedAt) || c.Scope != s.scope || c.ClusterID != s.cluster || c.NamespaceUID != s.namespace || c.Revision.UID != s.source {
		return time.Time{}, app.ErrKeyUnavailable
	}
	// Own a stable public snapshot across I/O; no plaintext key bytes exist here.
	c.Versions = append([]value.LocalKeyVersion(nil), c.Versions...)
	b, e := json.Marshal(c)
	if e != nil || len(b) > 16384 {
		return time.Time{}, app.ErrKeyUnavailable
	}
	var until time.Time
	e = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, e := q.ShareFleetTrust(ctx, id(s.scope.InstallationID))
		if e != nil {
			return e
		}
		start, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		check := func() error {
			now, e := q.CurrentTime(ctx)
			if e != nil {
				return e
			}
			recovery, e := recoveryState(trust, start.Time, now.Time)
			if e != nil || !c.Valid(now.Time) || recovery.IssuerEpoch != c.RecoveryEpoch {
				return app.ErrKeyUnavailable
			}
			until = identity.Earlier(c.FreshUntil, recovery.FreshUntil)
			return nil
		}
		if e = check(); e != nil {
			return e
		}
		if e = q.InsertLocalKeyConfiguration(ctx, custodydb.InsertLocalKeyConfigurationParams{InstallationID: id(s.scope.InstallationID), Purpose: s.scope.Purpose, KeyID: s.scope.KeyID, SnapshotJson: b}); e != nil {
			return e
		}
		saved, e := q.LockLocalKeyConfiguration(ctx, custodydb.LockLocalKeyConfigurationParams{InstallationID: id(s.scope.InstallationID), Purpose: s.scope.Purpose, KeyID: s.scope.KeyID})
		if e != nil {
			return e
		}
		if e = check(); e != nil {
			return e
		}
		var old value.LocalKeyConfiguration
		if json.Unmarshal(saved, &old) != nil || !old.Valid(old.ObservedAt) || old.Scope != c.Scope || old.ClusterID != c.ClusterID || old.NamespaceUID != c.NamespaceUID || old.Revision.UID != c.Revision.UID || old.Revision.Generation > c.Revision.Generation || old.ActiveVersion > c.ActiveVersion || (old.Revision.Generation == c.Revision.Generation && !old.SameSnapshot(c)) {
			return app.ErrKeyUnavailable
		}
		versions, e := q.ReadLocalKeyVersions(ctx, custodydb.ReadLocalKeyVersionsParams{InstallationID: id(s.scope.InstallationID), Purpose: s.scope.Purpose, KeyID: s.scope.KeyID})
		if e != nil {
			return e
		}
		present := make(map[int][]byte, len(c.Versions))
		for _, v := range c.Versions {
			present[v.Version] = v.Fingerprint[:]
		}
		last := 0
		for _, v := range versions {
			if !bytes.Equal(v.Fingerprint, present[int(v.Version)]) {
				return app.ErrKeyUnavailable
			} // No retirement without obligation qualification.
			last = int(v.Version)
		}
		for _, v := range c.Versions {
			if v.Version <= last {
				found := false
				for _, prior := range versions {
					if int(prior.Version) == v.Version {
						found = true
					}
				}
				if !found {
					return app.ErrKeyUnavailable
				}
				continue
			}
			if e = q.InsertLocalKeyVersion(ctx, custodydb.InsertLocalKeyVersionParams{InstallationID: id(s.scope.InstallationID), Purpose: s.scope.Purpose, KeyID: s.scope.KeyID, Version: int32(v.Version), Fingerprint: v.Fingerprint[:]}); e != nil {
				return e
			}
		}
		if !old.SameSnapshot(c) {
			if e = q.UpdateLocalKeyConfiguration(ctx, custodydb.UpdateLocalKeyConfigurationParams{InstallationID: id(s.scope.InstallationID), Purpose: s.scope.Purpose, KeyID: s.scope.KeyID, SnapshotJson: b}); e != nil {
				return e
			}
		}
		return check()
	})
	if e != nil {
		return time.Time{}, app.ErrKeyUnavailable
	}
	return until, nil
}
