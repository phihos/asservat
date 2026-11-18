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
	corev1 "k8s.io/api/core/v1"
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
	// Each encoded version and its 32 JSON fingerprint integers take less
	// than three times the bytes of a version and its base64 key in the Secret.
	if e != nil || len(b) > 3*corev1.MaxSecretSize {
		return time.Time{}, app.ErrKeyUnavailable
	}
	var until time.Time
	e = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		check := func() error {
			now, e := q.CurrentTime(ctx)
			if e != nil {
				return e
			}
			if !c.Valid(now.Time) {
				return app.ErrKeyUnavailable
			}
			until = c.FreshUntil
			return nil
		}
		if e := check(); e != nil {
			return e
		}
		if e := q.InsertLocalKeyConfiguration(ctx, custodydb.InsertLocalKeyConfigurationParams{InstallationID: id(s.scope.InstallationID), Purpose: s.scope.Purpose, KeyID: s.scope.KeyID, SnapshotJson: b}); e != nil {
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
		// Retained versions are the unchanged prefix. An additive rotation can
		// append many versions in one Secret update and one database statement.
		if len(versions) > len(c.Versions) {
			return app.ErrKeyUnavailable
		}
		for i, saved := range versions {
			current := c.Versions[i]
			if int(saved.Version) != current.Version || !bytes.Equal(saved.Fingerprint, current.Fingerprint[:]) {
				return app.ErrKeyUnavailable
			}
		}
		added := c.Versions[len(versions):]
		if len(added) > 0 {
			numbers := make([]int32, len(added))
			fingerprints := make([][]byte, len(added))
			for i := range added {
				numbers[i] = int32(added[i].Version)
				fingerprints[i] = added[i].Fingerprint[:]
			}
			if e := q.InsertLocalKeyVersions(ctx, custodydb.InsertLocalKeyVersionsParams{
				InstallationID: id(s.scope.InstallationID), Purpose: s.scope.Purpose, KeyID: s.scope.KeyID,
				Versions: numbers, Fingerprints: fingerprints,
			}); e != nil {
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
