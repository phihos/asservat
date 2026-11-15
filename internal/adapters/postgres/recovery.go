package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// trustWire is the fleet trust shape that the capacity and connector SQL
// functions still read under the JSON key "Recovery". The adapter builds it
// from the trust row in its own transaction; callers never carry it.
type trustWire struct {
	InstallationID, IssuerEpoch string
	Revision                    identity.Revision
	ObservedAt, FreshUntil      time.Time
}

// currentTrust reads the installation's fleet trust row and the database
// time. The returned wire is valid for at most five seconds and never past
// the trust row's own freshness.
func currentTrust(ctx context.Context, q *custodydb.Queries, installation string) (custodydb.FleetCurrentTrust, trustWire, error) {
	row, err := q.ReadFleetTrust(ctx, id(installation))
	if err != nil {
		return row, trustWire{}, err
	}
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return row, trustWire{}, err
	}
	n := now.Time.UTC().Truncate(time.Microsecond)
	return row, trustWire{InstallationID: uid(row.InstallationID), IssuerEpoch: uid(row.IssuerEpoch), Revision: trustRevision(row),
		ObservedAt: n, FreshUntil: identity.Earlier(n.Add(5*time.Second), row.FreshUntil.Time)}, nil
}

// retentionGuardFor accepts no guard (read, audit and configuration facets)
// or exactly one guard bound to root.
func retentionGuardFor(root string, guards []*RetentionTransactionGuard) (*RetentionTransactionGuard, error) {
	if len(guards) == 0 {
		return nil, nil
	}
	if len(guards) != 1 || guards[0] == nil || guards[0].root != root {
		return nil, artifact.ErrInvalid
	}
	return guards[0], nil
}

func trustRevision(root custodydb.FleetCurrentTrust) identity.Revision {
	r := identity.Revision{UID: root.SourceUid, Generation: root.SourceGeneration}
	copy(r.Digest[:], root.SourceDigest)
	return r
}
