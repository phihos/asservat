package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// trustWire is the fleet trust shape that the capacity SQL functions still
// read under the JSON key "Recovery". The adapter builds it
// from the trust row in its own transaction; callers never carry it.
type trustWire struct {
	InstallationID, IssuerEpoch string
	Revision                    identity.Revision
	ObservedAt, FreshUntil      time.Time
}

// currentTrust reads the installation's fleet trust row and the database
// time, and refuses a suspended or stale row (as the removed recovery guards
// did). The returned wire is valid for at most five seconds and never past
// the trust row's own freshness. It takes no row lock: several callers hold
// read-only roles, and a suspension racing one effect is within the ADR-311
// authority reuse window.
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
	if row.Suspended || !identity.Fresh(row.ObservedAt.Time, row.FreshUntil.Time, n, 30*time.Second) {
		return row, trustWire{}, value.ErrUnavailable
	}
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
