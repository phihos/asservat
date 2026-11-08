package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RecoveryReader struct {
	ledger       *Ledger
	installation string
	window       time.Duration
}

// ForEvidenceReads returns a reader whose observations stay current for up to
// identity.AuthorityRecheckInterval (ADR-311; still bounded by the trust row's
// own fresh_until and the 20 s evidence-read request). Only evidence-read
// composition may use it. The default reader keeps five seconds: SQL fences
// that persist recovery proofs (connector enrollment, migration 00049;
// capacity_recovery_current, 00054/00065/00073) admit at most five seconds.
func (s *RecoveryReader) ForEvidenceReads() *RecoveryReader {
	if s == nil {
		return nil
	}
	out := *s
	out.window = identity.AuthorityRecheckInterval
	return &out
}

var _ app.RecoveryReader = (*RecoveryReader)(nil)

func NewRecoveryReader(ctx context.Context, pool *pgxpool.Pool, installation string) (*RecoveryReader, error) {
	if !authorization.UUID(installation) {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &RecoveryReader{ledger: l, installation: installation}, nil
}
func recoveryState(row custodydb.FleetCurrentTrust, started, now time.Time) (value.RecoveryState, error) {
	return recoveryStateWithin(row, started, now, 5*time.Second)
}
func recoveryStateWithin(row custodydb.FleetCurrentTrust, started, now time.Time, window time.Duration) (value.RecoveryState, error) {
	if window <= 0 || window > identity.AuthorityRecheckInterval {
		window = 5 * time.Second
	}
	if row.Suspended || row.RecoveryBlocked || !identity.Fresh(row.ObservedAt.Time, row.FreshUntil.Time, now, 30*time.Second) {
		return value.RecoveryState{}, value.ErrUnavailable
	}
	out := value.RecoveryState{InstallationID: uid(row.InstallationID), IssuerEpoch: uid(row.IssuerEpoch), Revision: trustRevision(row), ObservedAt: started, FreshUntil: identity.Earlier(started.Add(window), row.FreshUntil.Time)}
	if !out.Valid(now) {
		return value.RecoveryState{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *RecoveryReader) RecoveryState(ctx context.Context) (value.RecoveryState, error) {
	var out value.RecoveryState
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		start, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		row, err := q.ReadFleetTrust(ctx, id(s.installation))
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		out, err = recoveryStateWithin(row, start.Time, now.Time, s.window)
		return err
	})
	if err != nil {
		return value.RecoveryState{}, value.ErrUnavailable
	}
	return out, nil
}

// The installation/root association is accepted private composition, not a
// caller-selected ID from its environment proof. Lock BEFORE the permission root
// and retain that lock for every final check and write in the effect transaction.
type RecoveryTransactionGuard struct{ root, installation string }

func NewRecoveryTransactionGuard(root, installation string) (*RecoveryTransactionGuard, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) {
		return nil, value.ErrInvalid
	}
	return &RecoveryTransactionGuard{root, installation}, nil
}

// installationID is the guard's private installation, or "" without a guard.
func (g *RecoveryTransactionGuard) installationID() string {
	if g == nil {
		return ""
	}
	return g.installation
}
func (g *RecoveryTransactionGuard) lock(ctx context.Context, q *custodydb.Queries, root string, a artifact.RecoveryProof) (custodydb.FleetCurrentTrust, error) {
	if g == nil || root != g.root || a.InstallationID != g.installation {
		return custodydb.FleetCurrentTrust{}, value.ErrUnavailable
	}
	row, err := q.ShareFleetTrust(ctx, id(g.installation))
	if err != nil {
		return row, err
	}
	return row, g.check(ctx, q, row, root, a)
}
func (g *RecoveryTransactionGuard) check(ctx context.Context, q *custodydb.Queries, row custodydb.FleetCurrentTrust, root string, a artifact.RecoveryProof) error {
	if g == nil {
		return value.ErrUnavailable
	}
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return err
	}
	if !a.Valid(now.Time) || root != g.root || a.InstallationID != g.installation || uid(row.InstallationID) != g.installation || a.IssuerEpoch != uid(row.IssuerEpoch) || a.Revision != trustRevision(row) || a.FreshUntil.After(row.FreshUntil.Time) {
		return value.ErrDenied
	}
	// The proof keeps its own producer interval (five seconds, or the
	// evidence-read window); the trust row still bounds it above.
	_, err = recoveryStateWithin(row, a.ObservedAt, now.Time, a.FreshUntil.Sub(a.ObservedAt))
	return err
}

// lockStarted serves a started download response's continuation (ADR-312).
// The installation must still be the incarnation the response started under
// and neither suspended nor recovery-blocked; observation freshness and the
// trust source revision are not reobserved.
func (g *RecoveryTransactionGuard) lockStarted(ctx context.Context, q *custodydb.Queries, root string, a artifact.RecoveryProof) (custodydb.FleetCurrentTrust, error) {
	if g == nil || root != g.root || a.InstallationID != g.installation {
		return custodydb.FleetCurrentTrust{}, value.ErrUnavailable
	}
	row, err := q.ShareFleetTrust(ctx, id(g.installation))
	if err != nil {
		return row, err
	}
	return row, g.checkStarted(row, root, a)
}
func (g *RecoveryTransactionGuard) checkStarted(row custodydb.FleetCurrentTrust, root string, a artifact.RecoveryProof) error {
	if g == nil || root != g.root || a.InstallationID != g.installation || uid(row.InstallationID) != g.installation || a.IssuerEpoch != uid(row.IssuerEpoch) || row.Suspended || row.RecoveryBlocked {
		return value.ErrDenied
	}
	return nil
}

// Read/audit/configuration facets may omit guards. All effect methods reject
// that composition; both guards bind the same private permission root.
type EffectTransactionGuards struct {
	Retention *RetentionTransactionGuard
	Recovery  *RecoveryTransactionGuard
}

func effectGuardsFor(root string, guards []EffectTransactionGuards) (EffectTransactionGuards, error) {
	if len(guards) == 0 {
		return EffectTransactionGuards{}, nil
	}
	if len(guards) != 1 || guards[0].Retention == nil || guards[0].Recovery == nil || guards[0].Retention.root != root || guards[0].Recovery.root != root {
		return EffectTransactionGuards{}, artifact.ErrInvalid
	}
	return guards[0], nil
}
