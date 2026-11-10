package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	v "asservat.local/asservat/internal/domain/live"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LiveWatches persists only control/accounting. The existing owner registry
// remains the authority; a stored process UUID or an opaque fence is not one.
type LiveWatches struct {
	ledger       *Ledger
	root, owner  string
	registry     *OwnerEnrollments
	certificate  func(context.Context) (fleet.OwnerCertificate, error)
	limits       LiveWatchLimits
	limitsDigest [32]byte
	limitsJSON   []byte
}

var _ liveapp.Ledger = (*LiveWatches)(nil)

func NewLiveWatches(ctx context.Context, pool *pgxpool.Pool, root, owner string, registry *OwnerEnrollments, certificate func(context.Context) (fleet.OwnerCertificate, error), limits LiveWatchLimits) (*LiveWatches, error) {
	if ctx == nil || !authorization.UUID(root) || !authorization.UUID(owner) || registry == nil || registry.configuration == nil || certificate == nil || !limits.Valid() {
		return nil, fmt.Errorf("%w: live_watch:37", v.ErrInvalid)
	}
	ledger, err := New(ctx, pool)
	if err != nil {
		return nil, fmt.Errorf("%w: live_watch:41", v.ErrUnavailable)
	}
	encoded, err := json.Marshal(limits)
	if err != nil {
		return nil, fmt.Errorf("%w: live_watch:45", v.ErrInvalid)
	}
	return &LiveWatches{ledger: ledger, root: root, owner: owner, registry: registry, certificate: certificate, limits: limits, limitsDigest: sha256.Sum256(encoded), limitsJSON: encoded}, nil
}

func (s *LiveWatches) ownerCurrent(ctx context.Context) (fleet.OwnerRegistrationObservation, error) {
	var zero fleet.OwnerRegistrationObservation
	if s == nil || s.registry == nil || s.certificate == nil || ctx == nil || ctx.Err() != nil {
		return zero, fmt.Errorf("%w: live_watch:53", v.ErrUnavailable)
	}
	c, err := s.certificate(ctx)
	if err != nil || c.Binding.ProcessEpoch != s.owner || c.Usage != "server" {
		return zero, fmt.Errorf("%w: live_watch:57", v.ErrUnavailable)
	}
	proof, err := s.registry.ReadOwnerRegistration(ctx, c)
	if err != nil || proof.Certificate != c || proof.Enrollment.Binding.ProcessEpoch != s.owner || !proof.Valid(time.Now()) {
		return zero, fmt.Errorf("%w: live_watch:61", v.ErrUnavailable)
	}
	return proof, nil
}
func liveBound(ctx context.Context, q *custodydb.Queries, until time.Time) error {
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return err
	}
	if !n.Time.Before(until) || ctx.Err() != nil {
		return privacy.ErrExpired
	}
	return nil
}
func liveSQLError(err error) error {
	var p *pgconn.PgError
	if errors.As(err, &p) {
		switch p.Code {
		case "23505":
			return privacy.ErrConflict
		case "54000":
			return privacy.ErrCapacity
		}
	}
	return err
}
func liveError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, privacy.ErrConflict) {
		return fmt.Errorf("%w: live_watch:92", v.ErrConflict)
	}
	if errors.Is(err, privacy.ErrCapacity) {
		return fmt.Errorf("%w: live_watch:95", v.ErrCapacity)
	}
	return fmt.Errorf("%w: live_watch:97", v.ErrUnavailable)
}
func normalizedLive(c liveapp.Control) liveapp.Control {
	c.AcceptedAt = ownerTime(c.AcceptedAt)
	c.ExpiresAt = ownerTime(c.ExpiresAt)
	c.IdleUntil = ownerTime(c.IdleUntil)
	return c
}
func liveClusterKey(cluster string) ([32]byte, bool) {
	if !authorization.UUID(cluster) {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte("asservat-live-cluster/v1\x00" + cluster)), true
}
func decodeLive(raw []byte) (liveapp.Control, error) {
	var c liveapp.Control
	if queryDecode(raw, 4096, &c) != nil || !liveControlValid(c) {
		return c, fmt.Errorf("%w: live_watch:108", v.ErrUnavailable)
	}
	return normalizedLive(c), nil
}
func (s *LiveWatches) Create(ctx context.Context, cluster string, c liveapp.Control, key string) (liveapp.Control, bool, error) {
	var zero liveapp.Control
	c = normalizedLive(c)
	k, err := hex.DecodeString(key)
	clusterKey, clusterOK := liveClusterKey(cluster)
	if s == nil || c.OwnerID != s.owner || !liveControlValid(c) || c.State != "Active" || c.Revision != 1 || c.Spent != 0 || !clusterOK || err != nil || len(k) != 32 || hex.EncodeToString(k) != key {
		return zero, false, fmt.Errorf("%w: live_watch:117", v.ErrInvalid)
	}
	proof, err := s.ownerCurrent(ctx)
	if err != nil {
		return zero, false, err
	}
	call, stop := context.WithDeadline(ctx, proof.FreshUntil)
	defer stop()
	body, _ := json.Marshal(c)
	configurationUnavailable := false
	var out struct {
		Control json.RawMessage `json:"control"`
		Reused  bool            `json:"reused"`
	}
	err = s.ledger.transaction(call, func(q *custodydb.Queries) error {
		// Runtime enrollment starts after construction. Configure only under
		// the actual current owner proof, in the same Open transaction.
		ok, err := q.ConfigureLiveWatch(call, custodydb.ConfigureLiveWatchParams{RootID: id(s.root), InstallationID: id(proof.Certificate.Binding.InstallationID), IssuerEpoch: id(proof.Certificate.Binding.IssuerEpoch), LimitsDigest: s.limitsDigest[:], Limits: s.limitsJSON})
		if err != nil {
			return liveSQLError(err)
		}
		if !ok {
			// Commit bounded restrictive maintenance even when debt/receipts
			// still prevent the new limits. Otherwise every Open would roll
			// back the same first page forever. No new control is admitted.
			configurationUnavailable = true
			return liveBound(call, q, proof.FreshUntil)
		}
		raw, err := q.CreateLiveWatch(call, custodydb.CreateLiveWatchParams{RootID: id(s.root), OwnerID: id(s.owner), LimitsDigest: s.limitsDigest[:], Control: body, KeyHash: k, OriginalUntil: ts(proof.FreshUntil), ClusterKey: clusterKey[:]})
		if err != nil {
			return liveSQLError(err)
		}
		if queryDecode(raw, 8192, &out) != nil {
			return privacy.ErrUnavailable
		}
		return liveBound(call, q, proof.FreshUntil)
	})
	if err != nil {
		return zero, false, liveError(err)
	}
	if configurationUnavailable {
		return zero, false, fmt.Errorf("%w: live_watch:158", v.ErrUnavailable)
	}
	stored, err := decodeLive(out.Control)
	if err != nil || stored.OwnerID != s.owner || stored.PrincipalKey != c.PrincipalKey || stored.RequestDigest != c.RequestDigest {
		return zero, false, fmt.Errorf("%w: live_watch:162", v.ErrUnavailable)
	}
	if !out.Reused && stored != c {
		return zero, false, fmt.Errorf("%w: live_watch:165", v.ErrUnavailable)
	}
	return stored, out.Reused, nil
}
func (s *LiveWatches) Change(ctx context.Context, c liveapp.Control, revision, cost int64) (liveapp.Control, error) {
	var zero liveapp.Control
	c = normalizedLive(c)
	if s == nil || !liveControlValid(c) || c.OwnerID != s.owner || revision < 1 || cost < 0 || cost > 24<<10 || ctx == nil || ctx.Err() != nil {
		return zero, fmt.Errorf("%w: live_watch:173", v.ErrInvalid)
	}
	// Closing this exact owner/fence is restrictive and discloses nothing. Like
	// existing logout/stop paths, it remains possible during registry outages.
	until := time.Now().Add(5 * time.Second)
	if c.State != "Closed" {
		proof, err := s.ownerCurrent(ctx)
		if err != nil {
			return zero, err
		}
		until = proof.FreshUntil
	}
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	body, _ := json.Marshal(c)
	var raw []byte
	err := s.ledger.transaction(call, func(q *custodydb.Queries) error {
		var e error
		raw, e = q.ChangeLiveWatch(call, custodydb.ChangeLiveWatchParams{RootID: id(s.root), OwnerID: id(s.owner), LimitsDigest: s.limitsDigest[:], Control: body, ExpectedRevision: revision, Cost: cost, OriginalUntil: ts(until)})
		if e != nil {
			return liveSQLError(e)
		}
		return liveBound(call, q, until)
	})
	if err != nil {
		return zero, liveError(err)
	}
	out, err := decodeLive(raw)
	if err != nil || out != c {
		return zero, fmt.Errorf("%w: live_watch:202", v.ErrUnavailable)
	}
	return out, nil
}
func (s *LiveWatches) CurrentLive(ctx context.Context, c liveapp.Control) error {
	c = normalizedLive(c)
	if s == nil || !liveControlValid(c) || c.OwnerID != s.owner {
		return fmt.Errorf("%w: live_watch:209", v.ErrInvalid)
	}
	proof, err := s.ownerCurrent(ctx)
	if err != nil {
		return err
	}
	call, stop := context.WithDeadline(ctx, proof.FreshUntil)
	defer stop()
	body, _ := json.Marshal(c)
	refused := false
	err = s.ledger.transaction(call, func(q *custodydb.Queries) error {
		refused = false
		ok, e := q.CurrentLiveWatch(call, custodydb.CurrentLiveWatchParams{RootID: id(s.root), OwnerID: id(s.owner), LimitsDigest: s.limitsDigest[:], Control: body, OriginalUntil: ts(proof.FreshUntil)})
		if e != nil {
			return liveSQLError(e)
		}
		if !ok {
			refused = true
			return privacy.ErrUnavailable
		}
		return liveBound(call, q, proof.FreshUntil)
	})
	if err != nil && refused {
		// The ledger answered: this control (fence, revision, spend, state or
		// expiry) is no longer current. That is a refusal that ends the view,
		// not an outage the caller may retry.
		return fmt.Errorf("%w: live_watch:not-current", v.ErrDenied)
	}
	return liveError(err)
}

// PruneExpired is bounded, restrictive maintenance for the pinned root. It
// removes at most64 original-expired controls and64 fully refilled unreferenced
// accounts. It never closes a current watch or grants disclosure, and needs no
// new background loop. Schema-owner rollback can use it after all original ends.
func (s *LiveWatches) PruneExpired(ctx context.Context) (int64, int64, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return 0, 0, fmt.Errorf("%w: live_watch:237", v.ErrUnavailable)
	}
	var out struct {
		Controls int64 `json:"controls"`
		Accounts int64 `json:"accounts"`
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		raw, e := q.PruneLiveWatch(ctx, id(s.root))
		if e != nil {
			return e
		}
		if queryDecode(raw, 1024, &out) != nil || out.Controls < 0 || out.Controls > 64 || out.Accounts < 0 || out.Accounts > 64 {
			return privacy.ErrUnavailable
		}
		return ctx.Err()
	})
	if err != nil {
		return 0, 0, liveError(err)
	}
	return out.Controls, out.Accounts, nil
}
