package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"slices"
	"time"
)

type Retention struct {
	ledger *Ledger
	root   string
}

var _ app.RetentionLedger = (*Retention)(nil)
var _ app.LifecycleJournal = (*Retention)(nil)

func NewRetention(ctx context.Context, pool *pgxpool.Pool, root string) (*Retention, error) {
	if !authorization.UUID(root) {
		return nil, artifact.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &Retention{l, root}, nil
}
func retainedContext(root string, c custodydb.ContextCapture, a custodydb.CustodyAttempt) (value.RetainedArtifact, error) {
	var out value.RetainedArtifact
	accepted, err := admittedRecord(c)
	if err != nil {
		return out, err
	}
	e := accepted.Expectation
	r := e.Registration
	if c.RootID != id(root) || c.AttemptID != a.ID || a.ID != id(r.Location.AttemptID) || !bytes.Equal(a.RequestDigest, digest(normalized(r))) {
		return out, app.ErrConflict
	}
	// The only supported retained producer is the qualified context projection.
	// Its classification is fixed, not inferred from uploaded labels or content.
	out = value.RetainedArtifact{RootID: root, Registration: r, OriginPolicies: slices.Clone(e.RetentionRules), Input: value.Input{Target: authorization.Target{ClusterID: r.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: e.RequestedAgeSeconds, AnchorAt: r.AnchorAt}, Effective: value.Deadlines{AnchorAt: r.AnchorAt, ExpiresAt: a.EffectiveExpiresAt.Time, DeleteBy: a.EffectiveDeleteBy.Time}, Sequence: a.RetentionSequence}
	if !out.Valid() {
		return value.RetainedArtifact{}, app.ErrUnavailable
	}
	return out, nil
}
func (s *Retention) RetainedArtifact(ctx context.Context, loc artifact.Location) (value.RetainedArtifact, error) {
	var out value.RetainedArtifact
	if loc.Validate() != nil {
		return out, artifact.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		hint, err := q.ReadAttempt(ctx, id(loc.AttemptID))
		if err != nil {
			return err
		}
		if _, _, err = lockAllocation(ctx, q, uid(hint.AllocationID)); err != nil {
			return err
		}
		a, err := q.LockAttempt(ctx, id(loc.AttemptID))
		if err != nil {
			return err
		}
		if a.ClusterID != id(loc.ClusterID) || a.ArtifactID != id(loc.ArtifactID) {
			return app.ErrConflict
		}
		c, err := q.ReadRetainedContext(ctx, custodydb.ReadRetainedContextParams{RootID: id(s.root), AttemptID: a.ID})
		if err != nil {
			return err
		}
		out, err = retainedContextOrigins(ctx, q, s.root, c, a)
		return err
	})
	if err != nil {
		return value.RetainedArtifact{}, err
	}
	return out, nil
}
func decodeLifecycle(r custodydb.RetentionDecision) (value.LifecycleDecision, error) {
	var d value.LifecycleDecision
	if json.Unmarshal(r.DecisionJson, &d) != nil || !d.Valid() || id(d.ID) != r.ID || id(d.RootID) != r.RootID || id(d.Location.AttemptID) != r.AttemptID || d.Sequence != r.Sequence || !d.Previous.ExpiresAt.Equal(r.PreviousExpiresAt.Time) || !d.Previous.DeleteBy.Equal(r.PreviousDeleteBy.Time) || !d.Effective.ExpiresAt.Equal(r.ExpiresAt.Time) || !d.Effective.DeleteBy.Equal(r.DeleteBy.Time) || !bytes.Equal(digest(d), r.DecisionDigest) {
		return d, app.ErrUnavailable
	}
	return d, nil
}
func (s *Retention) TightenRetention(ctx context.Context, d value.LifecycleDecision) error {
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error { return s.tightenRetention(ctx, q, d) })
}
func (s *Retention) tightenRetention(ctx context.Context, q *custodydb.Queries, d value.LifecycleDecision) error {
	if !d.Valid() || d.RootID != s.root {
		return artifact.ErrInvalid
	}
	// SQL precision is part of the exact replay contract.
	for _, at := range []time.Time{d.ObservedAt, d.ValidUntil, d.Previous.AnchorAt, d.Previous.ExpiresAt, d.Previous.DeleteBy, d.Effective.AnchorAt, d.Effective.ExpiresAt, d.Effective.DeleteBy} {
		if at.Nanosecond()%1000 != 0 {
			return artifact.ErrInvalid
		}
	}
	// Serialize restrictive updates with catalog/transfer admission. No root
	// freshness is needed to revoke access or keep an existing deletion duty.
	if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
		return err
	}
	hint, err := q.ReadAttempt(ctx, id(d.Location.AttemptID))
	if err != nil {
		return err
	}
	if _, _, err = lockAllocation(ctx, q, uid(hint.AllocationID)); err != nil {
		return err
	}
	a, err := q.LockAttempt(ctx, id(d.Location.AttemptID))
	if err != nil {
		return err
	}
	existing, err := q.ReadRetentionDecision(ctx, custodydb.ReadRetentionDecisionParams{ID: id(d.ID), RootID: id(s.root)})
	if err == nil {
		if !bytes.Equal(existing.DecisionDigest, digest(d)) {
			return app.ErrConflict
		}
		_, err = decodeLifecycle(existing)
		return err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	c, err := q.ReadRetainedContext(ctx, custodydb.ReadRetainedContextParams{RootID: id(s.root), AttemptID: a.ID})
	if err != nil {
		return err
	}
	r, err := retainedContextOrigins(ctx, q, s.root, c, a)
	if err != nil {
		return err
	}
	if r.Registration.Location != d.Location || r.Input.Target != d.Target || r.Sequence+1 != d.Sequence || app.RegistrationDigest(r.Registration) != d.RegistrationDigest || !r.Effective.AnchorAt.Equal(d.Previous.AnchorAt) || !r.Effective.ExpiresAt.Equal(d.Previous.ExpiresAt) || !r.Effective.DeleteBy.Equal(d.Previous.DeleteBy) {
		return app.ErrConflict
	}
	merged, err := value.MergePolicyOrigins(r.OriginPolicies, d.Policies)
	if err != nil || !slices.Equal(merged, d.Origins) {
		return app.ErrConflict
	}
	check := func() error {
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !identity.Fresh(d.ObservedAt, d.ValidUntil, now.Time, 60*time.Second) {
			return app.ErrFence
		}
		return nil
	}
	if err = check(); err != nil {
		return err
	}
	encoded, err := json.Marshal(d)
	if err != nil || len(encoded) > 32<<10 {
		return artifact.ErrInvalid
	}
	if err = q.InsertRetentionDecision(ctx, custodydb.InsertRetentionDecisionParams{ID: id(d.ID), RootID: id(s.root), AttemptID: a.ID, Sequence: d.Sequence, PreviousExpiresAt: ts(d.Previous.ExpiresAt), PreviousDeleteBy: ts(d.Previous.DeleteBy), ExpiresAt: ts(d.Effective.ExpiresAt), DeleteBy: ts(d.Effective.DeleteBy), DecisionDigest: digest(d), DecisionJson: encoded}); err != nil {
		return err
	}
	n, err := q.TightenAttempt(ctx, custodydb.TightenAttemptParams{ID: a.ID, RetentionSequence: d.Sequence, EffectiveExpiresAt: ts(d.Effective.ExpiresAt), EffectiveDeleteBy: ts(d.Effective.DeleteBy)})
	if err != nil {
		return err
	}
	if n != 1 {
		return app.ErrConflict
	}
	return check()
}
func (s *Retention) PendingLifecycleDecisions(ctx context.Context) ([]value.LifecycleDecision, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := custodydb.New(s.ledger.pool).PendingRetentionDecisions(ctx, id(s.root))
	if err != nil {
		return nil, app.ErrUnavailable
	}
	out := make([]value.LifecycleDecision, 0, len(rows))
	for _, row := range rows {
		d, err := decodeLifecycle(row)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}
func (s *Retention) AcknowledgeLifecycleDecision(ctx context.Context, d value.LifecycleDecision, receipt audit.Receipt) error {
	if !d.Valid() || d.RootID != s.root || !receipt.ValidLifecycle(s.root, d.ID) {
		return artifact.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.LockRetentionDecision(ctx, custodydb.LockRetentionDecisionParams{ID: id(d.ID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		frozen, err := decodeLifecycle(row)
		if err != nil {
			return err
		}
		if !bytes.Equal(digest(frozen), digest(d)) {
			return app.ErrConflict
		}
		if row.AuditAcknowledgedAt.Valid {
			var old audit.Receipt
			if json.Unmarshal(row.AuditReceiptJson, &old) != nil || old != receipt {
				return app.ErrConflict
			}
			return nil
		}
		b, err := json.Marshal(receipt)
		if err != nil {
			return artifact.ErrInvalid
		}
		n, err := q.AcknowledgeRetentionDecision(ctx, custodydb.AcknowledgeRetentionDecisionParams{ID: id(d.ID), RootID: id(s.root), AuditReceiptJson: b})
		if err != nil {
			return err
		}
		if n != 1 {
			return app.ErrConflict
		}
		return nil
	})
}

func retainedContextOrigins(ctx context.Context, q *custodydb.Queries, root string, c custodydb.ContextCapture, a custodydb.CustodyAttempt) (value.RetainedArtifact, error) {
	r, err := retainedContext(root, c, a)
	if err != nil || r.Sequence == 0 {
		return r, err
	}
	row, err := q.ReadAttemptRetentionDecision(ctx, custodydb.ReadAttemptRetentionDecisionParams{AttemptID: a.ID, RootID: id(root), Sequence: r.Sequence})
	if err != nil {
		return value.RetainedArtifact{}, err
	}
	d, err := decodeLifecycle(row)
	if err != nil || d.Location != r.Registration.Location || d.RegistrationDigest != app.RegistrationDigest(r.Registration) {
		return value.RetainedArtifact{}, app.ErrUnavailable
	}
	merged, err := value.MergePolicyOrigins(r.OriginPolicies, d.Origins)
	if err != nil || !slices.Equal(merged, d.Origins) {
		return value.RetainedArtifact{}, app.ErrUnavailable
	}
	r.OriginPolicies = slices.Clone(d.Origins)
	return r, nil
}
