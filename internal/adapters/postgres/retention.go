package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Retention struct {
	ledger *Ledger
	root   string
}

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
	out = value.RetainedArtifact{RootID: root, Registration: r, OriginPolicies: slices.Clone(e.RetentionRules), Input: value.Input{Target: authorization.Target{ClusterID: r.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}, PrivacyClass: "potentialPersonalData", EvidenceType: e.Type().EvidenceType, RequestedSeconds: e.RequestedAgeSeconds, AnchorAt: r.AnchorAt}, Effective: value.Deadlines{AnchorAt: r.AnchorAt, ExpiresAt: a.EffectiveExpiresAt.Time, DeleteBy: a.EffectiveDeleteBy.Time}, Sequence: a.RetentionSequence}
	if !out.Valid() {
		return value.RetainedArtifact{}, app.ErrUnavailable
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

func (s *Retention) PendingLifecycleDecision(ctx context.Context) (value.LifecycleDecision, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	row, err := custodydb.New(s.ledger.pool).PendingRetentionDecision(ctx, id(s.root))
	if errors.Is(err, pgx.ErrNoRows) {
		return value.LifecycleDecision{}, false, nil
	}
	if err != nil {
		return value.LifecycleDecision{}, false, app.ErrUnavailable
	}
	d, err := decodeLifecycle(row)
	return d, true, err
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
	return retainedDecisionOrigins(r, row)
}

// retainedDecisionOrigins carries the policy origins of the artifact's current
// lifecycle decision (row, read at r.Sequence) into r.
func retainedDecisionOrigins(r value.RetainedArtifact, row custodydb.RetentionDecision) (value.RetainedArtifact, error) {
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
