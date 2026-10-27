package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	capture "asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
)

// retainedCustodyOrigins selects the actual typed producer of the obligation.
// History parameters never borrow native evidence facts or its lifetime.
func retainedCustodyOrigins(ctx context.Context, q *custodydb.Queries, root string, a custodydb.CustodyAttempt) (value.RetainedArtifact, error) {
	h, err := q.ReadHistoryParameterByAttempt(ctx, custodydb.ReadHistoryParameterByAttemptParams{RootID: id(root), AttemptID: a.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		c, e := q.ReadRetainedContext(ctx, custodydb.ReadRetainedContextParams{RootID: id(root), AttemptID: a.ID})
		if e != nil {
			return value.RetainedArtifact{}, e
		}
		return retainedContextOrigins(ctx, q, root, c, a)
	}
	if err != nil {
		return value.RetainedArtifact{}, err
	}
	e, err := decodeHistoryExpectation(h)
	if err != nil {
		return value.RetainedArtifact{}, err
	}
	var retention capture.HistoryRetention
	if json.Unmarshal(h.RetentionJson, &retention) != nil || !retention.Valid() {
		return value.RetainedArtifact{}, app.ErrUnavailable
	}
	r := value.RetainedArtifact{RootID: root, Registration: e.Registration, OriginPolicies: retention.Origins, Input: retention.Input, Effective: value.Deadlines{AnchorAt: e.Registration.AnchorAt, ExpiresAt: a.EffectiveExpiresAt.Time, DeleteBy: a.EffectiveDeleteBy.Time}, Sequence: a.RetentionSequence}
	if !r.Valid() {
		return value.RetainedArtifact{}, app.ErrUnavailable
	}
	if r.Sequence == 0 {
		return r, nil
	}
	row, err := q.ReadAttemptRetentionDecision(ctx, custodydb.ReadAttemptRetentionDecisionParams{AttemptID: a.ID, RootID: id(root), Sequence: r.Sequence})
	if err != nil {
		return value.RetainedArtifact{}, err
	}
	return retainedDecisionOrigins(r, row)
}
