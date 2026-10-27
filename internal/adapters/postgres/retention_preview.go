package postgres

import (
	"context"
	"errors"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// retentionPreviewPage bounds one keyset statement of the catalog scan.
const retentionPreviewPage = 1000

// RetentionPreviewCatalog reads the ADR-240 impact preview's inputs with the
// hub metadata reader: every retention source with its ordinary readiness and
// latest accepted snapshot (one short transaction under the usual root and
// source share locks), then at most limit retained context registrations
// whose effective deletion deadline has not passed (a second transaction of
// keyset pages over the catch-up's index, taking no locks, so a long scan
// never holds back lifecycle or permission writers). It writes nothing; the
// result is advisory and grants nothing.
func (s *RetentionSources) RetentionPreviewCatalog(ctx context.Context, limit int) (privacy.PreviewCatalog, error) {
	var out privacy.PreviewCatalog
	if limit < 1 || limit > privacy.MaxRetentionPreviewArtifacts {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out.Sources = nil
		rows, err := q.ListRetentionPreviewSources(ctx, custodydb.ListRetentionPreviewSourcesParams{RootID: id(s.root), RowLimit: privacy.MaxRetentionPreviewSources + 1})
		if err != nil {
			return err
		}
		if len(rows) > privacy.MaxRetentionPreviewSources {
			return value.ErrLimit
		}
		for _, row := range rows {
			f := retentionFence(row)
			source := privacy.PreviewSource{Ref: f.Source}
			_, err := acceptedRetentionSource(ctx, q, s.root, f.Source)
			switch {
			case err == nil:
				source.Ready = true
			case !errors.Is(err, value.ErrUnavailable) && !errors.Is(err, pgx.ErrNoRows):
				return err
			}
			// The latest accepted snapshot is the base the proposal edits,
			// whether or not the source is currently ready.
			checkpoint, err := currentRetentionCheckpoint(ctx, q, row)
			switch {
			case err == nil && checkpoint != nil:
				snapshot := checkpoint.Transition.List.Snapshot
				source.Current = &snapshot
			case err != nil && !errors.Is(err, value.ErrUnavailable) && !errors.Is(err, pgx.ErrNoRows):
				return err
			case err != nil:
				source.Ready = false
			}
			out.Sources = append(out.Sources, source)
		}
		return nil
	})
	if err != nil {
		return privacy.PreviewCatalog{}, permissionError(err)
	}
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out.Artifacts, out.Unreadable, out.Truncated = nil, map[string]int{}, false
		var after pgtype.UUID
		for scanned := 0; ; {
			page := min(retentionPreviewPage, limit-scanned) + 1
			rows, err := q.ListRetentionPreviewContexts(ctx, custodydb.ListRetentionPreviewContextsParams{RootID: id(s.root), AfterAttempt: after, PageLimit: int32(page)})
			if err != nil {
				return err
			}
			more := len(rows) == page
			if more {
				rows = rows[:page-1]
			}
			if err = s.previewPage(ctx, q, rows, &out); err != nil {
				return err
			}
			scanned += len(rows)
			if !more {
				return nil
			}
			if scanned >= limit {
				out.Truncated = true
				return nil
			}
			after = rows[len(rows)-1].AttemptID
		}
	})
	if err != nil {
		return privacy.PreviewCatalog{}, permissionError(err)
	}
	return out, nil
}

// previewPage decodes one page with the catch-up's own retained-artifact
// readers. A row that does not decode is counted as unreadable for its
// cluster, never skipped or assumed.
func (s *RetentionSources) previewPage(ctx context.Context, q *custodydb.Queries, rows []custodydb.ListRetentionPreviewContextsRow, out *privacy.PreviewCatalog) error {
	type key struct {
		attempt  pgtype.UUID
		sequence int64
	}
	retained := make([]privacy.RetainedArtifact, len(rows))
	ok := make([]bool, len(rows))
	var ids []pgtype.UUID
	var sequences []int64
	for i, row := range rows {
		// Exactly the fields retainedContext and admittedRecord read.
		c := custodydb.ContextCapture{ID: row.ID, RootID: row.RootID, SubmissionDigest: row.SubmissionDigest, ScopeDigest: row.ScopeDigest, ExpectationJson: row.ExpectationJson, PodPinJson: row.PodPinJson, AttemptID: row.AttemptID, CreatedAt: row.CreatedAt, Deadline: row.Deadline, State: row.State}
		a := custodydb.CustodyAttempt{ID: row.AttemptID, ClusterID: row.ClusterID, RequestDigest: row.RequestDigest, EffectiveExpiresAt: row.EffectiveExpiresAt, EffectiveDeleteBy: row.EffectiveDeleteBy, RetentionSequence: row.RetentionSequence}
		r, err := retainedContext(s.root, c, a)
		if err != nil {
			continue
		}
		retained[i], ok[i] = r, true
		if r.Sequence > 0 {
			ids = append(ids, row.AttemptID)
			sequences = append(sequences, r.Sequence)
		}
	}
	decisions := map[key]custodydb.RetentionDecision{}
	if len(ids) > 0 {
		found, err := q.ReadRetentionPreviewDecisions(ctx, custodydb.ReadRetentionPreviewDecisionsParams{RootID: id(s.root), AttemptIds: ids, Sequences: sequences})
		if err != nil {
			return err
		}
		for _, d := range found {
			decisions[key{d.AttemptID, d.Sequence}] = d
		}
	}
	for i, row := range rows {
		r := retained[i]
		if ok[i] && r.Sequence > 0 {
			d, found := decisions[key{row.AttemptID, r.Sequence}]
			var err error
			if r, err = retainedDecisionOrigins(r, d); !found || err != nil {
				ok[i] = false
			}
		}
		if !ok[i] {
			out.Unreadable[uid(row.ClusterID)]++
			continue
		}
		out.Artifacts = append(out.Artifacts, r)
	}
	return nil
}

var _ app.RetentionPreviewCatalog = (*RetentionSources)(nil)
