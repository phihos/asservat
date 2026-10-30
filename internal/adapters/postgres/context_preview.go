package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContextPreviews stores private passive review state. Possessing a row grants
// no collection authority: current identity, targets, permissions, retention,
// storage and recovery must be resolved again by the submission coordinator.
type ContextPreviews struct {
	ledger *Ledger
	root   string
}

var _ app.ContextPreviewStore = (*ContextPreviews)(nil)

func NewContextPreviews(ctx context.Context, pool *pgxpool.Pool, root string) (*ContextPreviews, error) {
	if !authorization.UUID(root) {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &ContextPreviews{ledger: l, root: root}, nil
}

func previewActorKey(p identity.Principal) []byte {
	return digest(struct {
		Format string
		Actor  identity.Principal
	}{"context-preview-actor/v1", p})
}

func previewRecord(row custodydb.ContextPreview) (value.ContextPreview, error) {
	var out value.ContextPreview
	if len(row.BlueprintJson) == 0 || len(row.BlueprintJson) > value.MaxContextPreviewBytes || len(row.BlueprintSha256) != sha256.Size {
		return out, value.ErrUnavailable
	}
	h := sha256.Sum256(row.BlueprintJson)
	if !bytes.Equal(h[:], row.BlueprintSha256) {
		return out, value.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(row.BlueprintJson))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || !app.ValidContextPreview(out) || (out.Group == nil && row.PreviewKind != "context") || (out.Group != nil && row.PreviewKind != "recordingSaveGroup") {
		return value.ContextPreview{}, value.ErrUnavailable
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, row.BlueprintJson) || out.ID != uid(row.ID) || out.RootID != uid(row.RootID) || out.CaptureID != uid(row.CaptureID) || out.AttemptID != uid(row.AttemptID) || !out.CreatedAt.Equal(row.CreatedAt.Time) || !out.Deadline.Equal(row.Deadline.Time) || !bytes.Equal(previewActorKey(out.Actor), row.ActorKey) || !bytes.Equal(principalKey(out.Actor), row.PrincipalKey) {
		return value.ContextPreview{}, value.ErrUnavailable
	}
	return out, nil
}

func currentPreview(ctx context.Context, q *custodydb.Queries, p value.ContextPreview) error {
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return err
	}
	if !p.Current(now.Time) {
		return value.ErrChanged
	}
	return ctx.Err()
}

func (s *ContextPreviews) CreateContextPreview(ctx context.Context, p value.ContextPreview) error {
	p = p.Clone()
	if s == nil || s.ledger == nil || p.RootID != s.root || !app.ValidContextPreview(p) {
		return value.ErrInvalid
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return value.ErrInvalid
	}
	h := sha256.Sum256(encoded)
	return captureError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		// One installation root serializes both counts and cleanup. The human
		// count excludes client ID, so another browser/MCP client cannot evade it.
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		if err := currentPreview(ctx, q, p); err != nil {
			return err
		}
		if err := checkContextPreviewFence(ctx, q, p.RootID, p.ID, p.Actor); err != nil {
			return err
		}
		old, err := q.FindContextPreview(ctx, custodydb.FindContextPreviewParams{RootID: id(s.root), ID: id(p.ID), ActorKey: previewActorKey(p.Actor)})
		if err == nil {
			if old.ClosedAt.Valid {
				return value.ErrChanged
			}
			if _, err := previewRecord(old); err != nil {
				return err
			}
			if !bytes.Equal(old.BlueprintJson, encoded) {
				return value.ErrConflict
			}
			return currentPreview(ctx, q, p) // exact retry; never renew the deadline
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err = q.DeleteExpiredContextPreviews(ctx, id(s.root)); err != nil {
			return err
		}
		if _, err := q.DeleteExpiredContextPreviewFences(ctx, id(s.root)); err != nil {
			return err
		}
		if _, err := q.DeleteExpiredRecordingSelections(ctx, id(s.root)); err != nil {
			return err
		}
		count, err := q.CountContextPreviews(ctx, id(s.root))
		if err != nil {
			return err
		}
		if count >= value.MaxPreviewsPerRoot {
			return value.ErrCapacity
		}
		count, err = q.CountPrincipalContextPreviews(ctx, custodydb.CountPrincipalContextPreviewsParams{RootID: id(s.root), PrincipalKey: principalKey(p.Actor)})
		if err != nil {
			return err
		}
		if count >= value.MaxPreviewsPerPrincipal {
			return value.ErrCapacity
		}
		if p.Group != nil {
			err = q.InsertRecordingGroupPreview(ctx, custodydb.InsertRecordingGroupPreviewParams{ID: id(p.ID), RootID: id(s.root), CaptureID: id(p.CaptureID), ActorKey: previewActorKey(p.Actor), PrincipalKey: principalKey(p.Actor), BlueprintJson: encoded, BlueprintSha256: h[:], CreatedAt: ts(p.CreatedAt), Deadline: ts(p.Deadline)})
		} else {
			err = q.InsertContextPreview(ctx, custodydb.InsertContextPreviewParams{ID: id(p.ID), RootID: id(s.root), CaptureID: id(p.CaptureID), AttemptID: id(p.AttemptID), ActorKey: previewActorKey(p.Actor), PrincipalKey: principalKey(p.Actor), BlueprintJson: encoded, BlueprintSha256: h[:], CreatedAt: ts(p.CreatedAt), Deadline: ts(p.Deadline)})
		}
		if err != nil {
			return err
		}
		return currentPreview(ctx, q, p)
	}))
}

func (s *ContextPreviews) ReadContextPreview(ctx context.Context, root, preview string, actor identity.Principal) (value.ContextPreview, error) {
	var out value.ContextPreview
	if s == nil || s.ledger == nil || root != s.root || !authorization.UUID(preview) || !actor.Valid() {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.FindContextPreview(ctx, custodydb.FindContextPreviewParams{RootID: id(root), ID: id(preview), ActorKey: previewActorKey(actor)})
		if errors.Is(err, pgx.ErrNoRows) {
			return value.ErrChanged // same result for absent, expired or another actor
		}
		if err != nil {
			return err
		}
		if row.ClosedAt.Valid {
			return value.ErrChanged
		}
		if err := checkContextPreviewFence(ctx, q, root, preview, actor); err != nil {
			return err
		}
		out, err = previewRecord(row)
		if err != nil {
			return err
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		until, e := q.ContextPreviewReadUntil(ctx, custodydb.ContextPreviewReadUntilParams{RootID: id(root), PreviewID: id(preview)})
		if e != nil {
			return e
		}
		if !until.Valid || !now.Time.Before(until.Time) || now.Time.Before(out.CreatedAt) {
			return value.ErrPreviewExpired
		}
		return ctx.Err()
	})
	if err != nil {
		return value.ContextPreview{}, captureError(err)
	}
	return out, nil
}

// ContextPreviewCleanup has only expiry deletion in its SQL role. It can run
// independently of identity/source outages and never deletes accepted captures.
// The caller schedules bounded pages; this is not a background goroutine.
type ContextPreviewCleanup struct{ previews *ContextPreviews }

func NewContextPreviewCleanup(ctx context.Context, pool *pgxpool.Pool, root string) (*ContextPreviewCleanup, error) {
	s, err := NewContextPreviews(ctx, pool, root)
	if err != nil {
		return nil, err
	}
	return &ContextPreviewCleanup{previews: s}, nil
}

func (s *ContextPreviewCleanup) DeleteExpiredContextPreviews(ctx context.Context) (int64, error) {
	var count int64
	if s == nil || s.previews == nil {
		return 0, value.ErrUnavailable
	}
	err := s.previews.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockPermissionStream(ctx, id(s.previews.root)); err != nil {
			return err
		}
		var err error
		count, err = q.DeleteExpiredContextPreviews(ctx, id(s.previews.root))
		if err != nil {
			return err
		}
		n, err := q.DeleteExpiredContextPreviewFences(ctx, id(s.previews.root))
		count += n
		return err
	})
	if err != nil {
		return 0, captureError(err)
	}
	return count, nil
}

func checkContextPreviewFence(ctx context.Context, q *custodydb.Queries, root, preview string, actor identity.Principal) error {
	_, err := q.FindContextPreviewFence(ctx, custodydb.FindContextPreviewFenceParams{RootID: id(root), PreviewID: id(preview), ActorKey: previewActorKey(actor)})
	if err == nil {
		return value.ErrChanged
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

// Group previews use the same bounded journal and fences, with no parent
// artifact/attempt. Separate entry points keep accidental single-route use closed.
func (s *ContextPreviews) CreateRecordingGroupPreview(ctx context.Context, p value.ContextPreview) error {
	if p.Group == nil {
		return value.ErrInvalid
	}
	return s.CreateContextPreview(ctx, p)
}

func (s *ContextPreviews) ReadRecordingGroupPreview(ctx context.Context, root, preview string, actor identity.Principal) (value.ContextPreview, error) {
	p, err := s.ReadContextPreview(ctx, root, preview, actor)
	if err != nil {
		return value.ContextPreview{}, err
	}
	if p.Group == nil {
		return value.ContextPreview{}, value.ErrInvalid
	}
	return p, nil
}
