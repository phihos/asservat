package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RetentionSources stores guarded checkpoints and finite source observations.
// Its separate read facet derives readiness from observations, catch-up and
// audit receipts; source writers have no readiness override.
type RetentionSources struct {
	ledger *Ledger
	root   string
}

var _ app.RetentionCheckpointStore = (*RetentionSources)(nil)
var _ app.RetentionAcceptanceJournal = (*RetentionSources)(nil)

func NewRetentionSources(ctx context.Context, pool *pgxpool.Pool, root string) (*RetentionSources, error) {
	if !authorization.UUID(root) {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &RetentionSources{l, root}, nil
}
func retentionFence(s custodydb.RetentionSource) app.RetentionFence {
	f := app.RetentionFence{RootID: uid(s.RootID), Epoch: uid(s.Epoch), Source: privacy.PolicySourceRef{ClusterID: uid(s.ClusterID), ControlNamespaceUID: s.NamespaceUid, Hub: s.Hub}, Sequence: s.Sequence, LeaseUntil: s.LeaseUntil.Time}
	copy(f.Source.ProtectionDigest[:], s.ProtectionDigest)
	return f
}
func decodeRetentionCheckpoint(c custodydb.RetentionCheckpoint) (app.RetentionCheckpoint, error) {
	var out app.RetentionCheckpoint
	if json.Unmarshal(c.TransitionJson, &out.Transition) != nil || json.Unmarshal(c.RecordJson, &out.Record) != nil {
		return out, value.ErrUnavailable
	}
	t, r := out.Transition, out.Record
	h := app.RetentionTransitionDigest(t)
	if !r.Valid() || h == (artifact.Digest{}) || !bytes.Equal(h[:], c.TransitionDigest) || !bytes.Equal(digest(r), c.RecordDigest) || r.CheckpointDigest != h || r.ID != t.ID || id(r.ID) != c.ID || id(r.RootID) != c.RootID || id(r.SourceClusterID) != c.ClusterID || r.ControlNamespaceUID != c.NamespaceUid || id(r.Epoch) != c.Epoch || r.Sequence != c.Sequence || !r.CreatedAt.Equal(c.CreatedAt.Time) || r.RootID != t.Fence.RootID || r.Epoch != t.Fence.Epoch || r.Sequence != t.Fence.Sequence+1 || r.SourceClusterID != t.Fence.Source.ClusterID || r.ControlNamespaceUID != t.Fence.Source.ControlNamespaceUID || r.ProtectionDigest != t.Fence.Source.ProtectionDigest || r.Hub != t.Fence.Source.Hub {
		return app.RetentionCheckpoint{}, value.ErrUnavailable
	}
	out.Audited = c.AuditAcknowledgedAt.Valid
	if out.Audited {
		var receipt audit.Receipt
		if json.Unmarshal(c.AuditReceipt, &receipt) != nil || !receipt.HistoricalRetentionAcceptance(r.RootID, r.ID) {
			return app.RetentionCheckpoint{}, value.ErrUnavailable
		}
	}
	return out, nil
}
func currentRetentionCheckpoint(ctx context.Context, q *custodydb.Queries, s custodydb.RetentionSource) (*app.RetentionCheckpoint, error) {
	if s.Sequence == 0 {
		return nil, nil
	}
	c, err := q.ReadCurrentRetentionCheckpoint(ctx, custodydb.ReadCurrentRetentionCheckpointParams{RootID: s.RootID, ClusterID: s.ClusterID, NamespaceUid: s.NamespaceUid, Sequence: s.Sequence})
	if err != nil {
		return nil, err
	}
	checkpoint, err := decodeRetentionCheckpoint(c)
	return &checkpoint, err
}
func lockRetentionSource(ctx context.Context, q *custodydb.Queries, root string, source privacy.PolicySourceRef) (custodydb.RetentionSource, error) {
	return q.LockRetentionSource(ctx, custodydb.LockRetentionSourceParams{RootID: id(root), ClusterID: id(source.ClusterID), NamespaceUid: source.ControlNamespaceUID})
}
func liveRetentionSource(ctx context.Context, q *custodydb.Queries, s custodydb.RetentionSource, f app.RetentionFence) (time.Time, error) {
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	got := retentionFence(s)
	if s.RecoveryBlocked || s.Suspended || got.RootID != f.RootID || got.Epoch != f.Epoch || got.Source != f.Source || got.Sequence != f.Sequence || !n.Time.Before(s.LeaseUntil.Time) || !n.Time.Before(f.LeaseUntil) {
		return time.Time{}, value.ErrChanged
	}
	return n.Time, nil
}
func (s *RetentionSources) BeginRetention(ctx context.Context, root string, source privacy.PolicySourceRef, epoch string) (app.RetentionStart, error) {
	var out app.RetentionStart
	if root != s.root || !app.ValidRetentionSource(source) || !authorization.UUID(epoch) {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockPermissionStream(ctx, id(root)); err != nil {
			return err
		}
		if err := q.InsertRetentionSource(ctx, custodydb.InsertRetentionSourceParams{RootID: id(root), ClusterID: id(source.ClusterID), NamespaceUid: source.ControlNamespaceUID, Hub: source.Hub, ProtectionDigest: source.ProtectionDigest[:], Epoch: id(epoch)}); err != nil {
			return err
		}
		row, err := lockRetentionSource(ctx, q, root, source)
		if err != nil {
			return err
		}
		f := retentionFence(row)
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if row.RecoveryBlocked || f.Source != source || (!row.Suspended && n.Time.Before(row.LeaseUntil.Time) && f.Epoch != epoch) {
			return value.ErrChanged
		}
		// A lost reply may retry the same still-live epoch without extending it.
		if row.Suspended || !n.Time.Before(row.LeaseUntil.Time) {
			// Never resurrect an expired process epoch, even when its caller retries.
			if err = q.InsertRetentionEpoch(ctx, custodydb.InsertRetentionEpochParams{RootID: row.RootID, ClusterID: row.ClusterID, NamespaceUid: row.NamespaceUid, Epoch: id(epoch)}); err != nil {
				return err
			}
			row, err = q.StartRetentionSource(ctx, custodydb.StartRetentionSourceParams{RootID: id(root), ClusterID: id(source.ClusterID), NamespaceUid: source.ControlNamespaceUID, Epoch: id(epoch)})
			if err != nil {
				return err
			}
		}
		out.Fence = retentionFence(row)
		out.ResumeCursor = row.WatchCursor
		out.Checkpoint, err = currentRetentionCheckpoint(ctx, q, row)
		return err
	})
	if err != nil {
		return app.RetentionStart{}, permissionError(err)
	}
	return out, nil
}
func (s *RetentionSources) AcceptRetention(ctx context.Context, t app.RetentionTransition) (app.RetentionCheckpoint, error) {
	var out app.RetentionCheckpoint
	if t.Fence.RootID != s.root || !t.Fence.Valid() || !authorization.UUID(t.ID) {
		return out, value.ErrInvalid
	}
	encoded, err := json.Marshal(t)
	if err != nil || len(encoded) > 8<<20 {
		return out, value.ErrLimit
	}
	h := app.RetentionTransitionDigest(t)
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		row, err := lockRetentionSource(ctx, q, s.root, t.Fence.Source)
		if err != nil {
			return err
		}
		prior, err := q.ReadRetentionCheckpoint(ctx, custodydb.ReadRetentionCheckpointParams{ID: id(t.ID), RootID: id(s.root)})
		if err == nil {
			if !bytes.Equal(h[:], prior.TransitionDigest) {
				return value.ErrChanged
			}
			out, err = decodeRetentionCheckpoint(prior)
			return err // immutable historical replay; it does not renew readiness
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		now, err := liveRetentionSource(ctx, q, row, t.Fence)
		if err != nil {
			return err
		}
		previous, err := currentRetentionCheckpoint(ctx, q, row)
		if err != nil {
			return err
		}
		r, err := app.ValidateRetentionTransition(t, previous, now)
		if err != nil {
			return err
		}
		record, err := json.Marshal(r)
		if err != nil || len(record) > 256<<10 {
			return value.ErrLimit
		}
		if err = q.InsertRetentionCheckpoint(ctx, custodydb.InsertRetentionCheckpointParams{ID: id(t.ID), RootID: id(s.root), ClusterID: row.ClusterID, NamespaceUid: row.NamespaceUid, Epoch: row.Epoch, Sequence: r.Sequence, TransitionDigest: h[:], TransitionJson: encoded, RecordDigest: digest(r), RecordJson: record, CreatedAt: ts(now)}); err != nil {
			return err
		}
		if err = q.AdvanceRetentionSource(ctx, custodydb.AdvanceRetentionSourceParams{RootID: row.RootID, ClusterID: row.ClusterID, NamespaceUid: row.NamespaceUid, Sequence: r.Sequence, WatchCursor: t.List.ResourceVersion}); err != nil {
			return err
		}
		// All blocking locks and writes consume the original grant/lease window.
		after, err := liveRetentionSource(ctx, q, row, t.Fence)
		if err != nil {
			return err
		}
		if t.Fence.Sequence == 0 {
			if err = app.CheckInitialRetention(t.List.Snapshot, t.Fence.Source.ProtectionDigest, t.Review, after); err != nil {
				return err
			}
		}
		out = app.RetentionCheckpoint{Transition: t, Record: r}
		return nil
	})
	if err != nil {
		return app.RetentionCheckpoint{}, permissionError(err)
	}
	return out, nil
}
func (s *RetentionSources) RenewRetention(ctx context.Context, f app.RetentionFence) (app.RetentionFence, error) {
	if !f.Valid() || f.RootID != s.root {
		return app.RetentionFence{}, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := lockRetentionSource(ctx, q, s.root, f.Source)
		if err != nil {
			return err
		}
		if _, err = liveRetentionSource(ctx, q, row, f); err != nil {
			return err
		}
		until, err := q.RenewRetentionSource(ctx, custodydb.RenewRetentionSourceParams{RootID: row.RootID, ClusterID: row.ClusterID, NamespaceUid: row.NamespaceUid, Epoch: row.Epoch})
		f.LeaseUntil = until.Time
		return err
	})
	if err != nil {
		return app.RetentionFence{}, permissionError(err)
	}
	return f, nil
}

func (s *RetentionSources) AdvanceRetentionCursor(ctx context.Context, f app.RetentionFence, cursor string) error {
	if !f.Valid() || f.RootID != s.root || f.Sequence < 1 || !identity.Text(cursor, 128) || cursor == "0" {
		return value.ErrInvalid
	}
	return permissionError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := lockRetentionSource(ctx, q, s.root, f.Source)
		if err != nil {
			return err
		}
		if _, err = liveRetentionSource(ctx, q, row, f); err != nil {
			return err
		}
		if err = q.AdvanceRetentionCursor(ctx, custodydb.AdvanceRetentionCursorParams{RootID: row.RootID, ClusterID: row.ClusterID, NamespaceUid: row.NamespaceUid, WatchCursor: cursor}); err != nil {
			return err
		}
		_, err = liveRetentionSource(ctx, q, row, f)
		return err
	}))
}
func (s *RetentionSources) SuspendRetention(ctx context.Context, f app.RetentionFence) error {
	if !f.Valid() || f.RootID != s.root {
		return value.ErrInvalid
	}
	return permissionError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		return q.SuspendRetentionSource(ctx, custodydb.SuspendRetentionSourceParams{RootID: id(s.root), ClusterID: id(f.Source.ClusterID), NamespaceUid: f.Source.ControlNamespaceUID, Epoch: id(f.Epoch)})
	}))
}
func (s *RetentionSources) PendingRetentionAcceptances(ctx context.Context, limit int) ([]audit.RetentionAcceptance, error) {
	if limit < 1 || limit > 64 {
		return nil, value.ErrInvalid
	}
	var out []audit.RetentionAcceptance
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.PendingRetentionCheckpoints(ctx, custodydb.PendingRetentionCheckpointsParams{RootID: id(s.root), Limit: int32(limit)})
		if err != nil {
			return err
		}
		for _, row := range rows {
			c, err := decodeRetentionCheckpoint(row)
			if err != nil {
				return err
			}
			out = append(out, c.Record)
		}
		return nil
	})
	if err != nil {
		return nil, permissionError(err)
	}
	return out, nil
}
func (s *RetentionSources) AcknowledgeRetentionAcceptance(ctx context.Context, event string, r audit.Receipt) error {
	if !r.ValidRetentionAcceptance(s.root, event) {
		return value.ErrInvalid
	}
	return permissionError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.LockRetentionCheckpoint(ctx, custodydb.LockRetentionCheckpointParams{ID: id(event), RootID: id(s.root)})
		if err != nil {
			return err
		}
		if _, err = decodeRetentionCheckpoint(row); err != nil {
			return err
		}
		if row.AuditAcknowledgedAt.Valid {
			var old audit.Receipt
			if json.Unmarshal(row.AuditReceipt, &old) != nil || old != r {
				return value.ErrChanged
			}
			return nil
		}
		encoded, _ := json.Marshal(r)
		return q.AcknowledgeRetentionCheckpoint(ctx, custodydb.AcknowledgeRetentionCheckpointParams{ID: id(event), RootID: id(s.root), AuditReceipt: encoded})
	}))
}
