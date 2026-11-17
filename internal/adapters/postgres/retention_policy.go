package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RetentionPolicies stores the current EvidenceRetentionPolicy set and
// applies policy events to stored deadlines (ADR-330 D12).
type RetentionPolicies struct{ ledger *Ledger }

func NewRetentionPolicies(ctx context.Context, pool *pgxpool.Pool) (*RetentionPolicies, error) {
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &RetentionPolicies{l}, nil
}

// CurrentRetentionPolicies returns the stored policy set.
func (s *RetentionPolicies) CurrentRetentionPolicies(ctx context.Context) ([]value.ScopedPolicy, error) {
	var out []value.ScopedPolicy
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.ListRetentionPolicies(ctx)
		if err != nil {
			return err
		}
		out = make([]value.ScopedPolicy, 0, len(rows))
		for _, r := range rows {
			var p value.ScopedPolicy
			if json.Unmarshal(r.Policy, &p) != nil || p.Policy.Revision.UID != r.Uid || !p.Valid() {
				return value.ErrUnavailable
			}
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// SyncRetentionPolicies stores the complete current set. Each new or changed
// policy shortens the stored deadlines it matches and writes one audit row,
// in one transaction; a removed policy only writes its audit row.
func (s *RetentionPolicies) SyncRetentionPolicies(ctx context.Context, policies []value.ScopedPolicy) error {
	for _, p := range policies {
		if !p.Valid() {
			return value.ErrInvalid
		}
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if err := q.LockRetentionPolicies(ctx); err != nil {
			return err
		}
		rows, err := q.ListRetentionPolicies(ctx)
		if err != nil {
			return err
		}
		stored := map[string]custodydb.ListRetentionPoliciesRow{}
		for _, r := range rows {
			stored[r.Uid] = r
		}
		for _, p := range policies {
			rev := p.Policy.Revision
			if old, ok := stored[rev.UID]; ok && old.Generation == rev.Generation && bytes.Equal(old.Digest, rev.Digest[:]) {
				delete(stored, rev.UID)
				continue
			}
			delete(stored, rev.UID)
			policy, _ := json.Marshal(p)
			effect, _ := json.Marshal(value.Effect(p))
			if err = q.UpsertRetentionPolicy(ctx, custodydb.UpsertRetentionPolicyParams{Uid: rev.UID, Name: p.Name, Generation: rev.Generation, Digest: rev.Digest[:], Policy: policy, Effect: effect}); err != nil {
				return err
			}
			n, err := q.ApplyRetentionEffect(ctx, effect)
			if err != nil {
				return err
			}
			if err = q.InsertRetentionPolicyEvent(ctx, custodydb.InsertRetentionPolicyEventParams{Uid: rev.UID, Name: p.Name, Generation: rev.Generation, Digest: rev.Digest[:], Change: "applied", Shortened: n}); err != nil {
				return err
			}
		}
		for uid, old := range stored {
			if err = q.DeleteRetentionPolicy(ctx, uid); err != nil {
				return err
			}
			if err = q.InsertRetentionPolicyEvent(ctx, custodydb.InsertRetentionPolicyEventParams{Uid: uid, Name: old.Name, Generation: old.Generation, Digest: old.Digest, Change: "removed"}); err != nil {
				return err
			}
		}
		return nil
	})
}

// PreviewRetentionEffects aggregates proposed effects over stored deadlines.
func (s *RetentionPolicies) PreviewRetentionEffects(ctx context.Context, effects []value.PolicyEffect) ([]value.PreviewRow, error) {
	in, err := json.Marshal(effects)
	if err != nil {
		return nil, value.ErrInvalid
	}
	var out []value.PreviewRow
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		b, err := q.PreviewRetentionEffects(ctx, in)
		if err != nil {
			return err
		}
		var groups []struct {
			ClusterID    string     `json:"cluster_id"`
			NativeType   string     `json:"native_type"`
			CaseMetadata bool       `json:"case_metadata"`
			Scanned      int        `json:"scanned"`
			Affected     int        `json:"affected"`
			ReadClosed   int        `json:"read_closed"`
			DeletionDue  int        `json:"deletion_due"`
			Expires      *time.Time `json:"earliest_expires_at"`
			Delete       *time.Time `json:"earliest_delete_by"`
		}
		if json.Unmarshal(b, &groups) != nil {
			return value.ErrUnavailable
		}
		out = make([]value.PreviewRow, 0, len(groups))
		for _, g := range groups {
			r := value.PreviewRow{ClusterID: g.ClusterID, NativeType: g.NativeType, CaseMetadata: g.CaseMetadata, Scanned: g.Scanned, Affected: g.Affected, ReadClosed: g.ReadClosed, DeletionDue: g.DeletionDue}
			if g.Expires != nil {
				r.EarliestExpiresAt = g.Expires.UTC()
			}
			if g.Delete != nil {
				r.EarliestDeleteBy = g.Delete.UTC()
			}
			out = append(out, r)
		}
		return nil
	})
	return out, err
}
