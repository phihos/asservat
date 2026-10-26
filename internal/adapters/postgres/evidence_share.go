package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EvidenceShares is the ADR-232 share ledger (migration 00086). It stores
// shares and revocations only; it never decides readership. Every read
// returns rows bounded to five seconds of observation.
type EvidenceShares struct {
	ledger   *Ledger
	root     string
	recovery *RecoveryTransactionGuard
}

var _ sharing.Store = (*EvidenceShares)(nil)

func NewEvidenceShares(ctx context.Context, pool *pgxpool.Pool, root string, recovery *RecoveryTransactionGuard) (*EvidenceShares, error) {
	if !authorization.UUID(root) || recovery == nil || recovery.root != root {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if why := schemaCompatible(ctx, pool); why != "" {
		return nil, schemaRefusal(value.ErrUnavailable, why)
	}
	return &EvidenceShares{ledger: l, root: root, recovery: recovery}, nil
}

type shareRecipientWire struct {
	Kind   string `json:"kind"`
	Issuer string `json:"issuer"`
	ID     string `json:"id"`
}

func (s *EvidenceShares) observed(ctx context.Context, q *custodydb.Queries, rows []custodydb.EvidenceShare) ([]authorization.Share, error) {
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return nil, err
	}
	until := now.Time.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	out := make([]authorization.Share, 0, len(rows))
	for _, r := range rows {
		v, err := shareFromRow(r)
		if err != nil || v.RootID != s.root {
			return nil, value.ErrUnavailable
		}
		v.ObservedAt, v.ValidUntil = now.Time, until
		out = append(out, v)
	}
	return out, nil
}

func shareFromRow(r custodydb.EvidenceShare) (authorization.Share, error) {
	var management []artifact.AudienceAssignment
	var recipients []shareRecipientWire
	if json.Unmarshal(r.Management, &management) != nil || json.Unmarshal(r.Recipients, &recipients) != nil || len(r.Version) != 32 {
		return authorization.Share{}, value.ErrUnavailable
	}
	v := authorization.Share{ID: uid(r.ID), RootID: uid(r.RootID), ArtifactID: uid(r.ArtifactID), CaseID: uid(r.CaseID),
		Target:   authorization.Target{ClusterID: uid(r.ClusterID), NamespaceUID: r.NamespaceUid, WorkloadUID: r.WorkloadUid, PodUID: r.PodUid},
		Creator:  identity.Principal{Issuer: r.CreatorIssuer, Subject: r.CreatorSubject, ClientID: r.CreatorClient, Kind: identity.Human},
		Revision: r.Revision, Management: management, CreatedAt: r.CreatedAt.Time, ExpiresAt: r.ExpiresAt.Time}
	copy(v.Version[:], r.Version)
	if r.RevokedAt.Valid {
		v.RevokedAt = r.RevokedAt.Time
	}
	keys := make([]string, 0, len(recipients))
	for _, x := range recipients {
		v.Recipients = append(v.Recipients, authorization.ShareRecipient{Kind: x.Kind, Issuer: x.Issuer, ID: x.ID})
		keys = append(keys, authorization.ShareRecipient{Kind: x.Kind, Issuer: x.Issuer, ID: x.ID}.Key())
	}
	// The indexed keys must be exactly the stored recipients' keys.
	stored := slices.Clone(r.RecipientKeys)
	slices.Sort(stored)
	slices.Sort(keys)
	if !v.Valid() || !slices.Equal(stored, keys) {
		return authorization.Share{}, value.ErrUnavailable
	}
	return v, nil
}

func (s *EvidenceShares) RecipientShares(ctx context.Context, artifactID string, caller identity.Identity) ([]authorization.Share, error) {
	keys := authorization.RecipientKeys(caller)
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(artifactID) || len(keys) == 0 || len(keys) > 257 {
		return nil, value.ErrUnavailable
	}
	var out []authorization.Share
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.ReadRecipientShares(ctx, custodydb.ReadRecipientSharesParams{RootID: id(s.root), ArtifactID: id(artifactID), Keys: keys})
		if err != nil {
			return err
		}
		out, err = s.observed(ctx, q, rows)
		return err
	})
	if err != nil {
		return nil, value.ErrUnavailable
	}
	for _, v := range out {
		if v.ArtifactID != artifactID {
			return nil, value.ErrUnavailable
		}
	}
	return out, nil
}

// OwnedShares returns the caller's own shares and the unrevoked, unexpired
// shares pinning a management assignment of the caller's user subject or one
// of its groups (ADR-232 increment 4). The second set is candidates only.
func (s *EvidenceShares) OwnedShares(ctx context.Context, caller identity.Identity, limit int) ([]authorization.Share, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !caller.Principal.Valid() || len(caller.Groups) > 256 || limit < 1 || limit > 100 {
		return nil, value.ErrUnavailable
	}
	// One containment pattern per subject: [{"Kind","Issuer","SubjectID"}].
	pattern := func(kind, subject string) ([]byte, error) {
		return json.Marshal([]map[string]string{{"Kind": kind, "Issuer": caller.Principal.Issuer, "SubjectID": subject}})
	}
	user, err := pattern("User", caller.Principal.Subject)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	managers := [][]byte{user}
	for _, g := range caller.Groups {
		b, err := pattern("Group", g)
		if err != nil {
			return nil, value.ErrUnavailable
		}
		managers = append(managers, b)
	}
	var out []authorization.Share
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.ListOwnedShares(ctx, custodydb.ListOwnedSharesParams{RootID: id(s.root), CreatorIssuer: caller.Principal.Issuer, CreatorSubject: caller.Principal.Subject, Managers: managers, RowLimit: int32(limit)})
		if err != nil {
			return err
		}
		out, err = s.observed(ctx, q, rows)
		return err
	})
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return out, nil
}

// Share reads one share of this root; a missing share is Denied.
func (s *EvidenceShares) Share(ctx context.Context, shareID string) (authorization.Share, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(shareID) {
		return authorization.Share{}, value.ErrUnavailable
	}
	var out []authorization.Share
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ReadShare(ctx, custodydb.ReadShareParams{RootID: id(s.root), ID: id(shareID)})
		if err != nil {
			return err
		}
		out, err = s.observed(ctx, q, []custodydb.EvidenceShare{row})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return authorization.Share{}, value.ErrDenied
	}
	if err != nil || len(out) != 1 || out[0].ID != shareID {
		return authorization.Share{}, value.ErrUnavailable
	}
	return out[0], nil
}

func (s *EvidenceShares) ReceivedShares(ctx context.Context, caller identity.Identity, limit int) ([]authorization.Share, error) {
	keys := authorization.RecipientKeys(caller)
	if s == nil || ctx == nil || ctx.Err() != nil || len(keys) == 0 || len(keys) > 257 || limit < 1 || limit > 100 {
		return nil, value.ErrUnavailable
	}
	var out []authorization.Share
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.ListReceivedShares(ctx, custodydb.ListReceivedSharesParams{RootID: id(s.root), Keys: keys, RowLimit: int32(limit)})
		if err != nil {
			return err
		}
		out, err = s.observed(ctx, q, rows)
		return err
	})
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return out, nil
}

// CreateShare inserts one share under the recovery fence and a per-artifact
// lock: a replayed creator key returns the original row (replay) when the
// request digest matches and Conflict otherwise; a 33rd active share of the
// artifact is Capacity. The insert copies case and target from the published
// case locator and requires them to equal the prepared share.
func (s *EvidenceShares) CreateShare(ctx context.Context, r sharing.Request, recovery artifact.RecoveryProof) (authorization.Share, bool, error) {
	var zero authorization.Share
	v := r.Share
	if s == nil || ctx == nil || ctx.Err() != nil || v.RootID != s.root || !authorization.UUID(v.ID) || !identity.Text(r.IdempotencyKey, 128) || r.RequestDigest == (artifact.Digest{}) {
		return zero, false, value.ErrInvalid
	}
	// Validate the complete prepared row with a provisional creation time.
	probe := v
	probe.CreatedAt, probe.Revision = v.ExpiresAt.Add(-time.Second), 1
	if !probe.Valid() {
		return zero, false, value.ErrInvalid
	}
	management, err := json.Marshal(v.Management)
	if err != nil {
		return zero, false, value.ErrInvalid
	}
	wires := make([]shareRecipientWire, 0, len(v.Recipients))
	keys := make([]string, 0, len(v.Recipients))
	for _, x := range v.Recipients {
		wires = append(wires, shareRecipientWire{x.Kind, x.Issuer, x.ID})
		keys = append(keys, x.Key())
	}
	recipients, err := json.Marshal(wires)
	if err != nil {
		return zero, false, value.ErrInvalid
	}
	var out authorization.Share
	replay := false
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		replay = false
		trust, err := s.recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		if err = q.LockShareArtifact(ctx, v.ArtifactID); err != nil {
			return err
		}
		row, err := q.ReadShareByKey(ctx, custodydb.ReadShareByKeyParams{RootID: id(s.root), CreatorIssuer: v.Creator.Issuer, CreatorSubject: v.Creator.Subject, IdempotencyKey: r.IdempotencyKey})
		switch {
		case err == nil:
			if !bytes.Equal(row.RequestDigest, r.RequestDigest[:]) {
				return value.ErrConflict
			}
			replay = true
		case errors.Is(err, pgx.ErrNoRows):
			active, err := q.CountActiveShares(ctx, custodydb.CountActiveSharesParams{RootID: id(s.root), ArtifactID: id(v.ArtifactID)})
			if err != nil {
				return err
			}
			if active >= authorization.ShareMaxActivePerArtifact {
				return value.ErrCapacity
			}
			row, err = q.InsertShare(ctx, custodydb.InsertShareParams{ID: id(v.ID), RootID: id(s.root), ArtifactID: id(v.ArtifactID), CaseID: id(v.CaseID),
				ClusterID: id(v.Target.ClusterID), NamespaceUid: v.Target.NamespaceUID, WorkloadUid: v.Target.WorkloadUID, PodUid: v.Target.PodUID,
				Version: v.Version[:], CreatorIssuer: v.Creator.Issuer, CreatorSubject: v.Creator.Subject, CreatorClient: v.Creator.ClientID,
				Management: management, Recipients: recipients, RecipientKeys: keys, IdempotencyKey: r.IdempotencyKey, RequestDigest: r.RequestDigest[:], ExpiresAt: ts(v.ExpiresAt)})
			if errors.Is(err, pgx.ErrNoRows) {
				// No published route with this case and target, or an expiry
				// outside (now, now+7 days].
				return value.ErrDenied
			}
			if err != nil {
				return err
			}
		default:
			return err
		}
		got, err := s.observed(ctx, q, []custodydb.EvidenceShare{row})
		if err != nil {
			return err
		}
		out = got[0]
		if err = s.recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return zero, false, shareError(err)
	}
	return out, replay, nil
}

// RevokeShare revokes a share once for its creator, with r.Managers for a
// manager the service found holding those pinned assignments now (ADR-232
// increment 4; every named assignment must be pinned by the locked row), or
// for an administrator the service checked (ADR-238). The same key after
// success is a replay; another key or a stale expected revision is Conflict;
// any other share (or none) is Denied without saying which.
func (s *EvidenceShares) RevokeShare(ctx context.Context, r sharing.Revocation, recovery artifact.RecoveryProof) (authorization.Share, bool, error) {
	var zero authorization.Share
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(r.ShareID) || !r.Actor.Valid() || len(r.Managers) > authorization.ShareMaxManagers || !identity.Text(r.IdempotencyKey, 128) || r.ExpectedRevision < 1 {
		return zero, false, value.ErrInvalid
	}
	var out authorization.Share
	replay := false
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		replay = false
		trust, err := s.recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		row, err := q.ReadShareForUpdate(ctx, custodydb.ReadShareForUpdateParams{RootID: id(s.root), ID: id(r.ShareID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return value.ErrDenied
		}
		if err != nil {
			return err
		}
		if !r.Administrator && (row.CreatorIssuer != r.Actor.Issuer || row.CreatorSubject != r.Actor.Subject) && !pinsAll(row.Management, r.Managers) {
			return value.ErrDenied
		}
		switch {
		case row.RevokedAt.Valid && row.RevokeKey == (pgtype.Text{String: r.IdempotencyKey, Valid: true}):
			replay = true
		case row.RevokedAt.Valid || row.Revision != r.ExpectedRevision:
			return value.ErrConflict
		default:
			if row, err = q.RevokeShare(ctx, custodydb.RevokeShareParams{RootID: id(s.root), ID: id(r.ShareID), RevokeKey: pgtype.Text{String: r.IdempotencyKey, Valid: true}}); err != nil {
				return err
			}
		}
		got, err := s.observed(ctx, q, []custodydb.EvidenceShare{row})
		if err != nil {
			return err
		}
		out = got[0]
		if err = s.recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return zero, false, shareError(err)
	}
	return out, replay, nil
}

// TransferShare replaces the management of a live share (ADR-238) for a
// manager the service found holding r.Managers now; each must be pinned by
// the locked row. The same key and request after success is a replay (the
// latest transfer only); the same key for another request, another key at a
// stale revision or a revoked share is Conflict; an expired, unknown or not
// managed share is Denied.
func (s *EvidenceShares) TransferShare(ctx context.Context, r sharing.Transfer, recovery artifact.RecoveryProof) (authorization.Share, bool, error) {
	var zero authorization.Share
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(r.ShareID) || !r.Actor.Valid() || len(r.Managers) < 1 || len(r.Managers) > authorization.ShareMaxManagers ||
		len(r.Management) < 1 || len(r.Management) > authorization.ShareMaxManagers || !identity.Text(r.IdempotencyKey, 128) || r.RequestDigest == (artifact.Digest{}) || r.ExpectedRevision < 1 {
		return zero, false, value.ErrInvalid
	}
	management, err := json.Marshal(r.Management)
	if err != nil {
		return zero, false, value.ErrInvalid
	}
	var out authorization.Share
	replay := false
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		replay = false
		trust, err := s.recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		row, err := q.ReadShareForUpdate(ctx, custodydb.ReadShareForUpdateParams{RootID: id(s.root), ID: id(r.ShareID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return value.ErrDenied
		}
		if err != nil {
			return err
		}
		if !pinsAll(row.Management, r.Managers) {
			return value.ErrDenied
		}
		switch {
		case row.TransferKey == (pgtype.Text{String: r.IdempotencyKey, Valid: true}):
			if !bytes.Equal(row.TransferDigest, r.RequestDigest[:]) {
				return value.ErrConflict
			}
			replay = true
		case row.RevokedAt.Valid || row.Revision != r.ExpectedRevision:
			return value.ErrConflict
		default:
			row, err = q.TransferShare(ctx, custodydb.TransferShareParams{RootID: id(s.root), ID: id(r.ShareID), Management: management, TransferKey: r.IdempotencyKey, TransferDigest: r.RequestDigest[:]})
			if errors.Is(err, pgx.ErrNoRows) {
				// Expired (or at the revision bound): nothing to manage.
				return value.ErrDenied
			}
			if err != nil {
				return err
			}
		}
		got, err := s.observed(ctx, q, []custodydb.EvidenceShare{row})
		if err != nil {
			return err
		}
		out = got[0]
		if err = s.recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return zero, false, shareError(err)
	}
	return out, replay, nil
}

// pinsAll reports whether the stored management pins every named assignment
// (at least one).
func pinsAll(management []byte, ids []string) bool {
	var pinned []artifact.AudienceAssignment
	if len(ids) == 0 || json.Unmarshal(management, &pinned) != nil {
		return false
	}
	for _, x := range ids {
		if !slices.ContainsFunc(pinned, func(a artifact.AudienceAssignment) bool { return a.AssignmentID == x }) {
			return false
		}
	}
	return true
}

func shareError(err error) error {
	for _, sentinel := range []error{value.ErrConflict, value.ErrCapacity, value.ErrDenied, value.ErrInvalid} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return value.ErrUnavailable
}
