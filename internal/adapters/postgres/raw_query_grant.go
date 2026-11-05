package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var _ app.RawQueryGrantStore = (*AccessGrants)(nil)

func rawQueryKey(root string, p identity.Principal, key string) custodydb.ReadRawQueryByKeyParams {
	return custodydb.ReadRawQueryByKeyParams{RootID: id(root), RequesterKey: policyGrantActorKey(p), IdempotencyKey: key}
}
func rawQueryRequestMatches(r custodydb.AccessGrant, p identity.Principal, d artifact.Digest) bool {
	return r.Kind == value.GrantRawQuery && r.RequestOperation == "requestRawAccess" && r.RequesterKind == string(identity.Human) && r.RequesterIssuer == p.Issuer && r.RequesterSubject == p.Subject && r.RequesterClient == p.ClientID && bytes.Equal(r.RequestDigest, d[:])
}
func (s *AccessGrants) RawQueryRequest(ctx context.Context, p identity.Principal, key string) (app.StoredGrantRequest, error) {
	var out app.StoredGrantRequest
	if s == nil || !p.Valid() || p.Kind != identity.Human || !identity.Text(key, 128) {
		return out, value.ErrGrantInvalid
	}
	g, err := s.read(ctx, func(q *custodydb.Queries) (custodydb.AccessGrant, error) {
		row, err := q.ReadRawQueryByKey(ctx, rawQueryKey(s.root, p, key))
		if err != nil {
			return row, err
		}
		if len(row.RequestDigest) != 32 || row.RequesterIssuer != p.Issuer || row.RequesterSubject != p.Subject || row.RequesterClient != p.ClientID {
			return row, app.ErrGrantConflict
		}
		copy(out.RequestDigest[:], row.RequestDigest)
		return row, nil
	})
	if err != nil {
		return app.StoredGrantRequest{}, err
	}
	out.Grant = g
	out.IdempotencyKey = key
	return out, nil
}
func (s *AccessGrants) requestRawQueryGrant(ctx context.Context, in app.StoredGrantRequest, recovery artifact.RecoveryProof) (value.Grant, bool, error) {
	var out value.Grant
	g := in.Grant
	if !g.RequestedAt.IsZero() || !g.ReviewUntil.IsZero() || g.Spent != (value.GrantSpend{}) || !app.RawQueryScopeMatches(g) {
		return out, false, value.ErrGrantInvalid
	}
	probe := g
	probe.RequestedAt = time.Now().UTC()
	probe.ReviewUntil = probe.RequestedAt.Add(value.GrantReviewWindow)
	if !g.RawQuery.NotAfter.Equal(g.RawQuery.NotAfter.UTC().Truncate(time.Microsecond)) {
		return out, false, value.ErrGrantInvalid
	}
	raw, err := json.Marshal(g.RawQuery)
	if err != nil {
		return out, false, value.ErrGrantInvalid
	}
	reasons := make([]grantReasonWire, 0, len(g.Reasons))
	for _, r := range g.Reasons {
		reasons = append(reasons, grantReasonWire{r.ActionID, r.Code})
	}
	reasonBytes, err := json.Marshal(reasons)
	if err != nil {
		return out, false, err
	}
	replay := false
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		replay = false
		trust, err := s.recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		row, err := q.ReadRawQueryByKey(ctx, rawQueryKey(s.root, g.Requester, in.IdempotencyKey))
		if errors.Is(err, pgx.ErrNoRows) {
			if !probe.Valid() {
				return value.ErrGrantInvalid
			}
			row, err = q.InsertRawQueryGrant(ctx, custodydb.InsertRawQueryGrantParams{ID: id(g.ID), RootID: id(s.root), ExecutionDigest: g.ExecutionDigest[:], ReviewDigest: g.ReviewDigest[:], Reasons: reasonBytes, Review: g.Review, Scope: g.Scope, RequesterIssuer: g.Requester.Issuer, RequesterSubject: g.Requester.Subject, RequesterClient: g.Requester.ClientID, RequesterKey: policyGrantActorKey(g.Requester), LifetimeSeconds: int32(g.Lifetime / time.Second), RawQuery: raw, NotAfter: ts(g.RawQuery.NotAfter), MaxArtifacts: int32(len(g.RawQuery.Artifacts)), MaxBytes: g.RawQuery.MaxBytes, MaxOperations: g.RawQuery.MaxOperations, IdempotencyKey: in.IdempotencyKey, RequestDigest: in.RequestDigest[:]})
			if errors.Is(err, pgx.ErrNoRows) {
				row, err = q.ReadRawQueryByKey(ctx, rawQueryKey(s.root, g.Requester, in.IdempotencyKey))
				replay = true
			}
		} else if err == nil {
			replay = true
		}
		if err != nil {
			return err
		}
		if !rawQueryRequestMatches(row, g.Requester, in.RequestDigest) {
			return app.ErrGrantConflict
		}
		out, err = s.grant(row)
		if err != nil {
			return err
		}
		if err = s.recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return value.Grant{}, false, grantError(err)
	}
	return out, replay, nil
}
func (s *AccessGrants) RawQueryCandidates(ctx context.Context, scope artifact.DownloadScope, use value.GrantUse) ([]value.Grant, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !scope.Valid() || scope.RootID != s.root || scope.Principal.Kind != identity.Human || (use != (value.GrantUse{}) && use.Operation != value.GrantDownloadOperation && use.Operation != value.GrantPacketQueryOperation) || use.Bytes < 0 || use.Operations < 0 {
		return nil, value.ErrGrantInvalid
	}
	// This is index selection only; domain membership checks compare the full
	// original output tuple, current permissions and exact principal at use.
	member, err := json.Marshal(map[string]any{"Artifacts": []any{map[string]any{"Output": map[string]any{"ArtifactID": scope.ArtifactID, "ArtifactDigest": scope.Version, "CaptureID": scope.CaptureID, "Target": value.Target{ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, PodUID: scope.PodUID}}}}})
	if err != nil {
		return nil, err
	}
	version, _ := json.Marshal(scope.Version)
	var out []value.Grant
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.ReadRawQueryCandidates(ctx, custodydb.ReadRawQueryCandidatesParams{RootID: id(s.root), RequesterKey: policyGrantActorKey(scope.Principal), RequesterIssuer: scope.Principal.Issuer, RequesterSubject: scope.Principal.Subject, RequesterClient: scope.Principal.ClientID, Member: member, Version: version, ArtifactID: id(scope.ArtifactID), Bytes: use.Bytes, Operations: use.Operations, Operation: use.Operation})
		if err != nil {
			return err
		}
		out = nil
		for _, r := range rows {
			g, err := s.grant(r)
			if err != nil {
				return err
			}
			out = append(out, g)
		}
		return ctx.Err()
	})
	if err != nil {
		return nil, grantError(err)
	}
	if len(out) == 0 {
		return nil, app.ErrGrantNotFound
	}
	return out, nil
}
func (s *AccessGrants) GrantUseByID(ctx context.Context, useID string) (app.GrantUseRequest, error) {
	var out app.GrantUseRequest
	if s == nil || ctx == nil || ctx.Err() != nil || !value.UUID(useID) {
		return out, value.ErrGrantInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		r, err := q.ReadGrantUse(ctx, custodydb.ReadGrantUseParams{RootID: id(s.root), ID: id(useID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return app.ErrGrantNotFound
		}
		if err != nil {
			return err
		}
		out = app.GrantUseRequest{UseID: uid(r.ID), ParentID: uid(r.ParentID), ChildID: uid(r.ChildID), Use: value.GrantUse{Operation: r.Operation, Bytes: r.Bytes, Operations: r.Operations}}
		return ctx.Err()
	})
	if err != nil {
		return app.GrantUseRequest{}, grantError(err)
	}
	return out, nil
}

// The raw parent has no common target or capture. Its exact immutable member
// supplies these original facts, while the row keeps its own ciphertext version.
func rawQueryChildOutput(parent value.Grant, artifactID string) (value.VerifiedOutput, bool) {
	if parent.RawQuery == nil {
		return value.VerifiedOutput{}, false
	}
	for _, a := range parent.RawQuery.Artifacts {
		if a.Output.ArtifactID == artifactID {
			return a.Output, true
		}
	}
	return value.VerifiedOutput{}, false
}

// CountRegisteredGrantArtifacts only observes the selected artifact capacity;
// actual materialization still atomically checks and charges the original pool.
func (s *AccessGrants) CountRegisteredGrantArtifacts(ctx context.Context, parent string, artifacts []string) (int, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !value.UUID(parent) || len(artifacts) < 1 || len(artifacts) > value.GrantMaxResultArtifacts {
		return 0, value.ErrGrantInvalid
	}
	ids := make([]pgtype.UUID, len(artifacts))
	seen := make(map[string]bool, len(artifacts))
	for n, a := range artifacts {
		if !value.UUID(a) || seen[a] {
			return 0, value.ErrGrantInvalid
		}
		seen[a] = true
		ids[n] = id(a)
	}
	var count int64
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		var err error
		count, err = q.CountRegisteredGrantArtifacts(ctx, custodydb.CountRegisteredGrantArtifactsParams{RootID: id(s.root), ParentID: id(parent), ArtifactIds: ids})
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return 0, grantError(err)
	}
	if count < 0 || count > int64(len(artifacts)) {
		return 0, app.ErrGrantUnavailable
	}
	return int(count), nil
}
