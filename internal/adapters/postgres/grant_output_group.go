package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"bytes"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

// ResolveGrantedOutput reads immutable association metadata, not caller or
// recovery authority. Effect transactions independently repeat the exact join.
func (s *AccessGrants) ResolveGrantedOutput(ctx context.Context, parent string, scope artifact.DownloadScope, action string) (authorization.VerifiedOutput, *authorization.GrantOutputGroup, error) {
	var out authorization.VerifiedOutput
	var group *authorization.GrantOutputGroup
	if s == nil || ctx == nil || ctx.Err() != nil || !scope.Valid() || scope.RootID != s.root || !authorization.UUID(parent) {
		return out, nil, authorization.ErrGrantScope
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		var err error
		out, group, err = resolveGrantedGroupOutput(ctx, q, parent, scope, action)
		return err
	})
	return out, group, grantError(err)
}
func resolveGrantedGroupOutput(ctx context.Context, q *custodydb.Queries, parent string, scope artifact.DownloadScope, action string) (authorization.VerifiedOutput, *authorization.GrantOutputGroup, error) {
	var out authorization.VerifiedOutput
	row, err := q.ResolveGrantedGroupOutput(ctx, custodydb.ResolveGrantedGroupOutputParams{ParentID: id(parent), RootID: id(scope.RootID), CaptureID: id(scope.CaptureID), ArtifactID: id(scope.ArtifactID), Version: scope.Version[:], ClusterID: id(scope.ClusterID), NamespaceUid: scope.NamespaceUID, WorkloadUid: scope.WorkloadUID, PodUid: scope.PodUID, ActionID: action})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil, authorization.ErrGrantScope
	}
	if err != nil {
		return out, nil, err
	}
	var group authorization.GrantOutputGroup
	if len(row.ExecutionDigest) != 32 || queryDecode(row.GroupAssociation, 4096, &group) != nil || !group.Valid() {
		return out, nil, authorization.ErrGrantScope
	}
	out = authorization.VerifiedOutput{CaptureID: uid(row.CaptureID), ArtifactID: scope.ArtifactID, ActionID: row.ActionID, ArtifactDigest: scope.Version, Target: authorization.Target{ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, PodUID: scope.PodUID}}
	copy(out.ExecutionDigest[:], row.ExecutionDigest)
	if !out.Valid() || group.CaptureID != out.CaptureID || group.ArtifactID != out.ArtifactID || group.ActionID != out.ActionID || !bytes.Equal(group.ExecutionDigest[:], row.ExecutionDigest) {
		return authorization.VerifiedOutput{}, nil, authorization.ErrGrantScope
	}
	return out, &group, nil
}
