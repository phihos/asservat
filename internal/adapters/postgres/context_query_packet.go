package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authapp "asservat.local/asservat/internal/application/authorization"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
)

func rawProjectionGrantOperation(scope query.ContextProjectionScope) string {
	if scope.DisplayVersion == query.PacketQueryDisplayVersion && scope.NativeType == artifact.RawPCAPNGArtifact {
		return authorization.GrantPacketQueryOperation
	}
	if scope.DisplayVersion == query.SyscallQueryDisplayVersion && scope.NativeType == artifact.SyscallArgumentsArtifact {
		return authorization.GrantSyscallQueryOperation
	}
	return ""
}

// Uses only the existing query/batch IDs. The narrow SQL predicate returns no
// parent review or other artifacts to the acquisition key service.
func packetQueryCurrentGrant(ctx context.Context, tx *custodydb.Queries, q query.ContextQuery, batchID string) error {
	if rawProjectionGrantOperation(q.Scope) == "" {
		return nil
	}
	valid, err := tx.PacketQueryGrantCurrent(ctx, custodydb.PacketQueryGrantCurrentParams{RootID: id(q.Scope.RootID), QueryID: id(q.ID), BatchID: id(batchID)})
	if err != nil {
		return err
	}
	if !valid {
		return query.ErrUnavailable
	}
	return nil
}

func (s *ContextQueries) reservePacketQueryBatch(ctx context.Context, tx *custodydb.Queries, q query.ContextQuery, batchID string) error {
	if rawProjectionGrantOperation(q.Scope) == "" {
		return nil
	}
	if err := packetQueryCurrentGrant(ctx, tx, q, ""); err != nil {
		return err
	}
	grants := AccessGrants{root: s.root}
	_, _, err := grants.reserveGrantUse(ctx, tx, authapp.GrantUseRequest{UseID: batchID, ParentID: q.Grant.ParentID, ChildID: q.Grant.ChildID, Use: authorization.GrantUse{Operation: rawProjectionGrantOperation(q.Scope), Bytes: query.ContextResultBytes, Operations: 1}})
	if err != nil {
		return err
	}
	return packetQueryCurrentGrant(ctx, tx, q, batchID)
}
