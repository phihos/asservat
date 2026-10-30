package postgres

import (
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

// Created only after this transaction's permission-stream FOR UPDATE lock and
// replay lookup. Supported permission/receipt writers take that root lock;
// decision-time reviews take its conflicting SHARE lock. Only raw projections
// are retained. Every caller still evaluates expiry against current DB time.
// Nothing survives the transaction, and no policy or other authority is cached.
type recordingGroupPermissions struct {
	q        *custodydb.Queries
	stream   custodydb.PermissionStream
	byTarget map[authorization.Target]authorization.Projection
}

func newRecordingGroupPermissions(q *custodydb.Queries, stream custodydb.PermissionStream) *recordingGroupPermissions {
	return &recordingGroupPermissions{q: q, stream: stream, byTarget: make(map[authorization.Target]authorization.Projection)}
}

func (p *recordingGroupPermissions) read(ctx context.Context, q *custodydb.Queries, stream custodydb.PermissionStream, target authorization.Target) (authorization.Projection, error) {
	if p == nil {
		return permissionProjection(ctx, q, stream, target)
	}
	if ctx.Err() != nil {
		return authorization.Projection{}, ctx.Err()
	}
	if q != p.q || stream.ID != p.stream.ID || stream.Epoch != p.stream.Epoch || stream.Sequence != p.stream.Sequence || !target.Valid() {
		return authorization.Projection{}, value.ErrInvalid
	}
	if projection, ok := p.byTarget[target]; ok {
		return projection, nil
	}
	if len(p.byTarget) >= value.MaxRecordingSaveGroupChildren {
		return authorization.Projection{}, value.ErrCapacity
	}
	projection, err := permissionProjection(ctx, q, stream, target)
	if err != nil {
		return authorization.Projection{}, err
	}
	if projection.Target != target {
		return authorization.Projection{}, value.ErrChanged
	}
	p.byTarget[target] = projection
	return projection, nil
}
