package postgres

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auth "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
)

const comparisonKeyChildBytes = 4096

func insertProjectionComparisonKeyChildren(ctx context.Context, tx *custodydb.Queries, q query.ContextQuery, b query.ContextReadBatch, a query.ContextProjectionAuthority, scope value.KeyScope, proof query.ContextProjectionWorkerProof, created, until time.Time) error {
	ids, e := query.ProfileComparisonKeyChildIDs(b.ID)
	if e != nil {
		return auth.ErrKeyDenied
	}
	old, e := tx.ProjectionComparisonKeyChildren(ctx, id(b.ID))
	if e != nil || len(old) != 0 {
		return auth.ErrKeyDenied
	}
	for ordinal, childID := range ids {
		version := q.Scope.Version
		if ordinal == 0 {
			version = q.Scope.Comparison.Baseline.Version
		}
		child := query.ContextProjectionComparisonKeyChild{ID: childID, QueryID: q.ID, BatchID: b.ID, WorkerID: q.WorkerID, ProcessEpoch: b.Worker.ProcessEpoch, SourceOrdinal: ordinal, SourceVersion: version, AuthorityDigest: a.DecisionDigest, PublicKey: proof.PublicKey, Certificate: proof.Peer.Certificate, Scope: scope, CreatedAt: created, Until: identity.Earlier(until, q.ProviderUntil)}
		if !child.Valid(q, b, a, created) {
			return auth.ErrKeyDenied
		}
		raw, e := queryJSON(child)
		if e != nil || len(raw) > comparisonKeyChildBytes {
			return auth.ErrKeyDenied
		}
		if e = tx.InsertProjectionComparisonKeyChild(ctx, custodydb.InsertProjectionComparisonKeyChildParams{ChildID: id(childID), BatchID: id(b.ID), QueryID: id(q.ID), SourceOrdinal: pgtype.Int2{Int16: int16(ordinal), Valid: true}, Binding: raw}); e != nil {
			return e
		}
	}
	return nil
}

func (s *ProjectionKeys) resolveComparisonKeyChild(ctx context.Context, peer value.KeyPeer, r value.KeyRequestInfo) (value.KeyOperationPermit, error) {
	var out value.KeyOperationPermit
	tx := custodydb.New(s.queries.ledger.pool)
	row, e := tx.ReadProjectionComparisonKeyChild(ctx, id(r.AuthorityID))
	var child query.ContextProjectionComparisonKeyChild
	if e != nil || queryDecode(row.Binding, comparisonKeyChildBytes, &child) != nil || child.ID != r.AuthorityID || child.Scope != s.scope || child.WorkerID == "" || child.Certificate != peer.Certificate || child.ProcessEpoch == "" || !row.SourceOrdinal.Valid || int(row.SourceOrdinal.Int16) != child.SourceOrdinal || child.QueryID != uid(row.QueryID) || child.BatchID != uid(row.BatchID) {
		return out, auth.ErrKeyDenied
	}
	parent, e := tx.ReadAcquisitionQuery(ctx, custodydb.ReadAcquisitionQueryParams{ID: id(child.QueryID), RootID: id(s.queries.root)})
	if e != nil {
		return out, auth.ErrKeyDenied
	}
	q, e := queryFromRow(parent)
	if e != nil {
		return out, auth.ErrKeyDenied
	}
	batch, e := tx.ReadProjectionNativeBatch(ctx, custodydb.ReadProjectionNativeBatchParams{ID: id(q.ID), RootID: id(s.queries.root), WorkerID: id(q.WorkerID)})
	if e != nil {
		return out, auth.ErrKeyDenied
	}
	b, o, a, e := projectionNativeRecord(batch, q)
	if e != nil || batch.NativeClosed || child.BatchID != b.ID || !child.Valid(q, b, a, time.Now()) {
		return out, auth.ErrKeyDenied
	}
	e = s.queries.withBatch(ctx, b, a, func(ctx context.Context, tx *custodydb.Queries, current query.ContextQuery, batch custodydb.ContextQueryBatch) error {
		_, stored, actual, e := projectionNativeRecord(batch, current)
		if e != nil || batch.NativeClosed || !stored.Equal(o) || !sameAuditJSON(a, actual) || child.AuthorityDigest != actual.DecisionDigest {
			return auth.ErrKeyDenied
		}
		en, e := projectionNativeWorker(ctx, tx, current, b, stored, peer)
		if e != nil || en.PublicKeyDigest != child.PublicKey {
			return auth.ErrKeyDenied
		}
		active, e := tx.LockProjectionComparisonKeyChild(ctx, id(child.ID))
		if e != nil || !bytes.Equal(active.Binding, row.Binding) || active.BatchID != id(b.ID) || active.QueryID != id(current.ID) || active.SourceOrdinal != row.SourceOrdinal {
			return auth.ErrKeyDenied
		}
		// Both children must have committed together before either source can use a
		// slot. The deferred SQL constraint also refuses a partial binding commit.
		children, e := tx.ProjectionComparisonKeyChildren(ctx, id(b.ID))
		if e != nil || len(children) != 2 {
			return auth.ErrKeyDenied
		}
		now, e := tx.CurrentTime(ctx)
		if e != nil || !child.Valid(current, b, actual, now.Time) || !peer.Valid(now.Time) {
			return auth.ErrKeyDenied
		}
		selected, ok := current.Scope.IncidentScope()
		if child.SourceOrdinal == 0 {
			selected, ok = current.Scope.BaselineScope()
		}
		if !ok {
			return auth.ErrKeyDenied
		}
		mask, e := projectionPublishedKeyMask(ctx, tx, selected, r.Binding)
		if e != nil || mask == 0 || active.UsedRoles&mask != 0 {
			return auth.ErrKeyDenied
		}
		count, e := tx.ConsumeProjectionComparisonKeyRole(ctx, custodydb.ConsumeProjectionComparisonKeyRoleParams{ChildID: id(child.ID), Role: mask})
		if e != nil || count != 1 {
			return auth.ErrKeyDenied
		}
		out = value.KeyOperationPermit{AuthorityID: child.ID, RecoveryEpoch: actual.Environment.Recovery.IssuerEpoch, Revision: uint64(b.Generation), Certificate: peer.Certificate, RequestDigest: r.RequestDigest, ObservedAt: now.Time, ValidUntil: identity.Earlier(now.Time.Add(5*time.Second), identity.Earlier(child.Until, peer.NotAfter))}
		after, e := tx.CurrentTime(ctx)
		if e != nil || !out.Valid(peer, r, after.Time) || !child.Valid(current, b, actual, after.Time) {
			return auth.ErrKeyDenied
		}
		return nil
	})
	if e != nil {
		return value.KeyOperationPermit{}, auth.ErrKeyDenied
	}
	return out, nil
}

func projectionPublishedKeyMask(ctx context.Context, tx *custodydb.Queries, scope query.ContextProjectionScope, binding []byte) (int16, error) {
	published, e := tx.ReadPublishedContext(ctx, custodydb.ReadPublishedContextParams{ArtifactID: id(scope.ArtifactID), RootID: id(scope.RootID)})
	if e != nil {
		return 0, e
	}
	expected, e := currentPublishedContext(published)
	if e != nil || !bytes.Equal(published.ContextVerification.CopiesDigest, scope.Version[:]) || !scopeSource(scope, expected) {
		return 0, auth.ErrKeyDenied
	}
	for _, role := range []query.ContextProjectionKeyRole{query.ContextProjectionDataKey, query.ContextProjectionIndexKey, query.ContextProjectionManifestKey} {
		aad, e := evidence.ArtifactKeyBinding(expected.Binding(), string(role))
		if e != nil {
			return 0, e
		}
		if bytes.Equal(aad, binding) {
			return int16(role.Mask()), nil
		}
	}
	return 0, auth.ErrKeyDenied
}
