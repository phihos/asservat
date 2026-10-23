package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auth "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

func projectionActualProof(q query.ContextQuery, b query.ContextReadBatch, en value.AcquisitionEnrollment, o evidence.NativeOrigin) query.ContextProjectionWorkerProof {
	w := en.Worker
	binding := w.Binding
	return query.ContextProjectionWorkerProof{
		Binding: query.ContextProjectionWorkerBinding{QueryID: q.ID, WorkerID: q.WorkerID, InstallationID: binding.InstallationID, ClusterID: binding.ClusterID, Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID,
			ServiceAccount: binding.ServiceAccount, ServiceAccountUID: binding.ServiceAccountUID, Job: binding.Job, JobUID: binding.JobUID, Pod: binding.Pod, PodUID: binding.PodUID, JobSpec: binding.JobSpec, PodSpec: binding.PodSpec, Configuration: w.Intent.Profile.Configuration},
		Peer: o.Proof.Peer, ProcessEpoch: b.Worker.ProcessEpoch, PublicKey: en.PublicKeyDigest, TokenDigest: o.Proof.TokenDigest,
		// The actual attester checks the profile's complete protected source before
		// and after TokenReview. This is that accepted profile revision, not a new
		// source observation or an invented independent protection generation.
		Protection: w.Intent.Profile.Configuration, ObservedAt: o.Proof.ObservedAt, ValidUntil: o.Proof.FreshUntil,
	}
}
func (s *ProjectionNativeOperations) BindProjectionNativeKeys(ctx context.Context, start query.ContextReadStart, a query.ContextProjectionAuthority, o value.NativeOperation, scope value.KeyScope, origin evidence.NativeOrigin) error {
	b := start.Batch
	if s == nil || ctx == nil || !start.Fresh || start.ClaimID != b.ID || !scope.Valid() || scope.Purpose != "artifact" || !origin.Proof.Valid(time.Now()) || !origin.Lease.Operation.Equal(o) || origin.Lease.Certificate != origin.Proof.Peer.Certificate || o.Reference.OperationID != b.ID {
		return auth.ErrKeyDenied
	}
	return s.queries.withBatch(ctx, b, a, func(ctx context.Context, tx *custodydb.Queries, q query.ContextQuery, row custodydb.ContextQueryBatch) error {
		_, stored, original, e := projectionNativeRecord(row, q)
		if e != nil || row.NativeClosed || uid(row.ClaimID) != b.ID || !stored.Equal(o) || !sameAuditJSON(original, a) || scope.InstallationID != q.Plan.InstallationID {
			return auth.ErrKeyDenied
		}
		en, e := projectionNativeWorker(ctx, tx, q, b, o, origin.Proof.Peer)
		if e != nil || en.Worker.Binding != origin.Proof.Binding {
			return auth.ErrKeyDenied
		}
		proof := projectionActualProof(q, b, en, origin)
		now, e := tx.CurrentTime(ctx)
		if e != nil {
			return e
		}
		end := identity.Earlier(b.Until, identity.Earlier(a.ValidUntil, identity.Earlier(o.Until, proof.ValidUntil)))
		binding := query.ContextProjectionKeyBinding{Purpose: query.ContextProjectionPurpose, ClaimID: b.ID, Batch: b, SourceVersion: q.Scope.Version, Scope: scope, Worker: proof, Authority: a, CreatedAt: now.Time, Until: end}
		if !binding.Valid(q, now.Time) {
			return auth.ErrKeyDenied
		}
		_, e = tx.ReadProjectionKeyBinding(ctx, id(b.ID))
		// Native before-callback runs once. An existing or uncertain child can never
		// be rebound/refilled under a second observation.
		if !errors.Is(e, pgx.ErrNoRows) {
			return auth.ErrKeyDenied
		}
		raw, e := queryJSON(binding)
		if e != nil || len(raw) > 16384 {
			return auth.ErrKeyDenied
		}
		return tx.InsertProjectionKeyBinding(ctx, custodydb.InsertProjectionKeyBindingParams{BatchID: id(b.ID), QueryID: id(q.ID), Binding: raw})
	})
}

type ProjectionKeys struct {
	queries *ContextQueries
	scope   value.KeyScope
}

func NewProjectionKeys(q *ContextQueries, scope value.KeyScope) (*ProjectionKeys, error) {
	if q == nil || q.ledger == nil || !scope.Valid() || scope.Purpose != "artifact" || scope.InstallationID != q.recovery.installation {
		return nil, auth.ErrKeyDenied
	}
	return &ProjectionKeys{q, scope}, nil
}
func (s *ProjectionKeys) Resolve(ctx context.Context, peer value.KeyPeer, r value.KeyRequestInfo) (value.KeyOperationPermit, error) {
	var out value.KeyOperationPermit
	if s == nil || ctx == nil || ctx.Err() != nil || r.Scope != s.scope || r.Operation != "unwrap" || r.Version != 0 || !value.UUID(r.AuthorityID) || r.RequestDigest == (artifact.Digest{}) || len(r.Binding) < 1 || len(r.Binding) > 2048 || peer.Role != "acquisition" || !peer.CanRequest(s.scope, "unwrap") || !strings.HasPrefix(r.Reference, "asservat-local-keyset/v1/"+s.scope.InstallationID+"/artifact/"+s.scope.KeyID+"/") {
		return out, auth.ErrKeyDenied
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	row, e := custodydb.New(s.queries.ledger.pool).ReadProjectionKeyBinding(call, id(r.AuthorityID))
	if e != nil {
		return out, auth.ErrKeyDenied
	}
	var binding query.ContextProjectionKeyBinding
	if queryDecode(row.Binding, 16384, &binding) != nil || binding.Scope != s.scope || binding.ClaimID != r.AuthorityID || binding.Authority.Scope.RootID != s.queries.root || binding.Worker.Peer != peer {
		return out, auth.ErrKeyDenied
	}
	e = s.queries.withBatch(call, binding.Batch, binding.Authority, func(ctx context.Context, tx *custodydb.Queries, q query.ContextQuery, batch custodydb.ContextQueryBatch) error {
		_, o, a, e := projectionNativeRecord(batch, q)
		if e != nil || batch.NativeClosed || uid(batch.ClaimID) != binding.ClaimID || !sameAuditJSON(a, binding.Authority) || o.ParentID != binding.ClaimID {
			return auth.ErrKeyDenied
		}
		en, e := projectionNativeWorker(ctx, tx, q, binding.Batch, o, peer)
		if e != nil || en.PublicKeyDigest != binding.Worker.PublicKey {
			return auth.ErrKeyDenied
		}
		active, e := tx.LockProjectionKeyBinding(ctx, id(r.AuthorityID))
		if e != nil || !bytes.Equal(active.Binding, row.Binding) || active.QueryID != id(q.ID) {
			return auth.ErrKeyDenied
		}
		now, e := tx.CurrentTime(ctx)
		if e != nil || !binding.Valid(q, now.Time) || !peer.Valid(now.Time) {
			return auth.ErrKeyDenied
		}
		published, e := tx.ReadPublishedContext(ctx, custodydb.ReadPublishedContextParams{ArtifactID: id(q.Scope.ArtifactID), RootID: id(q.Scope.RootID)})
		if e != nil {
			return e
		}
		expected, e := currentPublishedContext(published)
		if e != nil {
			return e
		}
		mask := int16(0)
		for _, role := range []query.ContextProjectionKeyRole{query.ContextProjectionDataKey, query.ContextProjectionIndexKey, query.ContextProjectionManifestKey} {
			actual, e := evidence.ArtifactKeyBinding(expected.Binding(), string(role))
			if e != nil {
				return e
			}
			if bytes.Equal(actual, r.Binding) {
				mask = int16(role.Mask())
				break
			}
		}
		if mask == 0 || active.UsedRoles&mask != 0 {
			return auth.ErrKeyDenied
		}
		count, e := tx.ConsumeProjectionKeyRole(ctx, custodydb.ConsumeProjectionKeyRoleParams{BatchID: id(r.AuthorityID), Role: mask})
		if e != nil || count != 1 {
			return auth.ErrKeyDenied
		}
		out = value.KeyOperationPermit{AuthorityID: r.AuthorityID, RecoveryEpoch: a.Environment.Recovery.IssuerEpoch, Revision: uint64(binding.Batch.Generation), Certificate: peer.Certificate, RequestDigest: r.RequestDigest, ObservedAt: now.Time, ValidUntil: identity.Earlier(binding.Until, peer.NotAfter)}
		after, e := tx.CurrentTime(ctx)
		if e != nil || !out.Valid(peer, r, after.Time) || !binding.Valid(q, after.Time) {
			return auth.ErrKeyDenied
		}
		return nil
	})
	if e != nil {
		return value.KeyOperationPermit{}, auth.ErrKeyDenied
	}
	return out, nil
}
