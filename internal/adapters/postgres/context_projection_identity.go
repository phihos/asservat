package postgres

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5"
)

// The query's immutable identity child is historical admitted identity, not a
// live TLS/TokenReview proof. Actual native admission supplies that proof before
// commands and key binding. The public caller cannot select or replace a Pod.
type projectionQueryIdentity struct {
	Enrollment value.AcquisitionEnrollment
	Peer       value.KeyPeer
}

func projectionIdentityWorker(q query.ContextQuery, e value.AcquisitionEnrollment, p value.KeyPeer) query.ContextQueryWorker {
	return query.ContextQueryWorker{QueryID: q.ID, WorkerID: q.WorkerID, PeerID: p.PeerID, PodUID: e.Worker.Binding.PodUID,
		// One Pod and one immutable enrollment key belong to this admitted ID. This
		// is an identity epoch, not a claim to have observed a fresh OS process UUID.
		ProcessEpoch: q.WorkerID, Certificate: p.Certificate, Configuration: e.Worker.Intent.Profile.Configuration}
}
func projectionCredential(ctx context.Context, tx *custodydb.Queries, q query.ContextQuery, w value.AcquisitionWorker) (evidence.ProjectionCredential, error) {
	var out evidence.ProjectionCredential
	row, e := tx.ReadWorkerEnrollment(ctx, id(w.Intent.ID))
	if errors.Is(e, pgx.ErrNoRows) {
		return out, nil
	}
	if e != nil {
		return out, e
	}
	en, e := decodeAcquisitionEnrollment(row, w)
	if e != nil {
		return out, e
	}
	_, ok, e := acquisitionEnrollmentReceipt(row, en)
	if e != nil {
		return out, e
	}
	if !ok {
		return out, nil
	}
	now, e := tx.CurrentTime(ctx)
	if e != nil {
		return out, e
	}
	epoch, _, e := w.CertificateEpoch(now.Time)
	if e != nil {
		return out, e
	}
	rows, e := tx.ReadWorkerCertificateEpoch(ctx, custodydb.ReadWorkerCertificateEpochParams{WorkerID: id(w.Intent.ID), Epoch: int32(epoch)})
	if e != nil || len(rows) > 2 {
		return out, query.ErrUnavailable
	}
	for _, r := range rows {
		if !r.ActivatedAt.Valid {
			continue
		}
		attempt, e := decodeAcquisitionCertificateAttempt(r)
		if e != nil || attempt.Enrollment != en {
			return out, query.ErrUnavailable
		}
		cert, e := decodeAcquisitionCertificate(r, attempt)
		if e != nil {
			return out, e
		}
		if !cert.Peer.Valid(now.Time) {
			continue
		}
		if e = activeAcquisitionCertificate(ctx, tx, w, cert.Peer); e != nil {
			return out, e
		}
		if out.Ready {
			return evidence.ProjectionCredential{}, query.ErrUnavailable
		}
		out = evidence.ProjectionCredential{Enrollment: en, Peer: cert.Peer, Ready: true}
	}
	return out, nil
}
func (s *ProjectionWorkers) ReadProjectionCredential(ctx context.Context, q query.ContextQuery, r query.ContextQueryRequest, a query.ContextProjectionAuthority) (evidence.ProjectionCredential, error) {
	var out evidence.ProjectionCredential
	e := s.current(ctx, q, r, a, func(ctx context.Context, tx *custodydb.Queries) error {
		row, e := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(q.WorkerID), RootID: id(q.Scope.RootID)})
		if e != nil || row.TerminationJson != nil || row.RetiredProofJson != nil {
			return query.ErrUnavailable
		}
		state, e := projectionWorkerState(row, q)
		if e != nil || !state.Audited || !state.Worker.Valid() {
			return query.ErrUnavailable
		}
		out, e = projectionCredential(ctx, tx, q, state.Worker)
		return e
	})
	if e != nil {
		return evidence.ProjectionCredential{}, e
	}
	return out, nil
}
func (s *ProjectionWorkers) BindProjectionIdentity(ctx context.Context, q query.ContextQuery, r query.ContextQueryRequest, a query.ContextProjectionAuthority, c evidence.ProjectionCredential) (query.ContextQueryWorker, error) {
	var out query.ContextQueryWorker
	if !c.Ready || !c.Enrollment.Valid() || c.Enrollment.Worker.Intent.ID != q.WorkerID {
		return out, query.ErrUnavailable
	}
	e := s.current(ctx, q, r, a, func(ctx context.Context, tx *custodydb.Queries) error {
		row, e := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(q.WorkerID), RootID: id(q.Scope.RootID)})
		if e != nil || row.TerminationJson != nil || row.RetiredProofJson != nil {
			return query.ErrUnavailable
		}
		state, e := projectionWorkerState(row, q)
		if e != nil || !state.Audited || state.Worker != c.Enrollment.Worker {
			return query.ErrUnavailable
		}
		current, e := projectionCredential(ctx, tx, q, state.Worker)
		if e != nil || !current.Ready || current.Enrollment != c.Enrollment || current.Peer != c.Peer {
			return query.ErrUnavailable
		}
		out = projectionIdentityWorker(q, c.Enrollment, c.Peer)
		if !out.Matches(q) {
			return query.ErrUnavailable
		}
		old, e := tx.ReadContextQueryWorker(ctx, id(q.ID))
		stored := projectionQueryIdentity{Enrollment: c.Enrollment, Peer: c.Peer}
		if e == nil {
			var prior query.ContextQueryWorker
			var priorProof projectionQueryIdentity
			if queryDecode(old.Binding, 16384, &prior) != nil || queryDecode(old.Proof, 65536, &priorProof) != nil || prior != out || priorProof != stored {
				return query.ErrUnavailable
			}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		binding, e := queryJSON(out)
		if e != nil {
			return e
		}
		proof, e := queryJSON(stored)
		if e != nil {
			return e
		}
		return tx.InsertProjectionQueryWorker(ctx, custodydb.InsertProjectionQueryWorkerParams{QueryID: id(q.ID), WorkerID: id(q.WorkerID), Binding: binding, Proof: proof})
	})
	if e != nil {
		return query.ContextQueryWorker{}, e
	}
	return out, nil
}

// This guard checks admitted identity and certificate state around the query
// SQL callback. It never substitutes for the actual token/TLS proof at native
// admission. Every callback joins before the original request can return.
type projectionIdentityGuard struct{ workers *ProjectionWorkers }

func (s projectionIdentityGuard) WithCurrentProjectionWorker(ctx context.Context, q query.ContextQuery, r query.ContextQueryRequest, w query.ContextQueryWorker, a query.ContextProjectionAuthority, fn func(context.Context) error) error {
	if ctx == nil || fn == nil || !w.Matches(q) {
		return query.ErrUnavailable
	}
	check := func() error {
		// This is only the admitted-identity guard. The callback owns all current
		// query/permission/processing/retention fences; do not repeat that whole
		// evaluation here or hold a connection across its transaction.
		identity := admittedWorkerIdentity{ledger: s.workers.queries.ledger, root: s.workers.queries.root, profile: s.workers.profile}
		return identity.withCurrent(ctx, value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: q.ID}, q.WorkerID, func(call context.Context, tx *custodydb.Queries, checked admittedWorkerCheck, now time.Time) error {
			c, e := projectionCredential(call, tx, q, checked.worker)
			if e != nil || !c.Ready || projectionIdentityWorker(q, c.Enrollment, c.Peer) != w || !c.Peer.Valid(now) || !q.Current(a, now) || !r.Valid(now) || call.Err() != nil {
				return query.ErrUnavailable
			}
			return nil
		})
	}
	if e := check(); e != nil {
		return e
	}
	if e := fn(ctx); e != nil {
		return e
	}
	return check()
}
