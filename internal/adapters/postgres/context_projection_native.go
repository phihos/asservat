package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

// ProjectionNativeOperations composes the existing query ledger with the shared
// worker registry. Every read/key operation consumes actual ReadApproved and
// processing/recovery/retention/permission fences; no download row is created.
type ProjectionNativeOperations struct{ queries *ContextQueries }

func NewProjectionNativeOperations(q *ContextQueries) (*ProjectionNativeOperations, error) {
	if q == nil || q.ledger == nil || q.recovery == nil {
		return nil, query.ErrUnavailable
	}
	return &ProjectionNativeOperations{queries: q}, nil
}

var _ evidence.ProjectionNativeReader = (*ProjectionNativeOperations)(nil)

func (s *ProjectionNativeOperations) query(ctx context.Context, idText string) (query.ContextQuery, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !value.UUID(idText) {
		return query.ContextQuery{}, query.ErrUnavailable
	}
	row, e := custodydb.New(s.queries.ledger.pool).ReadAcquisitionQuery(ctx, custodydb.ReadAcquisitionQueryParams{ID: id(idText), RootID: id(s.queries.root)})
	if e != nil {
		return query.ContextQuery{}, query.ErrUnavailable
	}
	return queryFromRow(row)
}

// Identity-only enrollment and native lookup share the same admitted-parent
// guard. Current query effects below retain their independent evidence fences.
func (s *ProjectionNativeOperations) ReadAcquisitionEnrollment(ctx context.Context, parent value.AcquisitionParent, worker string) (value.AcquisitionWorkerIdentity, error) {
	if s == nil || s.queries == nil || parent.Purpose != value.AcquisitionProjection {
		return value.AcquisitionWorkerIdentity{}, query.ErrUnavailable
	}
	routing := &WorkerRouting{ledger: s.queries.ledger, root: s.queries.root, installation: s.queries.recovery.installation}
	return routing.ReadAcquisitionEnrollment(ctx, parent, worker)
}
func (s *ProjectionNativeOperations) ReadProjectionWorkerCertificate(ctx context.Context, queryID, worker string, leaf []byte) (value.WorkerCertificate, error) {
	var zero value.WorkerCertificate
	if len(leaf) < 1 || len(leaf) > 16<<10 {
		return zero, query.ErrUnavailable
	}
	observed, e := s.ReadAcquisitionEnrollment(ctx, value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: queryID}, worker)
	if e != nil {
		return zero, e
	}
	call, cancel := context.WithDeadline(ctx, observed.FreshUntil)
	defer cancel()
	tx := custodydb.New(s.queries.ledger.pool)
	digest := sha256.Sum256(leaf)
	row, e := tx.ReadActiveWorkerCertificate(call, custodydb.ReadActiveWorkerCertificateParams{WorkerID: id(worker), CertificateSha256: digest[:]})
	if e != nil {
		return zero, e
	}
	attempt, e := decodeAcquisitionCertificateAttempt(row)
	if e != nil || attempt.Enrollment.Worker != observed.Worker {
		return zero, query.ErrUnavailable
	}
	cert, e := decodeAcquisitionCertificate(row, attempt)
	if e != nil || !bytes.Equal(leaf, cert.DER) {
		return zero, query.ErrUnavailable
	}
	if e = activeAcquisitionCertificate(call, tx, observed.Worker, cert.Peer); e != nil || !observed.Valid(time.Now()) || call.Err() != nil {
		return zero, query.ErrUnavailable
	}
	return cert, nil
}
func projectionNativeRecord(row custodydb.ContextQueryBatch, q query.ContextQuery) (query.ContextReadBatch, value.NativeOperation, query.ContextProjectionAuthority, error) {
	b, e := queryBatch(row, q)
	var o value.NativeOperation
	var a query.ContextProjectionAuthority
	if e != nil || queryDecode(row.NativeOperation, 16384, &o) != nil || queryDecode(row.NativeAuthority, 65536, &a) != nil || !o.Valid() || o.Kind != value.NativeProjection || o.Reference.Parent() != (value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: q.ID}) || o.Reference.InstallationID != q.Plan.InstallationID || o.Reference.WorkerID != q.WorkerID || o.Reference.OperationID != b.ID || o.Reference.Fence != b.Generation || o.ParentID != b.ID || o.Generation != b.Generation || o.SourceVersion != q.Scope.Version || o.Path != a.Environment.Path.AcquisitionPath() || !o.Processing.Equal(a.Environment.Processing) || o.Until.After(b.Until) || o.Until.After(a.ValidUntil) || o.HubProcessEpoch != b.Request.HubProcessEpoch {
		return b, o, a, query.ErrUnavailable
	}
	return b, o, a, nil
}
func projectionNativeWorker(ctx context.Context, tx *custodydb.Queries, q query.ContextQuery, b query.ContextReadBatch, o value.NativeOperation, peer value.KeyPeer) (value.AcquisitionEnrollment, error) {
	row, e := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(q.WorkerID), RootID: id(q.Scope.RootID)})
	if e != nil || row.TerminationJson != nil || row.RetiredProofJson != nil {
		return value.AcquisitionEnrollment{}, query.ErrUnavailable
	}
	state, e := projectionWorkerState(row, q)
	if e != nil || !state.Audited || !state.Worker.Valid() {
		return value.AcquisitionEnrollment{}, query.ErrUnavailable
	}
	if _, e = currentWorkerConfiguration(ctx, tx, state.Worker.Intent.Profile, q.RecoveryIssuerEpoch); e != nil {
		return value.AcquisitionEnrollment{}, e
	}
	en, e := currentAuditedAcquisitionEnrollment(ctx, tx, state.Worker)
	if e != nil || q.WorkerID != b.Worker.ProcessEpoch || en.PublicKeyDigest != o.WorkerPublicKey || peer.PeerID != state.Worker.Binding.PodUID || peer.PeerID != o.WorkerPodUID || peer.PeerID != b.Worker.PeerID || peer.Certificate != b.Worker.Certificate || peer.NotAfter.After(q.CredentialUntil) {
		return value.AcquisitionEnrollment{}, query.ErrUnavailable
	}
	if e = activeAcquisitionCertificate(ctx, tx, state.Worker, peer); e != nil {
		return value.AcquisitionEnrollment{}, e
	}
	if e = queryWorker(ctx, tx, q, b.Worker); e != nil {
		return value.AcquisitionEnrollment{}, e
	}
	return en, nil
}

func (s *ProjectionNativeOperations) ObserveProjectionNativeOperation(ctx context.Context, ref value.NativeReference, peer value.KeyPeer) (value.NativeLease, error) {
	var zero value.NativeLease
	if s == nil || ctx == nil || ctx.Err() != nil || !ref.Valid() || ref.Parent().Purpose != value.AcquisitionProjection || !peer.Valid(time.Now()) || peer.Role != "acquisition" || peer.InstallationID != ref.InstallationID {
		return zero, query.ErrUnavailable
	}
	q, e := s.query(ctx, ref.QueryID)
	if e != nil {
		return zero, e
	}
	initial, e := custodydb.New(s.queries.ledger.pool).ReadProjectionNativeBatch(ctx, custodydb.ReadProjectionNativeBatchParams{ID: id(q.ID), RootID: id(s.queries.root), WorkerID: id(q.WorkerID)})
	if e != nil {
		return zero, query.ErrUnavailable
	}
	b, o, a, e := projectionNativeRecord(initial, q)
	if e != nil || o.Reference != ref || !o.CurrentValid(time.Now()) {
		return zero, query.ErrUnavailable
	}
	var out value.NativeLease
	e = s.queries.current(ctx, q, b.Request, a, func(ctx context.Context, tx *custodydb.Queries, _ custodydb.ContextQueryBacking, _ custodydb.ContextQueryAllocation) error {
		qr, e := queryExact(ctx, tx, q)
		if e != nil || qr.Uncertain || uid(qr.ActiveBatch) != b.ID {
			return query.ErrUnavailable
		}
		if _, e = projectionNativeWorker(ctx, tx, q, b, o, peer); e != nil {
			return e
		}
		row, e := tx.LockContextQueryBatch(ctx, custodydb.LockContextQueryBatchParams{ID: id(b.ID), QueryID: id(q.ID)})
		if e != nil || row.Closed || row.NativeClosed || uid(row.ClaimID) != b.ID || !bytes.Equal(row.NativeOperation, initial.NativeOperation) || !bytes.Equal(row.NativeAuthority, initial.NativeAuthority) {
			return query.ErrUnavailable
		}
		now, e := tx.CurrentTime(ctx)
		if e != nil {
			return e
		}
		until := identity.Earlier(o.Until, peer.NotAfter)
		out = value.NativeLease{Operation: o, Certificate: peer.Certificate, Sequence: 1, ObservedAt: o.StartedAt, Until: until}
		if !peer.Valid(now.Time) || !out.Valid(now.Time) || !b.Current(q, a, now.Time) {
			return query.ErrUnavailable
		}
		return nil
	})
	if e != nil || ctx.Err() != nil || !out.Valid(time.Now()) {
		return zero, query.ErrUnavailable
	}
	return out, nil
}
func (s *ProjectionNativeOperations) LocateProjectionNativeOperation(ctx context.Context, installation, queryID, worker string, peer value.KeyPeer) (value.NativeLease, error) {
	var zero value.NativeLease
	if s == nil || ctx == nil || installation != s.queries.recovery.installation || peer.InstallationID != installation {
		return zero, query.ErrUnavailable
	}
	observed, e := s.ReadAcquisitionEnrollment(ctx, value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: queryID}, worker)
	if e != nil || peer.PeerID != observed.Worker.Binding.PodUID || !peer.Valid(time.Now()) {
		return zero, query.ErrUnavailable
	}
	tx := custodydb.New(s.queries.ledger.pool)
	if e = activeAcquisitionCertificate(ctx, tx, observed.Worker, peer); e != nil {
		return zero, e
	}
	row, e := tx.ReadProjectionNativeBatch(ctx, custodydb.ReadProjectionNativeBatchParams{ID: id(queryID), RootID: id(s.queries.root), WorkerID: id(worker)})
	if errors.Is(e, pgx.ErrNoRows) || e == nil && (row.NativeOperation == nil || row.NativeClosed) {
		if ctx.Err() != nil || !observed.Valid(time.Now()) {
			return zero, query.ErrUnavailable
		}
		return zero, &evidence.NativeNoOperation{Worker: observed}
	}
	if e != nil {
		return zero, e
	}
	q, e := s.query(ctx, queryID)
	if e != nil {
		return zero, e
	}
	_, o, _, e := projectionNativeRecord(row, q)
	if e != nil {
		return zero, e
	}
	return s.ObserveProjectionNativeOperation(ctx, o.Reference, peer)
}

func (s *ProjectionNativeOperations) ClaimProjectionNative(ctx context.Context, start query.ContextReadStart, a query.ContextProjectionAuthority, o value.NativeOperation) error {
	b := start.Batch
	if s == nil || !start.Fresh || start.ClaimID != b.ID || !o.CurrentValid(time.Now()) || o.Kind != value.NativeProjection || o.Reference.QueryID != b.QueryID || o.Reference.WorkerID != b.Worker.WorkerID || o.Reference.OperationID != b.ID || o.Reference.Fence != b.Generation || o.ParentID != b.ID || o.Generation != b.Generation || o.HubProcessEpoch != b.Request.HubProcessEpoch || o.StartedAt.Before(b.StartedAt) || o.Until.After(b.Until) || o.Until.After(a.ValidUntil) || o.Path != a.Environment.Path.AcquisitionPath() || !o.Processing.Equal(a.Environment.Processing) {
		return query.ErrUnavailable
	}
	return s.queries.withBatch(ctx, b, a, func(ctx context.Context, tx *custodydb.Queries, q query.ContextQuery, row custodydb.ContextQueryBatch) error {
		if uid(row.ClaimID) != b.ID || row.NativeOperation != nil || row.NativeClosed {
			return query.ErrUnavailable
		}
		worker, e := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(q.WorkerID), RootID: id(q.Scope.RootID)})
		if e != nil {
			return e
		}
		state, e := projectionWorkerState(worker, q)
		if e != nil || !state.Worker.Valid() {
			return query.ErrUnavailable
		}
		c, e := projectionCredential(ctx, tx, q, state.Worker)
		if e != nil || !c.Ready || projectionIdentityWorker(q, c.Enrollment, c.Peer) != b.Worker {
			return query.ErrUnavailable
		}
		if _, e = projectionNativeWorker(ctx, tx, q, b, o, c.Peer); e != nil {
			return e
		}
		encoded, e := queryJSON(o)
		if e != nil {
			return e
		}
		authority, e := queryJSON(a)
		if e != nil {
			return e
		}
		affected, e := tx.OpenProjectionNativeBatch(ctx, custodydb.OpenProjectionNativeBatchParams{ID: id(b.ID), QueryID: id(q.ID), NativeOperation: encoded, NativeAuthority: authority})
		if e != nil || affected != 1 {
			return query.ErrUnavailable
		}
		return nil
	})
}

// The native protocol invokes this only after the actual worker has discarded
// its DTO and acknowledged the exact operation. Public result/audit/flush still
// owns the batch; this private closure never releases that public obligation.
func (s *ProjectionNativeOperations) CompleteProjectionNative(ctx context.Context, l value.NativeLease) error {
	if s == nil || ctx == nil || !l.Valid(time.Now()) || l.Operation.Kind != value.NativeProjection {
		return query.ErrUnavailable
	}
	q, e := s.query(ctx, l.Operation.Reference.QueryID)
	if e != nil {
		return e
	}
	row, e := custodydb.New(s.queries.ledger.pool).ReadProjectionNativeBatch(ctx, custodydb.ReadProjectionNativeBatchParams{ID: id(q.ID), RootID: id(s.queries.root), WorkerID: id(q.WorkerID)})
	if e != nil {
		return e
	}
	b, o, a, e := projectionNativeRecord(row, q)
	if e != nil || !o.Equal(l.Operation) || l.Certificate != b.Worker.Certificate || l.Sequence != 1 {
		return query.ErrUnavailable
	}
	return s.queries.withBatch(ctx, b, a, func(ctx context.Context, tx *custodydb.Queries, q query.ContextQuery, row custodydb.ContextQueryBatch) error {
		_, current, original, e := projectionNativeRecord(row, q)
		if e != nil || !current.Equal(o) || !sameAuditJSON(original, a) || row.NativeClosed || uid(row.ClaimID) != b.ID {
			return query.ErrUnavailable
		}
		raw, e := queryJSON(o)
		if e != nil {
			return e
		}
		n, e := tx.CloseProjectionNativeBatch(ctx, custodydb.CloseProjectionNativeBatchParams{ID: id(b.ID), QueryID: id(q.ID), NativeOperation: raw})
		if e != nil || n != 1 {
			return query.ErrUnavailable
		}
		return nil
	})
}

func (s *ProjectionNativeOperations) ReadProjectionSource(ctx context.Context, q query.ContextQuery, a query.ContextProjectionAuthority, r query.ContextQueryRequest) (evidence.NativeContextSource, error) {
	var out evidence.NativeContextSource
	e := s.queries.current(ctx, q, r, a, func(ctx context.Context, tx *custodydb.Queries, _ custodydb.ContextQueryBacking, _ custodydb.ContextQueryAllocation) error {
		row, e := tx.ReadPublishedContext(ctx, custodydb.ReadPublishedContextParams{ArtifactID: id(q.Scope.ArtifactID), RootID: id(q.Scope.RootID)})
		if e != nil {
			return e
		}
		expected, e := currentPublishedContext(row)
		if e != nil {
			return e
		}
		attempt, e := tx.ReadAttempt(ctx, row.ContextCapture.AttemptID)
		if e != nil {
			return e
		}
		stored, e := record(ctx, tx, attempt, expected.Registration.StoreID)
		if e != nil {
			return e
		}
		if stored.State != artifact.StoredUnpublished || !stored.Registration.Equal(expected.Registration) || stored.Copies.Validate(expected.Registration) != nil || !bytes.Equal(attempt.CopiesDigest, row.ContextVerification.CopiesDigest) {
			return query.ErrUnavailable
		}
		out = evidence.NativeContextSource{Expectation: expected, Copies: stored.Copies}
		if !evidence.ProjectionSourceMatches(out, q, a) {
			return query.ErrUnavailable
		}
		return nil
	})
	if e != nil {
		return evidence.NativeContextSource{}, e
	}
	return out, nil
}
