package postgres

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WorkerRouting is a read facet for a hub installation and permission root. It
// resolves the cluster/profile from immutable admitted SQL state. It exposes no
// dispatch, enrollment, locator claim, configuration acceptance or audit writes.
type WorkerRouting struct {
	ledger             *Ledger
	root, installation string
}

var _ evidence.WorkerEnrollmentBindings = (*WorkerRouting)(nil)
var _ evidence.AcquisitionEnrollmentBindings = (*WorkerRouting)(nil)
var _ evidence.WorkerOwnerLookup = (*WorkerRouting)(nil)

func NewWorkerRouting(ctx context.Context, pool *pgxpool.Pool, root, installation string) (*WorkerRouting, error) {
	if ctx == nil || ctx.Err() != nil || !value.UUID(root) || !value.UUID(installation) {
		return nil, artifact.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &WorkerRouting{l, root, installation}, nil
}

func (s *WorkerRouting) ReadDownloadWorkerEnrollment(ctx context.Context, session, worker string) (value.DownloadWorkerIdentity, error) {
	if s == nil || !value.UUID(worker) {
		return value.DownloadWorkerIdentity{}, artifact.ErrInvalid
	}
	o, err := readWorkerIdentity(ctx, s.ledger, s.root, s.installation, nil, session)
	if err != nil {
		return value.DownloadWorkerIdentity{}, err
	}
	if o.Worker.Intent.ID != worker {
		return value.DownloadWorkerIdentity{}, artifact.ErrInvalid
	}
	return o, nil
}

// ReadAcquisitionEnrollment chooses the profile from admitted state, never from
// a worker-provided endpoint or a human request. This is identity observation;
// native operations and key grants still require their own current authority.
func (s *WorkerRouting) ReadAcquisitionEnrollment(ctx context.Context, parent value.AcquisitionParent, worker string) (value.AcquisitionWorkerIdentity, error) {
	var out value.AcquisitionWorkerIdentity
	if s == nil || ctx == nil || ctx.Err() != nil || !parent.Valid() || !value.UUID(worker) {
		return out, artifact.ErrInvalid
	}
	if parent.Purpose == value.AcquisitionDownload {
		o, err := s.ReadDownloadWorkerEnrollment(ctx, parent.ID, worker)
		if err != nil {
			return out, err
		}
		return o.Acquisition(), nil
	}
	started := time.Now().UTC()
	ctx, cancel := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer cancel()
	q := custodydb.New(s.ledger.pool)
	row, err := q.ReadAcquisitionQuery(ctx, custodydb.ReadAcquisitionQueryParams{ID: id(parent.ID), RootID: id(s.root)})
	if err != nil {
		return out, err
	}
	query, err := queryFromRow(row)
	if err != nil || row.Uncertain || query.WorkerID != worker || query.Plan.InstallationID != s.installation {
		return out, artifact.ErrDownloadUnavailable
	}
	stored, err := q.ReadQueryAcquisitionWorker(ctx, custodydb.ReadQueryAcquisitionWorkerParams{QueryID: id(parent.ID), RootID: id(s.root)})
	if err != nil {
		return out, err
	}
	state, err := projectionWorkerState(stored, query)
	if err != nil || !state.Audited || !state.Claimed || !state.Worker.Valid() {
		return out, artifact.ErrDownloadUnavailable
	}
	profile := state.Worker.Intent.Profile
	configuration := &WorkerConfigurations{s.ledger, s.installation, profile.ClusterID, profile.NamespaceUID, profile.Configuration.UID}
	until, err := configuration.CurrentWorkerConfiguration(ctx, profile)
	if err != nil {
		return out, err
	}
	// As with the native-download observation, no outer transaction is held
	// during the configuration check. Reread the exact parent and worker after
	// that possible wait; enrollment effects acquire their own ordered locks.
	currentQuery, err := q.ReadAcquisitionQuery(ctx, custodydb.ReadAcquisitionQueryParams{ID: id(parent.ID), RootID: id(s.root)})
	if err != nil {
		return out, err
	}
	current, err := queryFromRow(currentQuery)
	if err != nil || currentQuery.Uncertain || !current.Equal(query) {
		return out, artifact.ErrDownloadUnavailable
	}
	currentRow, err := q.ReadQueryAcquisitionWorker(ctx, custodydb.ReadQueryAcquisitionWorkerParams{QueryID: id(parent.ID), RootID: id(s.root)})
	if err != nil {
		return out, err
	}
	currentState, err := projectionWorkerState(currentRow, query)
	if err != nil || !currentState.Audited || !currentState.Claimed || currentState.Worker != state.Worker || currentRow.TerminationJson != nil || currentRow.RetiredProofJson != nil {
		return out, artifact.ErrDownloadUnavailable
	}
	trust, err := q.ReadFleetTrust(ctx, id(s.installation))
	if err != nil {
		return out, err
	}
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return out, err
	}
	recovery, err := recoveryState(trust, started, now.Time)
	if err != nil || recovery.InstallationID != s.installation || recovery.IssuerEpoch != query.RecoveryIssuerEpoch {
		return out, artifact.ErrDownloadUnavailable
	}
	deadline, _ := ctx.Deadline()
	until = identity.Earlier(until, identity.Earlier(recovery.FreshUntil, deadline))
	until = identity.Earlier(until, identity.Earlier(query.Deadline, identity.Earlier(query.CredentialUntil, state.Worker.Intent.RunUntil)))
	out = value.AcquisitionWorkerIdentity{Worker: state.Worker, ObservedAt: started, FreshUntil: until}
	if ctx.Err() != nil || !out.Valid(now.Time) || !out.Valid(time.Now()) {
		return value.AcquisitionWorkerIdentity{}, artifact.ErrDownloadExpired
	}
	return out, nil
}

func (s *WorkerRouting) ReadWorkerOwner(ctx context.Context, session, worker string) (value.WorkerOwnerLease, error) {
	if s == nil {
		return value.WorkerOwnerLease{}, artifact.ErrInvalid
	}
	return readWorkerOwner(ctx, s.ledger, s.root, s.installation, session, worker)
}

func readWorkerOwner(ctx context.Context, l *Ledger, root, installation, session, workerID string) (value.WorkerOwnerLease, error) {
	var out value.WorkerOwnerLease
	if ctx == nil || ctx.Err() != nil || !value.UUID(session) || !value.UUID(workerID) {
		return out, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	r, err := custodydb.New(l.pool).ReadWorkerOwner(ctx, custodydb.ReadWorkerOwnerParams{ID: id(workerID), SessionID: id(session), RootID: id(root), InstallationID: id(installation)})
	if err != nil {
		return out, artifact.ErrDownloadUnavailable
	}
	worker, err := currentAuditedWorker(r.DownloadWorker)
	if err != nil || worker.Intent.ID != workerID || worker.Intent.SessionID != session || worker.Binding.InstallationID != installation {
		return out, artifact.ErrDownloadUnavailable
	}
	out = workerOwnerLease(r.DownloadWorkerOwner, installation, session)
	if !out.Valid(time.Now()) || ctx.Err() != nil {
		return value.WorkerOwnerLease{}, artifact.ErrDownloadExpired
	}
	return out, nil
}

// expected is set only for the original profile-scoped effect adapter. The hub
// reader instead uses the exact stored profile and independently fixed installation.
func readWorkerIdentity(ctx context.Context, l *Ledger, root, installation string, expected *value.DownloadWorkerProfile, session string) (value.DownloadWorkerIdentity, error) {
	var out value.DownloadWorkerIdentity
	if ctx == nil || ctx.Err() != nil || !value.UUID(session) {
		return out, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	q := custodydb.New(l.pool)
	start, err := q.CurrentTime(ctx)
	if err != nil {
		return out, err
	}
	r, err := q.LatestDownloadWorker(ctx, custodydb.LatestDownloadWorkerParams{SessionID: id(session), RootID: id(root)})
	if err != nil {
		return out, err
	}
	w, err := currentAuditedWorker(r)
	if err != nil {
		return out, err
	}
	p := w.Intent.Profile
	if p.InstallationID != installation || expected != nil && p != *expected || r.AuditReceiptJson == nil || !r.ClaimedAt.Valid || r.TerminationJson != nil || r.RetiredProofJson != nil {
		return out, artifact.ErrDownloadUnavailable
	}
	configuration := &WorkerConfigurations{l, installation, p.ClusterID, p.NamespaceUID, p.Configuration.UID}
	until, err := configuration.CurrentWorkerConfiguration(ctx, p)
	if err != nil {
		return out, err
	}
	// Configuration/recovery checks can wait on locks. Recheck the original
	// worker and parent after that wait, without refreshing the original start.
	current, err := q.LatestDownloadWorker(ctx, custodydb.LatestDownloadWorkerParams{SessionID: r.SessionID, RootID: r.RootID})
	if err != nil {
		return out, err
	}
	currentWorker, err := currentAuditedWorker(current)
	if err != nil || currentWorker != w || !bytes.Equal(current.AuditReceiptJson, r.AuditReceiptJson) {
		return out, artifact.ErrDownloadUnavailable
	}
	parent, err := q.ReadDownloadSession(ctx, custodydb.ReadDownloadSessionParams{ID: r.SessionID, RootID: r.RootID})
	if err != nil {
		return out, err
	}
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return out, err
	}
	if current.ID != r.ID || current.TerminationJson != nil || current.RetiredProofJson != nil || !now.Time.Before(w.Intent.RunUntil) || !now.Time.Before(parent.Deadline.Time) || artifact.DownloadState(parent.State).Terminal() || !identity.Fresh(start.Time, start.Time.Add(5*time.Second), now.Time, 5*time.Second) {
		return out, artifact.ErrDownloadExpired
	}
	deadline, _ := ctx.Deadline()
	until = identity.Earlier(until, identity.Earlier(start.Time.Add(5*time.Second), w.Intent.RunUntil))
	until = identity.Earlier(until, identity.Earlier(parent.Deadline.Time, deadline))
	out = value.DownloadWorkerIdentity{Worker: w, ObservedAt: start.Time, FreshUntil: until}
	if ctx.Err() != nil || !out.Valid(time.Now()) {
		return value.DownloadWorkerIdentity{}, artifact.ErrDownloadExpired
	}
	return out, nil
}
