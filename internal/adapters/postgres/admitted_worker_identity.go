package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// admittedWorkerIdentity guards identity effects, not evidence access. Parent
// admission and every native/key operation retain their separate authority.
type admittedWorkerIdentity struct {
	ledger  *Ledger
	root    string
	profile value.DownloadWorkerProfile
}

type admittedWorkerCheck struct {
	worker        value.AcquisitionWorker
	download      value.DownloadWorker
	recoveryEpoch string
	observedAt    time.Time
	freshUntil    time.Time
}

func newAdmittedWorkerIdentity(ctx context.Context, pool *pgxpool.Pool, root string, profile value.DownloadWorkerProfile) (*admittedWorkerIdentity, error) {
	if !value.UUID(root) || !profile.Valid() {
		return nil, artifact.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &admittedWorkerIdentity{ledger: l, root: root, profile: profile}, nil
}

func (s *admittedWorkerIdentity) withCurrent(ctx context.Context, parent value.AcquisitionParent, worker string, effect func(context.Context, *custodydb.Queries, admittedWorkerCheck, time.Time) error) error {
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !parent.Valid() || !value.UUID(worker) || effect == nil {
		return artifact.ErrInvalid
	}
	started := time.Now().UTC()
	call, cancel := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer cancel()
	return s.ledger.transaction(call, func(tx *custodydb.Queries) error {
		return s.current(call, tx, parent, worker, started, effect)
	})
}

// The caller owns one transaction. Preserve recovery -> parent -> accepted
// configuration -> worker lock order; never acquire a second pool connection.
func (s *admittedWorkerIdentity) current(ctx context.Context, tx *custodydb.Queries, parent value.AcquisitionParent, workerID string, started time.Time, effect func(context.Context, *custodydb.Queries, admittedWorkerCheck, time.Time) error) error {
	trust, err := tx.ShareFleetTrust(ctx, id(s.profile.InstallationID))
	if err != nil {
		return err
	}
	var download artifact.DownloadSession
	var projection query.ContextQuery
	var parentUntil time.Time
	switch parent.Purpose {
	case value.AcquisitionDownload:
		row, e := tx.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(parent.ID), RootID: id(s.root)})
		if e != nil {
			return e
		}
		download, err = decodeDownload(row)
		if err != nil || download.ID != parent.ID || download.State.Terminal() {
			return artifact.ErrDownloadExpired
		}
		parentUntil = download.Deadline
	case value.AcquisitionProjection:
		row, e := tx.LockContextQuery(ctx, custodydb.LockContextQueryParams{ID: id(parent.ID), RootID: id(s.root)})
		if e != nil {
			return e
		}
		projection, err = queryFromRow(row)
		if err != nil || row.Uncertain || projection.ID != parent.ID || projection.WorkerID != workerID || projection.Plan.InstallationID != s.profile.InstallationID || projection.RecoveryIssuerEpoch != uid(trust.IssuerEpoch) {
			return artifact.ErrDownloadExpired
		}
		parentUntil = identity.Earlier(projection.Deadline, projection.CredentialUntil)
	default:
		return artifact.ErrInvalid
	}
	configurationUntil, err := currentWorkerConfiguration(ctx, tx, s.profile, uid(trust.IssuerEpoch))
	if err != nil {
		return err
	}
	row, err := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(workerID), RootID: id(s.root)})
	if err != nil {
		return err
	}
	if row.TerminationJson != nil || row.RetiredProofJson != nil {
		return artifact.ErrDownloadExpired
	}
	checked := admittedWorkerCheck{observedAt: started, recoveryEpoch: uid(trust.IssuerEpoch)}
	switch parent.Purpose {
	case value.AcquisitionDownload:
		checked.download, err = currentAuditedWorker(row)
		if err != nil || checked.download.Intent.SessionID != parent.ID || checked.download.Intent.Authority.Scope != download.Scope || checked.download.Intent.Authority.Environment.RecoveryEpoch != checked.recoveryEpoch {
			return artifact.ErrDownloadExpired
		}
		// The old authority is immutable audit provenance. Only its admitted
		// scope and recovery epoch are compared, never restamped or reused.
		checked.worker = checked.download.Acquisition()
		latest, e := tx.LatestDownloadWorker(ctx, custodydb.LatestDownloadWorkerParams{SessionID: id(parent.ID), RootID: id(s.root)})
		if e != nil || latest.ID != row.ID {
			return artifact.ErrDownloadExpired
		}
	case value.AcquisitionProjection:
		state, e := projectionWorkerState(row, projection)
		if e != nil || !state.Audited || !state.Claimed || !state.Worker.Valid() {
			return artifact.ErrDownloadExpired
		}
		checked.worker = state.Worker
	}
	if checked.worker.Intent.ID != workerID || checked.worker.Intent.Parent != parent || checked.worker.Intent.Profile != s.profile {
		return artifact.ErrDownloadExpired
	}
	checked.freshUntil = identity.Earlier(started.Add(5*time.Second), identity.Earlier(parentUntil, checked.worker.Intent.RunUntil))
	checked.freshUntil = identity.Earlier(checked.freshUntil, identity.Earlier(configurationUntil, trust.FreshUntil.Time))
	if until, ok := ctx.Deadline(); ok {
		checked.freshUntil = identity.Earlier(checked.freshUntil, until)
	}
	check := func() (time.Time, error) {
		n, e := tx.CurrentTime(ctx)
		if e != nil {
			return time.Time{}, e
		}
		if ctx.Err() != nil || !identity.Fresh(started, checked.freshUntil, n.Time, 5*time.Second) || uid(trust.InstallationID) != s.profile.InstallationID {
			return n.Time, artifact.ErrDownloadExpired
		}
		if _, e = recoveryState(trust, started, n.Time); e != nil {
			return n.Time, e
		}
		return n.Time, nil
	}
	now, err := check()
	if err != nil {
		return err
	}
	if err = effect(ctx, tx, checked, now); err != nil {
		return err
	}
	_, err = check()
	return err
}
