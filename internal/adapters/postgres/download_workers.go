package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type DownloadWorkers struct {
	downloads *Downloads
	profile   value.DownloadWorkerProfile
}

var _ evidence.DownloadWorkerLedger = (*DownloadWorkers)(nil)
var _ evidence.DownloadWorkerBindings = (*DownloadWorkers)(nil)
var _ auditapp.DownloadWorkerAcknowledgements = (*DownloadWorkers)(nil)

func NewDownloadWorkers(ctx context.Context, pool *pgxpool.Pool, root string, profile value.DownloadWorkerProfile, guards DownloadTransactionGuards) (*DownloadWorkers, error) {
	if !profile.Valid() || guards.Recovery == nil || guards.Recovery.installation != profile.InstallationID {
		return nil, artifact.ErrInvalid
	}
	d, e := NewDownloads(ctx, pool, root, guards)
	if e != nil {
		return nil, e
	}
	return &DownloadWorkers{d, profile}, nil
}
func decodeWorkerIntent(r custodydb.DownloadWorker) (value.DownloadWorkerIntent, error) {
	var i value.DownloadWorkerIntent
	if json.Unmarshal(r.IntentJson, &i) != nil || !i.Valid() || i.ID != uid(r.ID) || i.SessionID != uid(r.SessionID) || i.Generation != r.Generation || i.Authority.Scope.RootID != uid(r.RootID) || i.Profile.InstallationID != uid(r.InstallationID) || !i.RunUntil.Equal(r.RunUntil.Time) {
		return i, artifact.ErrIntegrity
	}
	return i, nil
}
func decodeWorker(r custodydb.DownloadWorker) (value.DownloadWorker, error) {
	i, e := decodeWorkerIntent(r)
	w := value.DownloadWorker{Intent: i}
	if e != nil || json.Unmarshal(r.JobJson, &w.Job) != nil || json.Unmarshal(r.BindingJson, &w.Binding) != nil || !w.Valid() {
		return w, artifact.ErrIntegrity
	}
	return w, nil
}
func workerMatches(r custodydb.DownloadWorker, i value.DownloadWorkerIntent) bool {
	b, e := json.Marshal(i)
	return e == nil && bytes.Equal(r.IntentJson, b)
}

func (s *DownloadWorkers) withSession(ctx context.Context, session string, a artifact.DownloadAuthority, f func(*custodydb.Queries, artifact.DownloadSession, time.Time) error) error {
	if s == nil || ctx == nil || !value.UUID(session) || a.Scope.RootID != s.downloads.root {
		return artifact.ErrInvalid
	}
	d := s.downloads
	top, e := d.retention.observe(ctx, a.Scope.ClusterID)
	if e != nil {
		return e
	}
	return d.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		recovery, e := d.recovery.lock(ctx, q, d.root, a.Environment.Recovery())
		if e != nil {
			return e
		}
		root, e := q.LockPermissionStream(ctx, id(d.root))
		if e != nil {
			return e
		}
		row, e := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(session), RootID: id(d.root)})
		if e != nil {
			return e
		}
		parent, e := loadDownload(ctx, q, row)
		if e != nil {
			return e
		}
		check := func() (time.Time, error) {
			if e := d.downloadFence(ctx, q, root, a, top, recovery); e != nil {
				return time.Time{}, e
			}
			if a.Environment.Path.AcquisitionClusterID != s.profile.ClusterID || a.Environment.Path.WorkerConfiguration != s.profile.Configuration {
				return time.Time{}, artifact.ErrDownloadUnavailable
			}
			if _, e := currentWorkerConfiguration(ctx, q, s.profile, a.Environment.RecoveryEpoch); e != nil {
				return time.Time{}, e
			}
			n, e := q.CurrentTime(ctx)
			if e != nil {
				return time.Time{}, e
			}
			if !a.Valid(n.Time) || parent.Scope != a.Scope || parent.State.Terminal() || !n.Time.Before(parent.Deadline) {
				return n.Time, artifact.ErrDownloadExpired
			}
			return n.Time, nil
		}
		now, e := check()
		if e != nil {
			return e
		}
		if e = f(q, parent, now); e != nil {
			return e
		}
		_, e = check()
		return e
	})
}
func (s *DownloadWorkers) ReserveDownloadWorker(ctx context.Context, session, attempt string, a artifact.DownloadAuthority, p value.DownloadWorkerProfile) (value.DownloadWorkerIntent, error) {
	var out value.DownloadWorkerIntent
	if s == nil || p != s.profile || !value.UUID(attempt) {
		return out, artifact.ErrInvalid
	}
	e := s.withSession(ctx, session, a, func(q *custodydb.Queries, parent artifact.DownloadSession, now time.Time) error {
		generation := int64(1)
		old, e := q.LatestDownloadWorker(ctx, custodydb.LatestDownloadWorkerParams{SessionID: id(session), RootID: id(s.downloads.root)})
		if e == nil {
			i, err := decodeWorkerIntent(old)
			if err != nil {
				return err
			}
			if old.RetiredProofJson == nil {
				if i.Profile != p || i.Authority.Scope != a.Scope || !now.Before(i.RunUntil) {
					return artifact.ErrDownloadExpired
				}
				out = i
				return nil
			}
			if i.ID == attempt {
				return artifact.ErrDownloadConflict
			}
			generation = i.Generation + 1
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if generation > parent.RequestLimit {
			return artifact.ErrDownloadCapacity
		}
		counts, e := q.AcquisitionWorkerCapacity(ctx, custodydb.AcquisitionWorkerCapacityParams{InstallationID: id(p.InstallationID), ClusterID: id(a.Scope.ClusterID), NamespaceUid: a.Scope.NamespaceUID, WorkloadUid: a.Scope.WorkloadUID, PrincipalKey: principalKey(a.Scope.Principal)})
		if e != nil {
			return e
		}
		if counts.Total >= 16 || counts.Workload >= 2 || counts.Principal >= 2 {
			return artifact.ErrDownloadCapacity
		}
		until := identity.Earlier(parent.Deadline, identity.Earlier(a.AccessUntil, now.Add(p.MaxRuntime))).UTC().Truncate(time.Microsecond)
		if until.Sub(now) < time.Second {
			return artifact.ErrDownloadExpired
		}
		out = value.DownloadWorkerIntent{ID: attempt, SessionID: session, Generation: generation, Profile: p, Authority: a, CreatedAt: now.UTC(), RunUntil: until}
		if !out.Valid() {
			return artifact.ErrInvalid
		}
		b, e := json.Marshal(out)
		if e != nil || len(b) > 65536 {
			return artifact.ErrInvalid
		}
		// Return the same timestamp representation recovered on a retry; local
		// monotonic clock/location details are not part of persisted identity.
		if json.Unmarshal(b, &out) != nil {
			return artifact.ErrInvalid
		}
		return q.InsertDownloadWorker(ctx, custodydb.InsertDownloadWorkerParams{ID: id(attempt), SessionID: id(session), RootID: id(s.downloads.root), InstallationID: id(p.InstallationID), AllocationID: id(parent.AllocationID), PrincipalKey: principalKey(a.Scope.Principal), Generation: generation, IntentJson: b, RunUntil: ts(until)})
	})
	if e != nil {
		return value.DownloadWorkerIntent{}, e
	}
	return out, nil
}

// An acknowledged immutable receipt is historical audit evidence, not a
// current authority decision. Reading it avoids repeated KMS/object work while
// polling a pending Job. ClaimDownloadWorker still repeats current fences.
func (s *DownloadWorkers) ReadDownloadWorkerIntentReceipt(ctx context.Context, i value.DownloadWorkerIntent) (audit.Receipt, bool, error) {
	var out audit.Receipt
	if s == nil || ctx == nil || !i.Valid() || i.Profile != s.profile {
		return out, false, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	q := custodydb.New(s.downloads.ledger.pool)
	r, e := q.LatestDownloadWorker(ctx, custodydb.LatestDownloadWorkerParams{SessionID: id(i.SessionID), RootID: id(s.downloads.root)})
	if e != nil {
		return out, false, e
	}
	if !workerMatches(r, i) {
		return out, false, artifact.ErrIntegrity
	}
	if r.AuditReceiptJson == nil {
		return out, false, nil
	}
	if json.Unmarshal(r.AuditReceiptJson, &out) != nil || !out.ValidDownloadWorker(i) {
		return out, false, artifact.ErrIntegrity
	}
	return out, true, nil
}
func (s *DownloadWorkers) AcknowledgeDownloadWorkerIntent(ctx context.Context, i value.DownloadWorkerIntent, r audit.Receipt) error {
	if s == nil || ctx == nil || !r.ValidDownloadWorker(i) || i.Profile != s.profile {
		return artifact.ErrInvalid
	}
	return s.downloads.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, e := q.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(i.ID), RootID: id(s.downloads.root)})
		if e != nil {
			return e
		}
		if !workerMatches(row, i) {
			return artifact.ErrIntegrity
		}
		b, _ := json.Marshal(r)
		if row.AuditReceiptJson != nil {
			if !bytes.Equal(row.AuditReceiptJson, b) {
				return artifact.ErrIntegrity
			}
			return nil
		}
		n, e := q.AuditDownloadWorker(ctx, custodydb.AuditDownloadWorkerParams{ID: row.ID, RootID: row.RootID, AuditReceiptJson: b})
		if e != nil || n != 1 {
			return artifact.ErrDownloadConflict
		}
		return nil
	})
}
func (s *DownloadWorkers) ClaimDownloadWorker(ctx context.Context, i value.DownloadWorkerIntent, a artifact.DownloadAuthority) (value.DownloadWorkerLaunch, error) {
	var out value.DownloadWorkerLaunch
	if s == nil || !i.Valid() || i.Profile != s.profile || i.Authority.Scope != a.Scope {
		return out, artifact.ErrInvalid
	}
	e := s.withSession(ctx, i.SessionID, a, func(q *custodydb.Queries, _ artifact.DownloadSession, _ time.Time) error {
		r, e := q.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(i.ID), RootID: id(s.downloads.root)})
		if e != nil {
			return e
		}
		var receipt audit.Receipt
		if !workerMatches(r, i) || r.RetiredProofJson != nil || json.Unmarshal(r.AuditReceiptJson, &receipt) != nil || !receipt.ValidDownloadWorker(i) {
			return artifact.ErrDownloadConflict
		}
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		until := identity.Earlier(i.RunUntil, a.ValidUntil)
		out = value.DownloadWorkerLaunch{Intent: i, CheckedAt: n.Time.UTC(), Until: until, MayCreate: !r.ClaimedAt.Valid}
		if !out.Valid(n.Time) {
			return artifact.ErrDownloadExpired
		}
		if out.MayCreate {
			count, e := q.ClaimDownloadWorker(ctx, custodydb.ClaimDownloadWorkerParams{ID: r.ID, RootID: r.RootID})
			if e != nil || count != 1 {
				return artifact.ErrDownloadConflict
			}
		}
		return nil
	})
	if e != nil {
		return value.DownloadWorkerLaunch{}, e
	}
	return out, nil
}
func (s *DownloadWorkers) RecordDownloadWorkerJob(ctx context.Context, i value.DownloadWorkerIntent, j value.DownloadWorkerJob) error {
	if s == nil || ctx == nil || !j.Valid(i) || i.Profile != s.profile {
		return artifact.ErrInvalid
	}
	return s.downloads.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		r, e := q.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(i.ID), RootID: id(s.downloads.root)})
		if e != nil {
			return e
		}
		if !workerMatches(r, i) || !r.ClaimedAt.Valid {
			return artifact.ErrDownloadConflict
		}
		b, _ := json.Marshal(j)
		if r.JobJson != nil {
			if !bytes.Equal(r.JobJson, b) {
				return artifact.ErrDownloadConflict
			}
			return nil
		}
		n, e := q.RecordDownloadWorkerJob(ctx, custodydb.RecordDownloadWorkerJobParams{ID: r.ID, RootID: r.RootID, JobJson: b})
		if e != nil || n != 1 {
			return artifact.ErrDownloadConflict
		}
		return nil
	})
}
func (s *DownloadWorkers) BindDownloadWorker(ctx context.Context, w value.DownloadWorker, a artifact.DownloadAuthority) error {
	if s == nil || !w.Valid() || w.Intent.Profile != s.profile || w.Intent.Authority.Scope != a.Scope {
		return artifact.ErrInvalid
	}
	return s.withSession(ctx, w.Intent.SessionID, a, func(q *custodydb.Queries, _ artifact.DownloadSession, _ time.Time) error {
		r, e := q.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(w.Intent.ID), RootID: id(s.downloads.root)})
		if e != nil {
			return e
		}
		j, _ := json.Marshal(w.Job)
		b, _ := json.Marshal(w.Binding)
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !workerMatches(r, w.Intent) || !bytes.Equal(j, r.JobJson) || r.RetiredProofJson != nil || !now.Time.Before(w.Intent.RunUntil) {
			return artifact.ErrDownloadConflict
		}
		if r.BindingJson != nil {
			if !bytes.Equal(r.BindingJson, b) {
				return artifact.ErrDownloadConflict
			}
			return nil
		}
		n, e := q.BindDownloadWorker(ctx, custodydb.BindDownloadWorkerParams{ID: r.ID, RootID: r.RootID, BindingJson: b})
		if e != nil || n != 1 {
			return artifact.ErrDownloadConflict
		}
		return nil
	})
}
func (s *DownloadWorkers) ReadDownloadWorker(ctx context.Context, session string, a artifact.DownloadAuthority) (value.DownloadWorker, error) {
	var out value.DownloadWorker
	e := s.withSession(ctx, session, a, func(q *custodydb.Queries, _ artifact.DownloadSession, now time.Time) error {
		r, e := q.LatestDownloadWorker(ctx, custodydb.LatestDownloadWorkerParams{SessionID: id(session), RootID: id(s.downloads.root)})
		if e != nil {
			return e
		}
		if r.RetiredProofJson != nil || !now.Before(r.RunUntil.Time) {
			return artifact.ErrDownloadExpired
		}
		out, e = currentAuditedWorker(r)
		return e
	})
	if e != nil {
		return value.DownloadWorker{}, e
	}
	return out, nil
}
func (s *DownloadWorkers) readWorkerIdentity(ctx context.Context, session string) (value.DownloadWorkerIdentity, error) {
	if s == nil {
		return value.DownloadWorkerIdentity{}, artifact.ErrInvalid
	}
	return readWorkerIdentity(ctx, s.downloads.ledger, s.downloads.root, s.profile.InstallationID, &s.profile, session)
}

func (s *DownloadWorkers) ReadDownloadWorkerEnrollment(ctx context.Context, session, worker string) (value.DownloadWorkerIdentity, error) {
	if !value.UUID(worker) {
		return value.DownloadWorkerIdentity{}, artifact.ErrInvalid
	}
	o, e := s.readWorkerIdentity(ctx, session)
	if e != nil {
		return value.DownloadWorkerIdentity{}, e
	}
	if o.Worker.Intent.ID != worker {
		return value.DownloadWorkerIdentity{}, artifact.ErrInvalid
	}
	return o, nil
}
func (s *DownloadWorkers) ReadDownloadWorkerIdentity(ctx context.Context, session string, peer value.KeyPeer) (value.DownloadWorkerIdentity, error) {
	if s == nil || !peer.Valid(time.Now()) || peer.Role != "acquisition" || peer.InstallationID != s.profile.InstallationID {
		return value.DownloadWorkerIdentity{}, artifact.ErrInvalid
	}
	o, e := s.readWorkerIdentity(ctx, session)
	if e != nil {
		return value.DownloadWorkerIdentity{}, e
	}
	if o.Worker.Binding.PodUID != peer.PeerID {
		return value.DownloadWorkerIdentity{}, artifact.ErrInvalid
	}
	ctx, end := context.WithDeadline(ctx, o.FreshUntil)
	defer end()
	if e = activeWorkerCertificate(ctx, custodydb.New(s.downloads.ledger.pool), o.Worker, peer); e != nil {
		return value.DownloadWorkerIdentity{}, e
	}
	if !o.Valid(time.Now()) || !peer.Valid(time.Now()) {
		return value.DownloadWorkerIdentity{}, artifact.ErrDownloadExpired
	}
	return o, nil
}
func (s *DownloadWorkers) RetireDownloadWorker(ctx context.Context, p value.DownloadWorkerRetirement) error {
	if s == nil || ctx == nil || !p.Valid(p.ObservedAt) || p.Termination.Worker.Intent.Profile != s.profile {
		return artifact.ErrInvalid
	}
	return s.downloads.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, e := q.LockPermissionStream(ctx, id(s.downloads.root)); e != nil {
			return e
		}
		r, e := q.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(p.Termination.Worker.Intent.ID), RootID: id(s.downloads.root)})
		if e != nil {
			return e
		}
		w, e := decodeWorker(r)
		if e != nil || w != p.Termination.Worker {
			return artifact.ErrIntegrity
		}
		now, e := q.CurrentTime(ctx)
		if e != nil || !p.Valid(now.Time) {
			return artifact.ErrDownloadExpired
		}
		term, _ := json.Marshal(p.Termination)
		if !bytes.Equal(term, r.TerminationJson) {
			return artifact.ErrIntegrity
		}
		if r.RetiredProofJson != nil {
			return nil
		}
		b, _ := json.Marshal(p)
		n, e := q.RetireDownloadWorker(ctx, custodydb.RetireDownloadWorkerParams{ID: r.ID, RootID: r.RootID, RetiredProofJson: b})
		if e != nil || n != 1 {
			return artifact.ErrDownloadConflict
		}
		now, e = q.CurrentTime(ctx)
		if e != nil || !p.Valid(now.Time) {
			return artifact.ErrDownloadExpired
		}
		return nil
	})
}

func (s *DownloadWorkers) ReadDownloadWorkerTermination(ctx context.Context, w value.DownloadWorker) (value.DownloadWorkerTermination, bool, error) {
	var out value.DownloadWorkerTermination
	if s == nil || ctx == nil || !w.Valid() || w.Intent.Profile != s.profile {
		return out, false, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	q := custodydb.New(s.downloads.ledger.pool)
	r, e := q.LatestDownloadWorker(ctx, custodydb.LatestDownloadWorkerParams{SessionID: id(w.Intent.SessionID), RootID: id(s.downloads.root)})
	if e != nil {
		return out, false, e
	}
	old, e := decodeWorker(r)
	if e != nil || old != w {
		return out, false, artifact.ErrIntegrity
	}
	if r.TerminationJson == nil {
		return out, false, nil
	}
	if json.Unmarshal(r.TerminationJson, &out) != nil || !out.Valid(out.ObservedAt) || out.Worker != w {
		return out, false, artifact.ErrIntegrity
	}
	return out, true, nil
}
func (s *DownloadWorkers) ConfirmDownloadWorkerTermination(ctx context.Context, p value.DownloadWorkerTermination) (value.DownloadWorkerTermination, error) {
	var out value.DownloadWorkerTermination
	if s == nil || ctx == nil || !p.Valid(p.ObservedAt) || p.Worker.Intent.Profile != s.profile {
		return out, artifact.ErrInvalid
	}
	e := s.downloads.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		r, e := q.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(p.Worker.Intent.ID), RootID: id(s.downloads.root)})
		if e != nil {
			return e
		}
		w, e := decodeWorker(r)
		if e != nil || w != p.Worker {
			return artifact.ErrIntegrity
		}
		if r.TerminationJson != nil {
			if json.Unmarshal(r.TerminationJson, &out) != nil || !out.Valid(out.ObservedAt) || out.Worker != w {
				return artifact.ErrIntegrity
			}
			return nil
		}
		now, e := q.CurrentTime(ctx)
		if e != nil || !p.Valid(now.Time) {
			return artifact.ErrDownloadExpired
		}
		b, _ := json.Marshal(p)
		n, e := q.ConfirmDownloadWorkerTermination(ctx, custodydb.ConfirmDownloadWorkerTerminationParams{ID: r.ID, RootID: r.RootID, TerminationJson: b})
		if e != nil || n != 1 {
			return artifact.ErrDownloadConflict
		}
		now, e = q.CurrentTime(ctx)
		if e != nil || !p.Valid(now.Time) {
			return artifact.ErrDownloadExpired
		}
		out = p
		return nil
	})
	if e != nil {
		return value.DownloadWorkerTermination{}, e
	}
	return out, nil
}

// UnretiredDownloadWorkers lists bound native download workers still charged
// against acquisition capacity. Rows from another profile stay charged.
func (s *DownloadWorkers) UnretiredDownloadWorkers(ctx context.Context) ([]evidence.DownloadCleanupCandidate, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	rows, e := custodydb.New(s.downloads.ledger.pool).UnretiredBoundDownloadWorkers(call, custodydb.UnretiredBoundDownloadWorkersParams{RootID: id(s.downloads.root), InstallationID: id(s.profile.InstallationID)})
	if e != nil || len(rows) > 16 {
		return nil, artifact.ErrDownloadUnavailable
	}
	out := make([]evidence.DownloadCleanupCandidate, 0, len(rows))
	for _, r := range rows {
		w, e := decodeWorker(r)
		if e != nil || w.Intent.Profile != s.profile {
			continue
		}
		c := evidence.DownloadCleanupCandidate{Worker: w}
		if r.TerminationJson != nil {
			if json.Unmarshal(r.TerminationJson, &c.Termination) != nil || !c.Termination.Valid(c.Termination.ObservedAt) || c.Termination.Worker != w {
				return nil, artifact.ErrIntegrity
			}
		}
		out = append(out, c)
	}
	if call.Err() != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	return out, nil
}
