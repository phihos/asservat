package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// NativeOwners is a purpose-separated worker rendezvous. Its deployment chooses
// exact profile/root credentials. A locator read supplies no address, human
// identity, admission or authority; actual peer/proof checking remains mandatory.
type NativeOwners struct{ workers *DownloadWorkers }

var _ evidence.NativeOperations = (*NativeOwners)(nil)
var _ evidence.NativeOperationRenewer = (*NativeOwners)(nil)

func NewNativeOwners(ctx context.Context, pool *pgxpool.Pool, root string, p value.DownloadWorkerProfile, g DownloadTransactionGuards) (*NativeOwners, error) {
	w, e := NewDownloadWorkers(ctx, pool, root, p, g)
	if e != nil {
		return nil, e
	}
	return &NativeOwners{w}, nil
}
func decodeNativeOwner(r custodydb.DownloadNativeOwner) (value.NativeOperation, artifact.DownloadAuthority, error) {
	var o value.NativeOperation
	var a artifact.DownloadAuthority
	if json.Unmarshal(r.OperationJson, &o) != nil || json.Unmarshal(r.AuthorityJson, &a) != nil || !o.Valid() || o.Reference.WorkerID != uid(r.WorkerID) || o.Reference.OperationID != uid(r.OperationID) || o.Reference.Fence != r.Fence || a.Scope.RootID != uid(r.RootID) || o.SourceVersion != a.Scope.Version || !a.Valid(r.LeaseStarted.Time) || r.LeaseUntil.Time.After(a.ValidUntil) || r.LeaseUntil.Time.After(o.Until) {
		return o, a, artifact.ErrIntegrity
	}
	return o, a, nil
}

// admit distinguishes an initial native preparation from its later positive
// commit check. Reading a stored outcome never reopens its three unwrap slots.
func nativeParent(ctx context.Context, q *custodydb.Queries, parent artifact.DownloadSession, o value.NativeOperation, now time.Time, admit bool) (int64, time.Time, error) {
	switch o.Kind {
	case value.NativePrepare, value.NativeObserve:
		b, e := q.ReadDownloadBatch(ctx, custodydb.ReadDownloadBatchParams{ID: id(o.ParentID), SessionID: id(parent.ID)})
		if e != nil {
			return 0, time.Time{}, e
		}
		i, e := decodeDownloadIntent(b)
		if e != nil || i.SessionID != parent.ID || i.Batch.Purpose != artifact.DownloadMetadata || i.Batch.Generation != o.Generation || i.Batch.Authority.Scope != parent.Scope || !b.AuditAcknowledgedAt.Valid || len(b.AuditReceiptJson) == 0 {
			return 0, time.Time{}, artifact.ErrDownloadUnavailable
		}
		if o.Kind == value.NativePrepare && parent.Active != nil && parent.Active.ID == o.ParentID && parent.Active.Generation == o.Generation && parent.Active.AuditAcknowledged && now.Before(parent.Active.LeaseUntil) {
			return 1, parent.Active.LeaseUntil, nil
		}
		if admit && o.Kind == value.NativePrepare {
			return 0, time.Time{}, artifact.ErrDownloadUnavailable
		}
		var outcome audit.DownloadOutcome
		var receipt audit.Receipt
		if !b.OutcomeAcknowledgedAt.Valid || json.Unmarshal(b.OutcomeJson, &outcome) != nil || !outcome.Valid() || !outcome.Intent.Equal(i) || !outcome.Success || json.Unmarshal(b.OutcomeReceiptJson, &receipt) != nil || !receipt.ValidDownload(parent.Scope.RootID, parent.ID, o.ParentID, "outcome") {
			return 0, time.Time{}, artifact.ErrDownloadUnavailable
		}
		return 1, parent.Deadline, nil
	case value.NativeResponse:
		row, e := q.LockDownloadResponse(ctx, custodydb.LockDownloadResponseParams{ID: id(o.ParentID), SessionID: id(parent.ID), RootID: id(parent.Scope.RootID)})
		if e != nil {
			return 0, time.Time{}, e
		}
		r, e := decodeResponse(row)
		if e != nil || r.Closed || r.Generation != o.Generation || r.Generation != parent.Generation || !now.Before(r.LeaseUntil) || !now.Before(r.Until) || r.ActiveWindowID == "" {
			return 0, time.Time{}, artifact.ErrDownloadUnavailable
		}
		wr, e := q.LockDownloadWindow(ctx, custodydb.LockDownloadWindowParams{ID: id(r.ActiveWindowID), ResponseID: id(r.ID), SessionID: id(parent.ID)})
		if e != nil {
			return 0, time.Time{}, e
		}
		_, w, e := decodeWindow(wr)
		if e != nil || !w.IntentAcknowledged || len(wr.IntentCompletion) == 0 || w.Outcome != nil || w.Generation != r.Generation || w.Authority.Scope != parent.Scope {
			return 0, time.Time{}, artifact.ErrDownloadUnavailable
		}
		return r.LeaseSequence, r.LeaseUntil, nil
	default:
		return 0, time.Time{}, artifact.ErrDownloadUnavailable
	}
}
func nativeWorker(ctx context.Context, q *custodydb.Queries, root string, o value.NativeOperation) (value.WorkerEnrollment, error) {
	var zero value.WorkerEnrollment
	row, e := q.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(o.Reference.WorkerID), RootID: id(root)})
	if e != nil {
		return zero, e
	}
	w, e := currentAuditedWorker(row)
	if e != nil || len(row.AuditReceiptJson) == 0 || row.TerminationJson != nil || row.RetiredProofJson != nil || w.Intent.SessionID != o.Reference.SessionID || w.Binding.InstallationID != o.Reference.InstallationID || w.Binding.PodUID != o.WorkerPodUID || o.Until.After(w.Intent.RunUntil) {
		return zero, artifact.ErrDownloadUnavailable
	}
	en, e := currentAuditedWorkerEnrollment(ctx, q, w)
	if e != nil || en.PublicKeyDigest != o.WorkerPublicKey {
		return zero, artifact.ErrDownloadUnavailable
	}
	return en, nil
}
func (s *NativeOwners) ClaimNativeOperation(ctx context.Context, en value.WorkerEnrollment, a artifact.DownloadAuthority, o value.NativeOperation) (value.NativeOperation, error) {
	return s.claimNativeOperation(ctx, en, a, o, false)
}
func (s *NativeOwners) claimNativeOperation(ctx context.Context, en value.WorkerEnrollment, a artifact.DownloadAuthority, o value.NativeOperation, firstContext bool) (value.NativeOperation, error) {
	var out value.NativeOperation
	if s == nil || ctx == nil || ctx.Err() != nil || !en.Valid() || en.Worker.Intent.Profile != s.workers.profile || !o.CurrentValid(time.Now()) || o.Path != a.Environment.Path || !o.Processing.Equal(a.Environment.Processing) || !a.Valid(time.Now()) || o.Reference.SessionID != en.Worker.Intent.SessionID || o.Reference.WorkerID != en.Worker.Intent.ID || o.WorkerPublicKey != en.PublicKeyDigest || o.SourceVersion != a.Scope.Version || a.Scope != en.Worker.Intent.Authority.Scope || o.StartedAt.After(time.Now()) {
		return out, sqlStep{"native-claim-input", artifact.ErrInvalid}
	}
	o.StartedAt = o.StartedAt.UTC().Truncate(time.Microsecond)
	o.Until = o.Until.UTC().Truncate(time.Microsecond)
	ctx, cancel := context.WithDeadline(ctx, identity.Earlier(a.ValidUntil, o.Until))
	defer cancel()
	stage := "native-claim-session"
	err := s.workers.withSession(ctx, o.Reference.SessionID, a, func(q *custodydb.Queries, p artifact.DownloadSession, now time.Time) error {
		// Parent response/window locks precede worker/native locks everywhere.
		stage = "native-claim-parent"
		seq, end, e := nativeParent(ctx, q, p, o, now, true)
		if e != nil {
			return e
		}
		stage = "native-claim-worker"
		actual, e := nativeWorker(ctx, q, s.workers.downloads.root, o)
		if e != nil || actual != en {
			return artifact.ErrDownloadUnavailable
		}
		stage = "native-claim-owner"
		old, lookup := q.LockNativeOwner(ctx, custodydb.LockNativeOwnerParams{WorkerID: id(o.Reference.WorkerID), RootID: id(s.workers.downloads.root)})
		if lookup != nil && !errors.Is(lookup, pgx.ErrNoRows) {
			return lookup
		}
		if firstContext && o.Kind == value.NativeObserve {
			if p.StopProtocol != artifact.DownloadStopProtocol || en.Worker.Intent.Generation != 1 {
				return artifact.ErrDownloadUnavailable
			}
			control, e := readContextNativeControl(ctx, q, p, en.Worker.Intent.ID)
			if e != nil {
				return e
			}
			if !control.canObserve() {
				return artifact.ErrDownloadUnavailable
			}
		}
		stage = "native-claim-clock"
		clock, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		now = clock.Time.UTC()
		end = identity.Earlier(end, identity.Earlier(a.ValidUntil, o.Until)).UTC().Truncate(time.Microsecond)
		stage = "native-claim-deadline"
		if !a.Valid(now) || !now.Before(end) || o.Until.After(p.Deadline) || o.Until.After(a.AccessUntil) {
			return artifact.ErrDownloadExpired
		}
		stage = "native-claim-predecessor"
		if lookup == nil {
			previous, _, e := decodeNativeOwner(old)
			if e != nil {
				return e
			}
			if previous.Reference.OperationID == o.Reference.OperationID {
				if !previous.Equal(o) || old.Closed || old.RetiredAt.Valid || !now.Before(old.LeaseUntil.Time) || old.LeaseSequence != seq {
					return artifact.ErrDownloadConflict
				}
				out = previous
				return nil
			}
			if !old.Closed || old.RetiredAt.Valid || o.Reference.Fence != old.Fence+1 {
				return artifact.ErrDownloadConflict
			}
		} else if o.Reference.Fence != 1 {
			return artifact.ErrDownloadConflict
		}
		stage = "native-claim-encoding"
		encoded, e := json.Marshal(o)
		if e != nil || len(encoded) > 8192 {
			return artifact.ErrInvalid
		}
		authority, e := json.Marshal(a)
		if e != nil || len(authority) > 16384 {
			return artifact.ErrInvalid
		}
		var row custodydb.DownloadNativeOwner
		stage = "native-claim-write"
		if lookup == nil {
			row, e = q.ReplaceNativeOwner(ctx, custodydb.ReplaceNativeOwnerParams{WorkerID: id(o.Reference.WorkerID), RootID: id(s.workers.downloads.root), Fence: old.Fence, OperationID: id(o.Reference.OperationID), OperationJson: encoded, AuthorityJson: authority, LeaseSequence: seq, LeaseStarted: ts(now), LeaseUntil: ts(end)})
		} else {
			row, e = q.InsertNativeOwner(ctx, custodydb.InsertNativeOwnerParams{WorkerID: id(o.Reference.WorkerID), RootID: id(s.workers.downloads.root), AllocationID: id(p.AllocationID), OperationID: id(o.Reference.OperationID), Fence: o.Reference.Fence, OperationJson: encoded, AuthorityJson: authority, LeaseSequence: seq, LeaseStarted: ts(now), LeaseUntil: ts(end)})
		}
		if e != nil {
			return e
		}
		stage = "native-claim-decode"
		out, _, e = decodeNativeOwner(row)
		if e != nil {
			return e
		}
		stage = "native-claim-session-final"
		return nil
	})
	if err != nil || ctx.Err() != nil {
		// Preserve only the closed stage; dependency errors remain private.
		var inner interface{ FixedStep() string }
		if errors.As(err, &inner) {
			stage += "/" + inner.FixedStep()
		}
		return value.NativeOperation{}, sqlStep{stage, artifact.ErrDownloadUnavailable}
	}
	return out, nil
}
func (s *NativeOwners) ObserveNativeOperation(ctx context.Context, ref value.NativeReference, peer value.KeyPeer) (value.NativeLease, error) {
	var out value.NativeLease
	if s == nil || ctx == nil || ctx.Err() != nil || !ref.Valid() || !peer.Valid(time.Now()) || peer.Role != "acquisition" || peer.InstallationID != ref.InstallationID {
		return out, artifact.ErrDownloadUnavailable
	}
	initial, e := custodydb.New(s.workers.downloads.ledger.pool).ReadNativeOwner(ctx, custodydb.ReadNativeOwnerParams{WorkerID: id(ref.WorkerID), RootID: id(s.workers.downloads.root)})
	if e != nil {
		return out, artifact.ErrDownloadUnavailable
	}
	o, a, e := decodeNativeOwner(initial)
	if e != nil || o.Reference != ref || !o.CurrentValid(time.Now()) || o.Path != a.Environment.Path || !sameNativeProcessingState(o.Processing, a.Environment.Processing) {
		return out, artifact.ErrDownloadUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, identity.Earlier(a.ValidUntil, initial.LeaseUntil.Time))
	defer cancel()
	e = s.workers.withSession(ctx, ref.SessionID, a, func(q *custodydb.Queries, p artifact.DownloadSession, now time.Time) error {
		seq, end, e := nativeParent(ctx, q, p, o, now, false)
		if e != nil {
			return e
		}
		en, e := nativeWorker(ctx, q, s.workers.downloads.root, o)
		if e != nil {
			return e
		}
		row, e := q.LockNativeOwner(ctx, custodydb.LockNativeOwnerParams{WorkerID: id(ref.WorkerID), RootID: id(s.workers.downloads.root)})
		if e != nil {
			return e
		}
		if row.Closed || row.RetiredAt.Valid || row.LeaseSequence != seq || !bytes.Equal(row.OperationJson, initial.OperationJson) || !bytes.Equal(row.AuthorityJson, initial.AuthorityJson) || row.Fence != ref.Fence || peer.PeerID != o.WorkerPodUID {
			return artifact.ErrDownloadUnavailable
		}
		if e = activeWorkerCertificate(ctx, q, en.Worker, peer); e != nil {
			return e
		}
		clock, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		now = clock.Time.UTC()
		end = identity.Earlier(end, identity.Earlier(row.LeaseUntil.Time, peer.NotAfter))
		out = value.NativeLease{Operation: o, Certificate: peer.Certificate, Sequence: seq, ObservedAt: row.LeaseStarted.Time.UTC(), Until: end.UTC()}
		if !out.Valid(now) || !peer.Valid(now) {
			return artifact.ErrDownloadExpired
		}
		return nil
	})
	if e != nil || ctx.Err() != nil || !out.Valid(time.Now()) {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}

// RenewNativeOperation consumes a separately admitted newer delivery lease of
// the same response. The existing operation, worker, source and deadline are
// immutable. An expired short observation is not reused as authority.
func (s *NativeOwners) RenewNativeOperation(ctx context.Context, ref value.NativeReference, a artifact.DownloadAuthority, peer value.KeyPeer) (value.NativeLease, error) {
	var out value.NativeLease
	now := time.Now()
	if s == nil || ctx == nil || ctx.Err() != nil || !ref.Valid() || !a.Valid(now) || !peer.Valid(now) || peer.Role != "acquisition" || peer.InstallationID != ref.InstallationID || ref.QueryID != "" {
		return out, artifact.ErrDownloadUnavailable
	}
	initial, err := custodydb.New(s.workers.downloads.ledger.pool).ReadNativeOwner(ctx, custodydb.ReadNativeOwnerParams{WorkerID: id(ref.WorkerID), RootID: id(s.workers.downloads.root)})
	if err != nil {
		return out, artifact.ErrDownloadUnavailable
	}
	o, previous, err := decodeNativeOwner(initial)
	if err != nil || o.Reference != ref || o.Kind != value.NativeResponse || !o.CurrentValid(now) || o.WorkerPodUID != peer.PeerID || a.Scope != previous.Scope || o.Path != a.Environment.Path || !sameNativeProcessingState(o.Processing, a.Environment.Processing) {
		return out, artifact.ErrDownloadUnavailable
	}
	call, cancel := context.WithDeadline(ctx, identity.Earlier(a.ValidUntil, o.Until))
	defer cancel()
	err = s.workers.withSession(call, ref.SessionID, a, func(q *custodydb.Queries, parent artifact.DownloadSession, _ time.Time) error {
		clock, err := q.CurrentTime(call)
		if err != nil {
			return err
		}
		// Parent response/window locks precede worker and owner locks, exactly
		// as they do during original admission and observation.
		seq, end, err := nativeParent(call, q, parent, o, clock.Time, true)
		if err != nil {
			return err
		}
		en, err := nativeWorker(call, q, s.workers.downloads.root, o)
		if err != nil {
			return err
		}
		row, err := q.LockNativeOwner(call, custodydb.LockNativeOwnerParams{WorkerID: id(ref.WorkerID), RootID: id(s.workers.downloads.root)})
		if err != nil {
			return err
		}
		if row.Closed || row.RetiredAt.Valid || row.Fence != ref.Fence || !bytes.Equal(row.OperationJson, initial.OperationJson) || seq <= row.LeaseSequence {
			return artifact.ErrDownloadConflict
		}
		if err := activeWorkerCertificate(call, q, en.Worker, peer); err != nil {
			return err
		}
		clock, err = q.CurrentTime(call)
		if err != nil {
			return err
		}
		now := clock.Time.UTC()
		end = identity.Earlier(end, identity.Earlier(a.ValidUntil, identity.Earlier(o.Until, peer.NotAfter))).UTC().Truncate(time.Microsecond)
		if !a.Valid(now) || !o.CurrentValid(now) || !peer.Valid(now) || !now.Before(end) || o.Until.After(parent.Deadline) || o.Until.After(a.AccessUntil) {
			return artifact.ErrDownloadExpired
		}
		encoded, err := json.Marshal(a)
		if err != nil || len(encoded) > 16384 {
			return artifact.ErrInvalid
		}
		_, err = q.RenewNativeOwner(call, custodydb.RenewNativeOwnerParams{WorkerID: id(ref.WorkerID), RootID: id(s.workers.downloads.root), OperationID: id(ref.OperationID), Fence: ref.Fence, AuthorityJson: encoded, LeaseSequence: seq, LeaseStarted: ts(now), LeaseUntil: ts(end)})
		if err != nil {
			return err
		}
		out = value.NativeLease{Operation: o, Certificate: peer.Certificate, Sequence: seq, ObservedAt: now, Until: end}
		if !out.Valid(now) {
			return artifact.ErrDownloadExpired
		}
		return call.Err()
	})
	if err != nil || call.Err() != nil || !out.Valid(time.Now()) {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}

// Observation dates can change during a fresh lease; processing identity cannot.
func sameNativeProcessingState(a, b artifact.DownloadProcessingProof) bool {
	a.ObservedAt, a.ValidUntil = time.Time{}, time.Time{}
	b.ObservedAt, b.ValidUntil = time.Time{}, time.Time{}
	return a == b
}
func (s *NativeOwners) ReleaseNativeOperation(ctx context.Context, o value.NativeOperation) error {
	if s == nil || ctx == nil || !o.Valid() || o.Reference.InstallationID != s.workers.profile.InstallationID {
		return artifact.ErrInvalid
	}
	_, e := custodydb.New(s.workers.downloads.ledger.pool).CloseNativeOwner(ctx, custodydb.CloseNativeOwnerParams{WorkerID: id(o.Reference.WorkerID), RootID: id(s.workers.downloads.root), OperationID: id(o.Reference.OperationID), Fence: o.Reference.Fence})
	return e
}

// LocateNativeOperation is private authenticated worker routing only. Its
// result is rechecked under normal effect fences and can never choose another
// worker or renew the recorded original operation interval.
func (s *NativeOwners) LocateNativeOperation(ctx context.Context, installation, session, worker string, peer value.KeyPeer) (value.NativeLease, error) {
	if s == nil || ctx == nil || installation != s.workers.profile.InstallationID || !value.UUID(session) || !value.UUID(worker) || peer.InstallationID != installation {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	row, e := custodydb.New(s.workers.downloads.ledger.pool).ReadNativeOwner(ctx, custodydb.ReadNativeOwnerParams{WorkerID: id(worker), RootID: id(s.workers.downloads.root)})
	if errors.Is(e, pgx.ErrNoRows) || e == nil && row.Closed {
		observation, readErr := s.workers.ReadDownloadWorkerIdentity(ctx, session, peer)
		if readErr != nil || observation.Worker.Intent.ID != worker || ctx.Err() != nil {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		return value.NativeLease{}, &evidence.NativeNoOperation{Worker: observation.Acquisition()}
	}
	if e != nil {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	o, _, e := decodeNativeOwner(row)
	if e != nil || o.Reference.InstallationID != installation || o.Reference.SessionID != session {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	return s.ObserveNativeOperation(ctx, o.Reference, peer)
}

// NextNativeFence is only a private candidate read. Claim rechecks the exact
// row under locks; absence/errors never publish routing or confer authority.
// An expired but unclosed owner is not silently replaced.
func (s *NativeOwners) NextNativeFence(ctx context.Context, worker string) (int64, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !value.UUID(worker) {
		return 0, artifact.ErrInvalid
	}
	row, e := custodydb.New(s.workers.downloads.ledger.pool).ReadNativeOwner(ctx, custodydb.ReadNativeOwnerParams{WorkerID: id(worker), RootID: id(s.workers.downloads.root)})
	if errors.Is(e, pgx.ErrNoRows) {
		return 1, nil
	}
	if e != nil {
		return 0, e
	}
	if !row.Closed || row.RetiredAt.Valid || row.Fence >= 1<<60 || ctx.Err() != nil {
		return 0, artifact.ErrDownloadUnavailable
	}
	return row.Fence + 1, nil
}

// ReadNativeWorkerCertificate supplies the exact already activated public chain
// for a trusted-connector leaf report. It creates no TLS observation; the caller
// must authenticate that connector and independently verify this current chain.
func (s *NativeOwners) ReadNativeWorkerCertificate(ctx context.Context, session, worker string, leaf []byte) (value.WorkerCertificate, error) {
	var zero value.WorkerCertificate
	if s == nil || ctx == nil || len(leaf) < 1 || len(leaf) > 16<<10 {
		return zero, artifact.ErrInvalid
	}
	observation, e := s.workers.ReadDownloadWorkerEnrollment(ctx, session, worker)
	if e != nil {
		return zero, e
	}
	call, stop := context.WithDeadline(ctx, observation.FreshUntil)
	defer stop()
	digest := sha256.Sum256(leaf)
	q := custodydb.New(s.workers.downloads.ledger.pool)
	row, e := q.ReadActiveWorkerCertificate(call, custodydb.ReadActiveWorkerCertificateParams{WorkerID: id(worker), CertificateSha256: digest[:]})
	if e != nil {
		return zero, e
	}
	attempt, e := decodeWorkerCertificateAttempt(row)
	if e != nil || attempt.Enrollment.Worker != observation.Worker {
		return zero, artifact.ErrDownloadUnavailable
	}
	certificate, e := decodeWorkerCertificate(row, attempt)
	if e != nil || !bytes.Equal(leaf, certificate.DER) {
		return zero, artifact.ErrDownloadUnavailable
	}
	if e = activeWorkerCertificate(call, q, observation.Worker, certificate.Peer); e != nil || call.Err() != nil || !observation.Valid(time.Now()) {
		return zero, artifact.ErrDownloadUnavailable
	}
	return certificate, nil
}
