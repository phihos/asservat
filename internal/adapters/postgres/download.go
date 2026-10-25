package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	privacyvalue "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type DownloadTransactionGuards = EffectTransactionGuards

type Downloads struct {
	ledger    *Ledger
	root      string
	retention *RetentionTransactionGuard
	recovery  *RecoveryTransactionGuard
}

var _ evidence.DownloadSessions = (*Downloads)(nil)
var _ evidence.DownloadAuditAcknowledger = (*Downloads)(nil)
var _ capacity.DownloadAllocations = (*Downloads)(nil)

// Runtime, audit and configuration facets are composed with separate SQL roles.
// The implementation does not grant roles, decrypt evidence or create authority.
func NewDownloads(ctx context.Context, pool *pgxpool.Pool, root string, guards ...DownloadTransactionGuards) (*Downloads, error) {
	if !authorization.UUID(root) {
		return nil, artifact.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if why := schemaCompatible(ctx, pool); why != "" {
		return nil, schemaRefusal(privacy.ErrUnavailable, why)
	}
	guard, err := effectGuardsFor(root, guards)
	if err != nil {
		return nil, err
	}
	return &Downloads{ledger: l, root: root, retention: guard.Retention, recovery: guard.Recovery}, nil
}
func principalKey(p identity.Principal) []byte { p.ClientID = ""; return digest(p) }
func downloadAllocation(r custodydb.DownloadAllocation) artifact.DownloadAllocation {
	return artifact.DownloadAllocation{ID: uid(r.ID), RootID: uid(r.RootID), ClusterID: uid(r.ClusterID), NamespaceUID: r.NamespaceUid, WorkloadUID: r.WorkloadUid, OutputLimit: r.OutputLimit, ReadLimit: r.ReadLimit, SessionLimit: r.SessionLimit, ValidUntil: r.ValidUntil.Time.UTC()}
}
func (s *Downloads) BindDownloadAllocation(ctx context.Context, a artifact.DownloadAllocation) error {
	a.ValidUntil = a.ValidUntil.UTC().Truncate(time.Microsecond)
	if !a.Valid() || a.RootID != s.root {
		return artifact.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		r, err := q.LockDownloadAllocation(ctx, custodydb.LockDownloadAllocationParams{ID: id(a.ID), RootID: id(s.root)})
		if err == nil {
			if downloadAllocation(r) != a {
				return privacy.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !n.Time.Before(a.ValidUntil) || a.ValidUntil.After(n.Time.Add(8*time.Hour)) {
			return artifact.ErrInvalid
		}
		_, err = q.InsertDownloadAllocation(ctx, custodydb.InsertDownloadAllocationParams{ID: id(a.ID), RootID: id(a.RootID), ClusterID: id(a.ClusterID), NamespaceUid: a.NamespaceUID, WorkloadUid: a.WorkloadUID, OutputLimit: a.OutputLimit, ReadLimit: a.ReadLimit, SessionLimit: a.SessionLimit, ValidUntil: ts(a.ValidUntil)})
		return err
	})
}

func decodeDownload(r custodydb.ArtifactDownload) (artifact.DownloadSession, error) {
	var scope artifact.DownloadScope
	if json.Unmarshal(r.ScopeJson, &scope) != nil || len(r.RequestDigest) != 32 || !scope.Valid() || scope.RootID != uid(r.RootID) || scope.ArtifactID != uid(r.ArtifactID) || !bytes.Equal(r.ActorKey, digest(scope.Principal)) || !bytes.Equal(r.PrincipalKey, principalKey(scope.Principal)) {
		return artifact.DownloadSession{}, privacy.ErrFence
	}
	s := artifact.DownloadSession{StopProtocol: r.StopProtocol.String, ID: uid(r.ID), AllocationID: uid(r.AllocationID), Scope: scope, RequestDigest: artifact.Digest(r.RequestDigest), State: artifact.DownloadState(r.State), CreatedAt: r.CreatedAt.Time, Deadline: r.Deadline.Time, OutputLimit: r.OutputLimit, ReadLimit: r.ReadLimit, RequestLimit: r.RequestLimit, ChargedOutput: r.ChargedOutput, ChargedRead: r.ChargedRead, Requests: r.Requests, EmittedBytes: r.EmittedBytes, Generation: r.Generation}
	if !s.Valid() {
		return artifact.DownloadSession{}, privacy.ErrFence
	}
	backing, err := decodeCapacitySessionBacking(r.CapacityBacking, r.CapacityBackingDigest, r.CapacityAccountID.Valid, s)
	if err != nil || backing != nil && backing.AccountID != uid(r.CapacityAccountID) {
		return artifact.DownloadSession{}, privacy.ErrFence
	}
	return s, nil
}
func decodeDownloadIntent(r custodydb.DownloadBatch) (audit.DownloadIntent, error) {
	out, err := decodeHistoricalDownloadIntent(r)
	if err != nil {
		return out, err
	}
	if r.AuditAcknowledgedAt.Valid {
		var receipt audit.Receipt
		if json.Unmarshal(r.AuditReceiptJson, &receipt) != nil || !receipt.ValidDownload(out.Batch.Authority.Scope.RootID, out.SessionID, out.Batch.ID, "intent") {
			return out, privacy.ErrFence
		}
	}
	return out, nil
}

// decodeHistoricalDownloadIntent preserves original receipt bytes for local
// cancellation and accounting. It never qualifies another read/effect.
func decodeHistoricalDownloadIntent(r custodydb.DownloadBatch) (audit.DownloadIntent, error) {
	var out audit.DownloadIntent
	if json.Unmarshal(r.IntentJson, &out) != nil || !out.Valid() || id(out.SessionID) != r.SessionID || id(out.Batch.ID) != r.ID || out.Batch.Generation != r.Generation || !out.Batch.LeaseUntil.Equal(r.LeaseUntil.Time) {
		return out, privacy.ErrFence
	}
	if r.AuditAcknowledgedAt.Valid {
		var receipt audit.Receipt
		if json.Unmarshal(r.AuditReceiptJson, &receipt) != nil || !receipt.ValidHistoricalDownload(out.Batch.Authority.Scope.RootID, out.SessionID, out.Batch.ID, "intent") {
			return out, privacy.ErrFence
		}
	}
	return out, nil
}
func loadDownload(ctx context.Context, q *custodydb.Queries, r custodydb.ArtifactDownload) (artifact.DownloadSession, error) {
	s, err := decodeDownload(r)
	if err != nil || !r.ActiveBatch.Valid {
		return s, err
	}
	b, err := q.ReadDownloadBatch(ctx, custodydb.ReadDownloadBatchParams{ID: r.ActiveBatch, SessionID: r.ID})
	if err != nil {
		return s, err
	}
	i, err := decodeDownloadIntent(b)
	if err != nil {
		return s, err
	}
	if i.Batch.Authority.Scope != s.Scope || i.Batch.Generation != s.Generation || len(b.OutcomeJson) > 0 {
		return s, privacy.ErrFence
	}
	i.Batch.AuditAcknowledged = b.AuditAcknowledgedAt.Valid
	s.Active = &i.Batch
	return s, nil
}

// loadHistoricalDownload is used only for cancellation and recording already
// performed I/O. Stored acknowledgement presence does not grant fresh authority.
func loadHistoricalDownload(ctx context.Context, q *custodydb.Queries, r custodydb.ArtifactDownload) (artifact.DownloadSession, error) {
	s, err := decodeDownload(r)
	if err != nil || !r.ActiveBatch.Valid {
		return s, err
	}
	b, err := q.ReadDownloadBatch(ctx, custodydb.ReadDownloadBatchParams{ID: r.ActiveBatch, SessionID: r.ID})
	if err != nil {
		return s, err
	}
	i, err := decodeHistoricalDownloadIntent(b)
	if err != nil {
		return s, err
	}
	if i.Batch.Authority.Scope != s.Scope || i.Batch.Generation != s.Generation || len(b.OutcomeJson) > 0 {
		return s, privacy.ErrFence
	}
	i.Batch.AuditAcknowledged = b.AuditAcknowledgedAt.Valid
	s.Active = &i.Batch
	return s, nil
}
func updateDownload(ctx context.Context, q *custodydb.Queries, s artifact.DownloadSession) error {
	if !s.Valid() {
		return artifact.ErrInvalid
	}
	var active pgtype.UUID
	if s.Active != nil {
		active = id(s.Active.ID)
	}
	n, err := q.UpdateDownloadSession(ctx, custodydb.UpdateDownloadSessionParams{ID: id(s.ID), RootID: id(s.Scope.RootID), State: string(s.State), ChargedOutput: s.ChargedOutput, ChargedRead: s.ChargedRead, Requests: s.Requests, EmittedBytes: s.EmittedBytes, Generation: s.Generation, ActiveBatch: active})
	if err == nil && n != 1 {
		return privacy.ErrConflict
	}
	return err
}

// Rechecked after blocking locks and before commit. A current permission stream
// and published catalog row are necessary; the external gate additionally owns
// identity, retention shortening, locality and (future) raw/share authority.
func (s *Downloads) downloadFence(ctx context.Context, q *custodydb.Queries, p custodydb.PermissionStream, a artifact.DownloadAuthority, topology privacyvalue.PolicyTopology, recovery custodydb.FleetCurrentTrust) error {
	if err := processingDownloadFence(ctx, q, a); err != nil {
		return err
	}
	if err := s.retention.check(ctx, q, topology, a.Retention, authorization.Target{ClusterID: a.Scope.ClusterID, NamespaceUID: a.Scope.NamespaceUID, WorkloadUID: a.Scope.WorkloadUID, PodUID: a.Scope.PodUID}); err != nil {
		return err
	}
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return err
	}
	if !a.Valid(n.Time) || a.DeleteBy.IsZero() || id(a.Scope.RootID) != p.ID || id(a.PermissionEpoch) != p.Epoch || a.PermissionSequence != p.Sequence || !bytes.Equal(a.ProjectionDigest[:], p.ProjectionDigest) || p.Suspended || !p.InitialAuditID.Valid || !n.Time.Before(p.LeaseUntil.Time) || !identity.Fresh(p.ObservedAt.Time, p.FreshUntil.Time, n.Time, authorization.PermissionObservationInterval) {
		return privacy.ErrFence
	}
	for _, v := range []pgtype.UUID{p.Epoch, p.InitialAuditID} {
		r, err := q.ReadAuthorityAudit(ctx, v)
		if err != nil {
			return err
		}
		if !currentAuthorityAudit(r, p.ID, v) {
			return privacy.ErrFence
		}
	}
	r, err := q.ReadPublishedContext(ctx, custodydb.ReadPublishedContextParams{ArtifactID: id(a.Scope.ArtifactID), RootID: p.ID})
	if err != nil {
		return err
	}
	e, err := currentPublishedContext(r)
	if err != nil || a.Environment.Location != e.Registration.Location || a.Environment.StoreID != e.Registration.StoreID || e.CaptureUID != a.Scope.CaptureID || e.Registration.Location.ArtifactID != a.Scope.ArtifactID || e.Registration.Location.ClusterID != a.Scope.ClusterID || e.NamespaceUID != a.Scope.NamespaceUID || e.WorkloadUID != a.Scope.WorkloadUID || e.PodUID != a.Scope.PodUID || !bytes.Equal(r.ContextVerification.CopiesDigest, a.Scope.Version[:]) || a.AccessUntil.After(r.EffectiveExpiresAt.Time) || a.DeleteBy.After(r.EffectiveDeleteBy.Time) {
		return privacy.ErrFence
	}
	n, err = q.CurrentTime(ctx)
	if err != nil {
		return err
	}
	if !a.Valid(n.Time) || !n.Time.Before(r.EffectiveExpiresAt.Time) {
		return artifact.ErrDownloadExpired
	}
	return s.recovery.check(ctx, q, recovery, a.Scope.RootID, a.Environment.Recovery())
}

func (s *Downloads) ReserveDownload(ctx context.Context, r evidence.DownloadReservation) (artifact.DownloadSession, error) {
	var out artifact.DownloadSession
	request := r.Session
	a := r.Authority
	if !request.Valid() || request.Scope.RootID != s.root || request.Scope != a.Scope || r.IdempotencyDigest == (artifact.Digest{}) || request.State != artifact.DownloadPreparing || request.Active != nil || request.Generation != 0 || request.Requests != 0 || request.ChargedOutput != 0 || request.ChargedRead != 0 || request.EmittedBytes != 0 {
		return out, artifact.ErrInvalid
	}
	topology, err := s.retention.observe(ctx, a.Scope.ClusterID)
	if err != nil {
		return out, err
	}
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		recovery, err := s.recovery.lock(ctx, q, a.Scope.RootID, a.Environment.Recovery())
		if err != nil {
			return err
		}
		p, err := q.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		if err = s.downloadFence(ctx, q, p, a, topology, recovery); err != nil {
			return err
		}
		existing, err := q.FindDownloadSession(ctx, custodydb.FindDownloadSessionParams{RootID: id(s.root), ActorKey: digest(a.Scope.Principal), IdempotencyDigest: r.IdempotencyDigest[:]})
		if err == nil {
			out, err = loadDownload(ctx, q, existing)
			if err != nil {
				return err
			}
			if out.Scope != request.Scope || out.RequestDigest != request.RequestDigest {
				return privacy.ErrConflict
			}
			// The original ID/deadline/spend survive retry and process restart.
			return s.downloadFence(ctx, q, p, a, topology, recovery)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// Replay is decided before consulting the newly proposed allocation.
		// Configuration rotation cannot replace or increase the original spend.
		allocation, err := q.LockDownloadAllocation(ctx, custodydb.LockDownloadAllocationParams{ID: id(request.AllocationID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		budget := downloadAllocation(allocation)
		if !budget.Valid() || !budget.Covers(request.Scope) || request.Deadline.After(budget.ValidUntil) || request.Deadline.After(a.AccessUntil) {
			return privacy.ErrFence
		}
		if request.OutputLimit > budget.OutputLimit-allocation.ReservedOutput || request.ReadLimit > budget.ReadLimit-allocation.ReservedRead || allocation.ReservedSessions >= budget.SessionLimit {
			return artifact.ErrDownloadCapacity
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !now.Time.Before(request.Deadline) || request.Deadline.After(now.Time.Add(8*time.Hour)) {
			return artifact.ErrDownloadExpired
		}
		encoded, err := json.Marshal(request.Scope)
		if err != nil {
			return artifact.ErrInvalid
		}
		row, err := q.InsertDownloadSession(ctx, custodydb.InsertDownloadSessionParams{ID: id(request.ID), RootID: id(s.root), AllocationID: id(request.AllocationID), ArtifactID: id(request.Scope.ArtifactID), PrincipalKey: principalKey(request.Scope.Principal), ActorKey: digest(request.Scope.Principal), IdempotencyDigest: r.IdempotencyDigest[:], RequestDigest: request.RequestDigest[:], ScopeJson: encoded, Deadline: ts(request.Deadline), OutputLimit: request.OutputLimit, ReadLimit: request.ReadLimit, RequestLimit: request.RequestLimit, StopProtocol: pgtype.Text{String: request.StopProtocol, Valid: request.StopProtocol != ""}})
		if err != nil {
			return err
		}
		if _, err = q.ChargeDownloadAllocation(ctx, custodydb.ChargeDownloadAllocationParams{ID: allocation.ID, RootID: allocation.RootID, ReservedOutput: request.OutputLimit, ReservedRead: request.ReadLimit}); err != nil {
			return err
		}
		out, err = decodeDownload(row)
		if err != nil {
			return err
		}
		return s.downloadFence(ctx, q, p, a, topology, recovery)
	})
	if err != nil {
		return artifact.DownloadSession{}, err
	}
	return out, nil
}

func (s *Downloads) LookupDownload(ctx context.Context, sessionID string, actor identity.Principal) (artifact.DownloadSession, error) {
	var out artifact.DownloadSession
	if !authorization.UUID(sessionID) || !actor.Valid() {
		return out, artifact.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		r, err := q.ReadDownloadSession(ctx, custodydb.ReadDownloadSessionParams{ID: id(sessionID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		if !bytes.Equal(r.ActorKey, digest(actor)) {
			return artifact.ErrDownloadUnavailable
		}
		out, err = loadDownload(ctx, q, r)
		if err != nil {
			return err
		}
		if out.Scope.Principal != actor {
			return artifact.ErrDownloadUnavailable
		}
		return nil
	})
	if err != nil {
		return artifact.DownloadSession{}, err
	}
	return out, nil
}

func (s *Downloads) BeginDownloadBatch(ctx context.Context, sessionID string, a artifact.DownloadAuthority, b artifact.DownloadBatch) (audit.DownloadIntent, error) {
	return s.beginDownloadBatch(ctx, sessionID, a, b, false)
}

func (s *Downloads) beginDownloadBatch(ctx context.Context, sessionID string, a artifact.DownloadAuthority, b artifact.DownloadBatch, firstContext bool) (audit.DownloadIntent, error) {
	a.CheckedAt = a.CheckedAt.UTC()
	a.ValidUntil = a.ValidUntil.UTC()
	a.AccessUntil = a.AccessUntil.UTC()
	var out audit.DownloadIntent
	if !authorization.UUID(sessionID) || a.Scope.RootID != s.root {
		return out, artifact.ErrInvalid
	}
	topology, err := s.retention.observe(ctx, a.Scope.ClusterID)
	if err != nil {
		return out, err
	}
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		recovery, err := s.recovery.lock(ctx, q, a.Scope.RootID, a.Environment.Recovery())
		if err != nil {
			return err
		}
		p, err := q.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		r, err := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(sessionID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		current, err := loadDownload(ctx, q, r)
		if err != nil {
			return err
		}
		if err = s.downloadFence(ctx, q, p, a, topology, recovery); err != nil {
			return err
		}
		// A repeated batch ID is deliberately NOT a second writer permit. Lost
		// SQL replies remain charged and recover through status + fresh batch.
		streams, err := q.DownloadStreams(ctx, custodydb.DownloadStreamsParams{RootID: id(s.root), PrincipalKey: principalKey(a.Scope.Principal)})
		if err != nil {
			return err
		}
		if streams.Total >= 16 || streams.Principal >= 2 {
			return artifact.ErrDownloadCapacity
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if err = responseBusy(ctx, q, current, now.Time); err != nil {
			return err
		}
		// The explicit first-context composition has one preparation attempt.
		// This check is serialized with the actual charge, never a prior read
		// or a boolean supplied by an HTTP/MCP request. Unknown commits remain
		// spent after expiry; generic paid re-preparation retains its contract.
		if firstContext && !firstContextPreparation(current, b) {
			return artifact.ErrDownloadConflict
		}
		current, err = current.Start(a, b, now.Time.UTC())
		if err != nil {
			return err
		}
		current.Active.LeaseUntil = current.Active.LeaseUntil.UTC().Truncate(time.Microsecond)
		out = audit.DownloadIntent{SessionID: sessionID, Batch: *current.Active}
		if !out.Valid() {
			return artifact.ErrInvalid
		}
		encoded, err := json.Marshal(out)
		if err != nil {
			return artifact.ErrInvalid
		}
		if _, err = q.InsertDownloadBatch(ctx, custodydb.InsertDownloadBatchParams{ID: id(out.Batch.ID), SessionID: r.ID, Generation: out.Batch.Generation, IntentJson: encoded, LeaseUntil: ts(out.Batch.LeaseUntil)}); err != nil {
			return err
		}
		if err = updateDownload(ctx, q, current); err != nil {
			return err
		}
		return s.downloadFence(ctx, q, p, a, topology, recovery)
	})
	if err != nil {
		return audit.DownloadIntent{}, err
	}
	return out, nil
}

func (s *Downloads) PermitDownloadBatch(ctx context.Context, sessionID string, a artifact.DownloadAuthority, batchID string, generation int64) error {
	if !authorization.UUID(sessionID) || !authorization.UUID(batchID) || a.Scope.RootID != s.root {
		return artifact.ErrInvalid
	}
	topology, err := s.retention.observe(ctx, a.Scope.ClusterID)
	if err != nil {
		return err
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		recovery, err := s.recovery.lock(ctx, q, a.Scope.RootID, a.Environment.Recovery())
		if err != nil {
			return err
		}
		p, err := q.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		r, err := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(sessionID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		current, err := loadDownload(ctx, q, r)
		if err != nil {
			return err
		}
		if err = s.downloadFence(ctx, q, p, a, topology, recovery); err != nil {
			return err
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		return current.Permit(a, batchID, generation, n.Time)
	})
}

func (s *Downloads) FinishDownloadBatch(ctx context.Context, sessionID, batchID string, generation, emitted int64, success, full bool) (audit.DownloadOutcome, error) {
	var out audit.DownloadOutcome
	if !authorization.UUID(sessionID) || !authorization.UUID(batchID) {
		return out, artifact.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		r, err := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(sessionID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		current, err := loadHistoricalDownload(ctx, q, r)
		if err != nil {
			return err
		}
		b, err := q.LockDownloadBatch(ctx, custodydb.LockDownloadBatchParams{ID: id(batchID), SessionID: r.ID})
		if err != nil {
			return err
		}
		i, err := decodeHistoricalDownloadIntent(b)
		if err != nil {
			return err
		}
		if generation != b.Generation || i.Batch.Authority.Scope != current.Scope || !b.AuditAcknowledgedAt.Valid && (emitted != 0 || success) {
			return privacy.ErrConflict
		}
		if len(b.OutcomeJson) > 0 {
			if json.Unmarshal(b.OutcomeJson, &out) != nil || !out.Valid() || !out.Intent.Equal(i) || out.EmittedBytes != emitted || out.Success != success || out.FullFile != full {
				return privacy.ErrConflict
			}
			return nil
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		out = audit.DownloadOutcome{Intent: i, EmittedBytes: emitted, Success: success, FullFile: full, RecordedAt: n.Time.UTC()}
		if !out.Valid() {
			return artifact.ErrInvalid
		}
		if current.Active != nil && current.Active.ID == batchID {
			before := current.State
			current, err = current.Finish(batchID, generation, emitted, success, full, n.Time)
			if err != nil {
				return err
			}
			if !current.State.Terminal() || current.State == artifact.DownloadCompleted {
				current.State = before
			} // outcome audit gates Ready/Completed
		} else {
			current.EmittedBytes += emitted
		} // old outcome cannot take over a new writer
		encoded, err := json.Marshal(out)
		if err != nil {
			return artifact.ErrInvalid
		}
		if _, err = q.SetDownloadOutcome(ctx, custodydb.SetDownloadOutcomeParams{ID: b.ID, SessionID: r.ID, OutcomeJson: encoded}); err != nil {
			return err
		}
		return updateDownload(ctx, q, current)
	})
	if err != nil {
		return audit.DownloadOutcome{}, err
	}
	return out, nil
}

// Metadata leaves the regional worker only after its exact read outcome audit.
// This gate does not reopen the completed acquisition batch or permit file bytes.
func (s *Downloads) PermitDownloadMetadata(ctx context.Context, sessionID string, a artifact.DownloadAuthority, batchID string, generation int64) error {
	if !authorization.UUID(sessionID) || !authorization.UUID(batchID) || a.Scope.RootID != s.root {
		return artifact.ErrInvalid
	}
	topology, err := s.retention.observe(ctx, a.Scope.ClusterID)
	if err != nil {
		return err
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		recovery, err := s.recovery.lock(ctx, q, a.Scope.RootID, a.Environment.Recovery())
		if err != nil {
			return err
		}
		p, err := q.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		r, err := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(sessionID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		current, err := loadDownload(ctx, q, r)
		if err != nil {
			return err
		}
		if current.Scope != a.Scope || current.Generation != generation || current.Active != nil || current.State != artifact.DownloadReady {
			return privacy.ErrFence
		}
		b, err := q.ReadDownloadBatch(ctx, custodydb.ReadDownloadBatchParams{ID: id(batchID), SessionID: r.ID})
		if err != nil {
			return err
		}
		i, err := decodeDownloadIntent(b)
		if err != nil {
			return err
		}
		var outcome audit.DownloadOutcome
		var receipt audit.Receipt
		if i.Batch.Generation != generation || i.Batch.Purpose != artifact.DownloadMetadata || !b.AuditAcknowledgedAt.Valid || !b.OutcomeAcknowledgedAt.Valid || json.Unmarshal(b.OutcomeJson, &outcome) != nil || !outcome.Valid() || !outcome.Intent.Equal(i) || !outcome.Success || json.Unmarshal(b.OutcomeReceiptJson, &receipt) != nil || !receipt.ValidDownload(s.root, sessionID, batchID, "outcome") {
			return privacy.ErrFence
		}
		if err = s.downloadFence(ctx, q, p, a, topology, recovery); err != nil {
			return err
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !n.Time.Before(current.Deadline) || !n.Time.Before(i.Batch.LeaseUntil) {
			return artifact.ErrDownloadExpired
		}
		return nil
	})
}

func (s *Downloads) CancelDownload(ctx context.Context, sessionID string, actor identity.Principal) (artifact.DownloadSession, error) {
	var out artifact.DownloadSession
	if !authorization.UUID(sessionID) || !actor.Valid() {
		return out, artifact.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		r, err := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(sessionID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		if !bytes.Equal(r.ActorKey, digest(actor)) {
			return artifact.ErrDownloadUnavailable
		}
		out, err = loadHistoricalDownload(ctx, q, r)
		if err != nil {
			return err
		}
		if out.Scope.Principal != actor {
			return artifact.ErrDownloadUnavailable
		}
		out, err = out.Cancel()
		if err != nil {
			return err
		}
		return updateDownload(ctx, q, out)
	})
	if err != nil {
		return artifact.DownloadSession{}, err
	}
	return out, nil
}

func (s *Downloads) AcknowledgeDownloadIntent(ctx context.Context, i audit.DownloadIntent, receipt audit.Receipt) error {
	if !i.Valid() || i.Batch.Authority.Scope.RootID != s.root || !receipt.ValidDownload(s.root, i.SessionID, i.Batch.ID, "intent") {
		return artifact.ErrInvalid
	}
	return s.ackDownload(ctx, i, nil, receipt)
}
func (s *Downloads) AcknowledgeDownloadOutcome(ctx context.Context, o audit.DownloadOutcome, receipt audit.Receipt) error {
	if !o.Valid() || o.Intent.Batch.Authority.Scope.RootID != s.root || !receipt.ValidDownload(s.root, o.Intent.SessionID, o.Intent.Batch.ID, "outcome") {
		return artifact.ErrInvalid
	}
	return s.ackDownload(ctx, o.Intent, &o, receipt)
}
func (s *Downloads) ackDownload(ctx context.Context, i audit.DownloadIntent, outcome *audit.DownloadOutcome, receipt audit.Receipt) error {
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		// Same session-before-batch lock order as cancellation and completion.
		r, err := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(i.SessionID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		b, err := q.LockDownloadBatch(ctx, custodydb.LockDownloadBatchParams{ID: id(i.Batch.ID), SessionID: r.ID})
		if err != nil {
			return err
		}
		frozen, err := decodeDownloadIntent(b)
		if err != nil {
			return err
		}
		if !frozen.Equal(i) {
			return privacy.ErrConflict
		}
		ack, existing := b.AuditAcknowledgedAt.Valid, b.AuditReceiptJson
		if outcome != nil {
			var old audit.DownloadOutcome
			if json.Unmarshal(b.OutcomeJson, &old) != nil || !old.Equal(*outcome) {
				return privacy.ErrConflict
			}
			ack, existing = b.OutcomeAcknowledgedAt.Valid, b.OutcomeReceiptJson
		}
		if ack {
			var old audit.Receipt
			if json.Unmarshal(existing, &old) != nil || old != receipt {
				return privacy.ErrConflict
			}
			return nil
		}
		encoded, err := json.Marshal(receipt)
		if err != nil {
			return artifact.ErrInvalid
		}
		if outcome == nil {
			_, err = q.AcknowledgeDownloadIntent(ctx, custodydb.AcknowledgeDownloadIntentParams{ID: b.ID, SessionID: r.ID, AuditReceiptJson: encoded})
		} else {
			_, err = q.AcknowledgeDownloadOutcome(ctx, custodydb.AcknowledgeDownloadOutcomeParams{ID: b.ID, SessionID: r.ID, OutcomeReceiptJson: encoded})
			if err == nil && r.Generation == outcome.Intent.Batch.Generation && !r.ActiveBatch.Valid && !artifact.DownloadState(r.State).Terminal() {
				next := artifact.DownloadState(r.State)
				n, e := q.CurrentTime(ctx)
				if e != nil {
					return e
				}
				if !n.Time.Before(r.Deadline.Time) {
					next = artifact.DownloadExpired
				} else if outcome.Intent.Batch.Purpose == artifact.DownloadMetadata && outcome.Success {
					next = artifact.DownloadReady
				} else if outcome.Intent.Batch.Purpose == artifact.DownloadContent {
					if outcome.Success && outcome.FullFile {
						next = artifact.DownloadCompleted
					} else {
						next = artifact.DownloadInterrupted
					}
				}
				_, err = q.AcknowledgeDownloadState(ctx, custodydb.AcknowledgeDownloadStateParams{ID: r.ID, RootID: r.RootID, State: string(next)})
			}
		}
		return err
	})
}
