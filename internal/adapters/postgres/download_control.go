package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

var _ evidence.ContextDownloadControlLedger = (*Downloads)(nil)
var _ evidence.ContextDownloadRoutes = (*Downloads)(nil)
var _ evidence.ContextDownloadSources = (*Downloads)(nil)

func downloadQueryScopes(i identity.Identity) bool {
	return slices.Contains(i.Scopes, "evidence:read") && slices.Contains(i.Scopes, "evidence:download")
}
func downloadObservationDeadline(ctx context.Context, first time.Time, bounds ...time.Time) time.Time {
	until := first.Add(artifact.DownloadLease)
	for _, b := range bounds {
		until = identity.Earlier(until, b)
	}
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	return until
}

// The minimized published-only locator is private routing, not evidence access.
// Ordinary target eligibility precedes the separate authorized source read.
func (s *Downloads) ResolveContextDownload(ctx context.Context, request artifact.DownloadRouteQuery) (artifact.DownloadRoute, error) {
	var out artifact.DownloadRoute
	if s == nil || ctx == nil || ctx.Err() != nil || !downloadQueryScopes(request.Identity) {
		return out, artifact.ErrDownloadUnavailable
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		first, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !request.Valid(first.Time) {
			return sqlStep{"request", artifact.ErrDownloadUnavailable}
		}
		recovery, err := s.recovery.lock(ctx, q, s.root, request.Recovery)
		if err != nil {
			return sqlStep{"recovery-lock", err}
		}
		row, err := q.ReadContextDownloadRoute(ctx, custodydb.ReadContextDownloadRouteParams{RootID: id(s.root), ArtifactID: id(request.ArtifactID)})
		if err != nil || len(row.CopiesDigest) != 32 {
			return sqlStep{"row", artifact.ErrDownloadUnavailable}
		}
		scope := artifact.DownloadScope{RootID: uid(row.RootID), ArtifactID: uid(row.ArtifactID), CaptureID: uid(row.CaptureID), ClusterID: uid(row.ClusterID), NamespaceUID: row.NamespaceUid, WorkloadUID: row.WorkloadUid, PodUID: row.PodUid, Principal: request.Identity.Principal, Version: artifact.Digest(row.CopiesDigest)}
		out = artifact.DownloadRoute{Scope: scope, ObservedAt: first.Time, ValidUntil: downloadObservationDeadline(ctx, first.Time, request.Identity.ValidUntil, request.Recovery.FreshUntil)}
		if scope.RootID != s.root || scope.ArtifactID != request.ArtifactID {
			return sqlStep{"scope", artifact.ErrDownloadUnavailable}
		}
		if err = s.recovery.check(ctx, q, recovery, s.root, request.Recovery); err != nil {
			return sqlStep{"recovery-check", err}
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !request.Valid(now.Time) || !out.Valid(now.Time) {
			return sqlStep{"final", artifact.ErrDownloadUnavailable}
		}
		return ctx.Err()
	})
	if err != nil || ctx.Err() != nil {
		// The closed stage, never the dependency error, is retained for the
		// operator report.
		var stage interface{ FixedStep() string }
		if errors.As(err, &stage) {
			return artifact.DownloadRoute{}, sqlStep{stage.FixedStep(), artifact.ErrDownloadUnavailable}
		}
		return artifact.DownloadRoute{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}

// This lookup returns no current metadata authority and never treats failure as
// absence. The actor/client/key is rechecked atomically by ReserveDownload.
func (s *Downloads) LookupDownloadKey(ctx context.Context, request artifact.DownloadKeyQuery) (artifact.DownloadKeyLookup, error) {
	var out artifact.DownloadKeyLookup
	if s == nil || ctx == nil || ctx.Err() != nil || !downloadQueryScopes(request.Identity) {
		return out, artifact.ErrDownloadUnavailable
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		first, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !request.Valid(first.Time) {
			return artifact.ErrDownloadUnavailable
		}
		recovery, err := s.recovery.lock(ctx, q, s.root, request.Recovery)
		if err != nil {
			return err
		}
		row, err := q.FindDownloadSession(ctx, custodydb.FindDownloadSessionParams{RootID: id(s.root), ActorKey: digest(request.Identity.Principal), IdempotencyDigest: request.Key[:]})
		out = artifact.DownloadKeyLookup{ObservedAt: first.Time, ValidUntil: downloadObservationDeadline(ctx, first.Time, request.Identity.ValidUntil, request.Recovery.FreshUntil)}
		if err == nil {
			out.Found = true
			out.Session, err = loadDownload(ctx, q, row)
			if err != nil {
				return err
			}
			if out.Session.Scope.RootID != s.root || out.Session.Scope.Principal != request.Identity.Principal {
				return artifact.ErrDownloadUnavailable
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err = s.recovery.check(ctx, q, recovery, s.root, request.Recovery); err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !request.Valid(now.Time) || !out.Valid(now.Time) {
			return artifact.ErrDownloadUnavailable
		}
		return ctx.Err()
	})
	if err != nil || ctx.Err() != nil {
		return artifact.DownloadKeyLookup{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}

// No native evidence or keys are read. The current authority precedes access to
// original accepted provenance and exact verified ciphertext object receipts.
func (s *Downloads) ReadContextDownloadSource(ctx context.Context, a artifact.DownloadAuthority) (evidence.ContextDownloadSource, error) {
	var out evidence.ContextDownloadSource
	if s == nil || ctx == nil || ctx.Err() != nil || a.Scope.RootID != s.root {
		return out, artifact.ErrDownloadUnavailable
	}
	topology, err := s.retention.observe(ctx, a.Scope.ClusterID)
	if err != nil {
		return out, err
	}
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		first, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		recovery, err := s.recovery.lock(ctx, q, s.root, a.Environment.Recovery())
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
		row, err := q.ReadPublishedContext(ctx, custodydb.ReadPublishedContextParams{ArtifactID: id(a.Scope.ArtifactID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		capture := row.ContextCapture
		expected, err := currentPublishedContext(row)
		if err != nil {
			return err
		}
		attempt, err := q.ReadAttempt(ctx, capture.AttemptID)
		if err != nil {
			return err
		}
		stored, err := record(ctx, q, attempt, expected.Registration.StoreID)
		if err != nil {
			return err
		}
		if stored.State != artifact.StoredUnpublished || !stored.Registration.Equal(expected.Registration) || stored.Copies.Validate(expected.Registration) != nil || !bytes.Equal(attempt.CopiesDigest, row.ContextVerification.CopiesDigest) || evidence.ContextCopiesDigest(stored.Copies) != a.Scope.Version {
			return privacy.ErrFence
		}
		out = evidence.ContextDownloadSource{Scope: a.Scope, Expectation: expected, Copies: stored.Copies, ObservedAt: first.Time, ValidUntil: downloadObservationDeadline(ctx, first.Time, a.ValidUntil)}
		if err = s.downloadFence(ctx, q, p, a, topology, recovery); err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !out.Valid(now.Time) {
			return artifact.ErrDownloadUnavailable
		}
		return ctx.Err()
	})
	if err != nil || ctx.Err() != nil {
		return evidence.ContextDownloadSource{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}

// ObserveDownload supplies a NEW bounded status observation, not a renewed
// acquisition lease. A historical successful preparation may support later
// generations/Completed metadata, but never authorize another byte or key read.
func (s *Downloads) ObserveDownload(ctx context.Context, sessionID string, a artifact.DownloadAuthority, preparation *artifact.DownloadPreparation) (artifact.DownloadObservation, error) {
	var out artifact.DownloadObservation
	if s == nil || ctx == nil || ctx.Err() != nil || a.Scope.RootID != s.root {
		return out, artifact.ErrDownloadUnavailable
	}
	if preparation != nil {
		copy := *preparation
		preparation = &copy
		if !preparation.Valid() || preparation.SessionID != sessionID {
			return out, artifact.ErrInvalid
		}
	}
	topology, err := s.retention.observe(ctx, a.Scope.ClusterID)
	if err != nil {
		return out, err
	}
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		first, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		recovery, err := s.recovery.lock(ctx, q, s.root, a.Environment.Recovery())
		if err != nil {
			return err
		}
		p, err := q.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		row, err := q.LockDownloadSession(ctx, custodydb.LockDownloadSessionParams{ID: id(sessionID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		session, err := loadDownload(ctx, q, row)
		if err != nil {
			return err
		}
		if session.Scope != a.Scope {
			return privacy.ErrFence
		}
		if err = s.downloadFence(ctx, q, p, a, topology, recovery); err != nil {
			return err
		}
		if preparation != nil {
			b, err := q.ReadDownloadBatch(ctx, custodydb.ReadDownloadBatchParams{ID: id(preparation.BatchID), SessionID: row.ID})
			if err != nil {
				return err
			}
			i, err := decodeDownloadIntent(b)
			if err != nil {
				return err
			}
			var outcome audit.DownloadOutcome
			var receipt audit.Receipt
			if i.SessionID != sessionID || i.Batch.Authority.Scope != session.Scope || i.Batch.Generation != preparation.Generation || i.Batch.Generation > session.Generation || i.Batch.Purpose != artifact.DownloadMetadata || !b.AuditAcknowledgedAt.Valid || !b.OutcomeAcknowledgedAt.Valid || json.Unmarshal(b.OutcomeJson, &outcome) != nil || !outcome.Valid() || !outcome.Intent.Equal(i) || !outcome.Success || outcome.EmittedBytes != 0 || outcome.FullFile || json.Unmarshal(b.OutcomeReceiptJson, &receipt) != nil || !receipt.ValidDownload(s.root, sessionID, preparation.BatchID, "outcome") {
				return privacy.ErrFence
			}
		}
		out = artifact.DownloadObservation{Session: session, ObservedAt: first.Time, ValidUntil: downloadObservationDeadline(ctx, first.Time, a.ValidUntil)}
		if err = s.downloadFence(ctx, q, p, a, topology, recovery); err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		// Expiry is a read projection only. Preserve completed/cancelled facts
		// and every durable counter, active batch and original deadline.
		out.Session.State = out.Session.ObservedState(now.Time)
		if !out.Valid(now.Time) {
			return artifact.ErrDownloadExpired
		}
		return ctx.Err()
	})
	if err != nil || ctx.Err() != nil {
		return artifact.DownloadObservation{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}
