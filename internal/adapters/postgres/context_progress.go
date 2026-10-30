package postgres

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	executionvalue "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContextProgressReads has no effect or evidence-disclosure methods. Its SQL
// credential can only read and take the existing recovery/permission root locks.
type ContextProgressReads struct {
	ledger   *Ledger
	root     string
	recovery *RecoveryTransactionGuard
}

var _ app.ContextProgressReader = (*ContextProgressReads)(nil)

func NewContextProgressReads(ctx context.Context, pool *pgxpool.Pool, root string, recovery *RecoveryTransactionGuard) (*ContextProgressReads, error) {
	if !authorization.UUID(root) || recovery == nil || recovery.root != root {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &ContextProgressReads{ledger: l, root: root, recovery: recovery}, nil
}

// progressFacts projects a single MVCC snapshot of immutable admission, custody,
// verified outcome, durable encrypted audit acknowledgement and publication.
// It deliberately makes no claim that admission implies collector execution.
func progressFacts(f custodydb.ReadContextProgressFactsRow, executions ...executionvalue.APIExecution) (value.ContextProgressObservation, error) {
	var out value.ContextProgressObservation
	c := f.ContextCapture
	accepted, err := admittedRecord(c)
	if err != nil {
		return out, value.ErrUnavailable
	}
	intent, err := captureIntent(c)
	if err != nil {
		return out, value.ErrUnavailable
	}
	if c.ProgressRevision < 1 || c.ProgressRevision > value.MaxProgressRevision || !bytes.Equal(f.RequestDigest, digest(normalized(accepted.Expectation.Registration))) {
		return out, value.ErrUnavailable
	}
	out = value.ContextProgressObservation{CaptureID: accepted.CaptureID, CandidateCaseID: accepted.Expectation.CaseID, CandidateArtifactID: accepted.Expectation.Registration.Location.ArtifactID, Target: intent.Target, Revision: c.ProgressRevision, CreatedAt: accepted.CreatedAt, Deadline: accepted.Deadline, Phase: "Pending", ActionPhase: "Pending", ReasonCode: "IntentAuditPending"}
	out.Operation, out.ActionID = "collect", accepted.Expectation.ActionID
	if e := accepted.Expectation; e.Snapshot != nil && e.Lifecycle != nil && e.Lifecycle.TriggerKind == "recordingSave" {
		out.Operation = "recordingSave"
	}
	if out.ShareID, err = captureShareID(c.ShareInstruction); err != nil {
		return out, err
	}
	audited := c.State == value.IntentAudited
	if audited {
		if _, err = historicalPublication(c); err != nil {
			return value.ContextProgressObservation{}, value.ErrUnavailable
		}
		out.ReasonCode = "DispatchUnconfirmed"
	}
	out.CancellationRequested = c.SnapshotCancelRequestedAt.Valid
	if c.SnapshotCancelJoinedAt.Valid {
		out.Phase, out.ActionPhase, out.ReasonCode = "Cancelled", "Cancelled", "CancellationJoined"
		return out, nil
	}
	out.CanCancel = accepted.Expectation.Snapshot != nil && !out.CancellationRequested && !f.CatalogArtifactID.Valid && (len(executions) == 0 || executions[0].Phase == "prepared" || executions[0].Phase == "started")
	verified := f.VerifiedCaptureID.Valid
	if verified {
		v := custodydb.ContextVerification{CaptureID: f.VerifiedCaptureID, RootID: f.VerifiedRootID, VerifiedAt: f.VerifiedAt, ExpectationDigest: f.ExpectationDigest, CopiesDigest: f.VerifiedCopiesDigest, IntentDigest: f.VerifiedIntentDigest, AuthorityDigest: f.AuthorityDigest, PermissionEpoch: f.PermissionEpoch, PermissionSequence: f.PermissionSequence.Int64}
		record, err := verificationRecord(c, v, executions...)
		if err != nil || !f.PermissionSequence.Valid || !bytes.Equal(f.CopiesDigest, f.VerifiedCopiesDigest) {
			return value.ContextProgressObservation{}, value.ErrUnavailable
		}
		if f.AuditAcknowledgedAt.Valid && (!bytes.Equal(f.AuditDigest, digest(record)) || f.AuditAcknowledgedAt.Time.Before(f.VerifiedAt.Time)) {
			return value.ContextProgressObservation{}, value.ErrUnavailable
		}
	}
	if f.CatalogArtifactID.Valid || f.PublishedAt.Valid {
		if !verified || !f.AuditAcknowledgedAt.Valid || uid(f.CatalogArtifactID) != out.CandidateArtifactID || !f.PublishedAt.Valid || f.PublishedAt.Time.Before(f.AuditAcknowledgedAt.Time) || !f.PublishedAt.Time.Before(accepted.Expectation.Registration.WriteUntil) {
			return value.ContextProgressObservation{}, value.ErrUnavailable
		}
		out.Phase = "Succeeded"
		out.ActionPhase = "Succeeded"
		out.ReasonCode = "Published"
		return out, nil // historical outcome; never current evidence access
	}
	if len(executions) > 0 {
		if len(executions) != 1 || !executions[0].Valid() || executions[0].Binding.CaptureID != accepted.CaptureID || executions[0].ExpectationDigest != evidence.ContextExpectationDigest(accepted.Expectation) {
			return value.ContextProgressObservation{}, value.ErrUnavailable
		}
		switch executions[0].Phase {
		case "prepared":
			// The regional preparation is recorded, but no acquisition start is:
			// dispatch remains unconfirmed until the start is recorded.
			out.Phase = "Pending"
			out.ActionPhase = "Pending"
			out.ReasonCode = "DispatchUnconfirmed"
		case "started":
			out.Phase = "Running"
			out.ActionPhase = "Running"
			out.ReasonCode = "AcquisitionStarted"
		case "captureFailed":
			out.Phase = "Failed"
			out.ActionPhase = "Failed"
			out.ReasonCode = "AcquisitionFailed"
			return out, nil
		case "targetGone":
			out.Phase = "Failed"
			out.ActionPhase = "TargetGone"
			out.ReasonCode = "PinnedPodGone"
			return out, nil
		case "denied":
			out.Phase = "Failed"
			out.ActionPhase = "Denied"
			out.ReasonCode = "PodStatusDenied"
			return out, nil
		case "storeUnconfirmed":
			out.Phase = "Indeterminate"
			out.ActionPhase = "Indeterminate"
			out.ReasonCode = "StorageOutcomeUnconfirmed"
			return out, nil
		case "cancelled":
			out.Phase, out.ActionPhase, out.ReasonCode = "Cancelled", "Cancelled", "CancellationJoined"
			return out, nil
		case "stored":
			out.Phase = "Finalizing"
			out.ActionPhase = "Finalizing"
			out.ReasonCode = "VerificationPending"
		default:
			return value.ContextProgressObservation{}, value.ErrUnavailable
		}
	}
	if c.DeadlineObservedAt.Valid {
		if c.DeadlineObservedAt.Time.Before(out.Deadline) {
			return value.ContextProgressObservation{}, value.ErrUnavailable
		}
		out.Phase = "Indeterminate"
		out.ActionPhase = "Indeterminate"
		out.ReasonCode = "DeadlineOutcomeUnconfirmed"
	} else if verified || f.CustodyState == artifact.StoredUnpublished {
		if !audited || len(f.CopiesDigest) != 32 {
			return value.ContextProgressObservation{}, value.ErrUnavailable
		}
		out.Phase = "Finalizing"
		out.ActionPhase = "Finalizing"
		out.ReasonCode = "VerificationPending"
		if verified {
			out.ReasonCode = "VerificationAuditPending"
			if f.AuditAcknowledgedAt.Valid {
				out.ReasonCode = "PublicationPending"
			}
		}
	}
	return out, nil
}

func (s *ContextProgressReads) ReadContextProgress(ctx context.Context, request value.ProgressQuery) (value.ContextProgressObservation, error) {
	var out value.ContextProgressObservation
	if s == nil || s.ledger == nil || request.RootID != s.root || !authorization.UUID(request.CaptureID) || !request.Identity.Valid(request.Identity.VerifiedAt) || !request.Recovery.Valid(request.Recovery.ObservedAt) {
		return out, value.ErrInvalid
	}
	request.Identity.Groups = slices.Clone(request.Identity.Groups)
	request.Identity.Scopes = slices.Clone(request.Identity.Scopes)
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = value.ContextProgressObservation{} // definitely-aborted transaction retry
		recovery, err := s.recovery.lock(ctx, q, s.root, request.Recovery)
		if err != nil {
			return err
		}
		stream, err := q.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		first, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !request.Valid(first.Time) {
			return value.ErrDenied
		}
		// This routing-only lookup provides no outward fields. Existence and access
		// denial have the same result; lifecycle joins happen only after eligibility.
		c, err := q.ReadPublicationCapture(ctx, custodydb.ReadPublicationCaptureParams{ID: id(request.CaptureID), RootID: id(s.root)})
		if errors.Is(err, pgx.ErrNoRows) {
			return value.ErrDenied
		}
		if err != nil {
			return err
		}
		intent, err := captureIntent(c)
		if err != nil {
			return value.ErrDenied
		}
		projection, err := permissionProjection(ctx, q, stream, intent.Target)
		if err != nil {
			return value.ErrDenied
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		eligible := authorization.CaptureProgressEligibility(request.Identity, projection, intent.Target, intent.Requester(), n.Time)
		if !eligible.Eligible {
			return value.ErrDenied
		}
		f, err := q.ReadContextProgressFacts(ctx, custodydb.ReadContextProgressFactsParams{ID: c.ID, RootID: c.RootID})
		if err != nil {
			return err
		}
		if !bytes.Equal(f.ContextCapture.ScopeDigest, c.ScopeDigest) || !bytes.Equal(f.ContextCapture.ExpectationJson, c.ExpectationJson) {
			return value.ErrUnavailable
		}
		var executions []executionvalue.APIExecution
		if accepted, decodeErr := admittedRecord(c); decodeErr != nil {
			return decodeErr
		} else if accepted.Expectation.ExecutionClass == artifact.ContextAPIExecution {
			row, readErr := q.ReadAPIExecution(ctx, custodydb.ReadAPIExecutionParams{RootID: c.RootID, CaptureID: c.ID})
			if readErr == nil {
				x, decodeErr := apiExecution(row)
				if decodeErr != nil {
					return decodeErr
				}
				executions = append(executions, x)
			} else if !errors.Is(readErr, pgx.ErrNoRows) {
				return readErr
			}
		}
		out, err = progressFacts(f, executions...)
		if err != nil {
			return err
		}
		if c.RepeatedFromCaptureID.Valid && n.Time.Before(c.RepeatedFromExpiresAt.Time) {
			accepted, e := admittedRecord(c)
			if e != nil {
				return e
			}
			historical := authorization.CaptureHistoryEligibility(request.Identity, projection, intent.Target, intent.Requester(), accepted.Expectation.Audience, n.Time)
			if historical.Eligible {
				out.RepeatedFrom = &value.HistoryLineage{CaptureID: uid(c.RepeatedFromCaptureID), ExpiresAt: c.RepeatedFromExpiresAt.Time}
			}
		}
		if c.HistoryParametersRequired {
			out.HistoryState = "unavailable"
			if f.HistoryParametersState.String == "available" && f.HistoryCustodyState.String == artifact.StoredUnpublished && f.HistoryVisible.Bool && n.Time.Before(f.HistorySummaryExpires.Time) && n.Time.Before(f.HistorySettingsExpires.Time) {
				out.HistoryState = "available"
			}
		}
		out.ObservedAt = first.Time
		out.ValidUntil = identity.Earlier(first.Time.Add(5*time.Second), identity.Earlier(eligible.ValidUntil, request.Recovery.FreshUntil))
		if err = s.recovery.check(ctx, q, recovery, s.root, request.Recovery); err != nil {
			return err
		}
		n, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !request.Valid(n.Time) || !n.Time.Before(eligible.ValidUntil) || !out.Valid(n.Time) {
			return value.ErrDenied
		}
		return ctx.Err()
	})
	if err != nil {
		return value.ContextProgressObservation{}, captureError(err)
	}
	return out, nil
}

// ContextDeadlines has a distinct column-scoped SQL role. The bounded observer
// records uncertainty after an original deadline; no GET mutates history and no
// marker cancels work, proves quiescence or returns storage/permit capacity.
type ContextDeadlines struct {
	ledger *Ledger
	root   string
}

var _ app.ContextDeadlineObserver = (*ContextDeadlines)(nil)

func NewContextDeadlineObserver(ctx context.Context, pool *pgxpool.Pool, root string) (*ContextDeadlines, error) {
	if !authorization.UUID(root) {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &ContextDeadlines{ledger: l, root: root}, nil
}
func (s *ContextDeadlines) ObserveOverdueContextCaptures(ctx context.Context, limit int) (int64, error) {
	if s == nil || s.ledger == nil {
		return 0, value.ErrUnavailable
	}
	if limit < 1 || limit > 16 {
		return 0, value.ErrInvalid
	}
	var count int64
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		count = 0
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		var err error
		count, err = q.ObserveOverdueContextCaptures(ctx, custodydb.ObserveOverdueContextCapturesParams{RootID: id(s.root), PageLimit: int32(limit)})
		return err
	})
	if err != nil {
		return 0, captureError(err)
	}
	return count, nil
}
