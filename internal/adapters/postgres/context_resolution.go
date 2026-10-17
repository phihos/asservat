package postgres

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContextRequestResolutions uses a separate credential with no custody or
// accepted-capture writes. Closing an unaccepted preview is its only effect.
type ContextRequestResolutions struct {
	ledger   *Ledger
	root     string
	recovery *RecoveryTransactionGuard
}

var _ app.ContextRequestResolution = (*ContextRequestResolutions)(nil)

func NewContextRequestResolutions(ctx context.Context, pool *pgxpool.Pool, root string, recovery *RecoveryTransactionGuard) (*ContextRequestResolutions, error) {
	if !authorization.UUID(root) || recovery == nil || recovery.root != root {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &ContextRequestResolutions{ledger: l, root: root, recovery: recovery}, nil
}

func (s *ContextRequestResolutions) ResolveOrCloseContextRequest(ctx context.Context, in value.ReplayQuery) (value.ContextRequestDisposition, error) {
	if s == nil {
		return value.ContextRequestDisposition{}, value.ErrUnavailable
	}
	return resolveContextRequest(ctx, s.ledger, s.root, s.recovery, in, true)
}

// requestRecordScope strictly validates private canonical historical ownership
// and its accepted target. Neither the row nor its digest supplies fresh rights.
func requestRecordScope(row custodydb.ContextCapture) (planning.ContextScopeIdentity, error) {
	var want artifact.Digest
	if len(row.ScopeDigest) != len(want) {
		return planning.ContextScopeIdentity{}, value.ErrUnavailable
	}
	copy(want[:], row.ScopeDigest)
	s, err := planning.ReadContextScopeIdentity(row.ScopeJson, want)
	if err != nil {
		return planning.ContextScopeIdentity{}, value.ErrUnavailable
	}
	a, err := admittedRecord(row)
	if err != nil {
		return planning.ContextScopeIdentity{}, err
	}
	e := a.Expectation
	target := authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}
	if s.CaptureID != a.CaptureID || s.Target != target || s.ExecutionClass != e.ExecutionClass || !s.Deadline.Equal(a.Deadline) {
		return planning.ContextScopeIdentity{}, value.ErrUnavailable
	}
	return s, nil
}

// findContextRequest is called with the root lock held. Foreign preview IDs
// are not an existence signal: a valid foreign record is treated as no request
// belonging to this actor/client. Canonical corruption remains unavailable.
func findContextRequest(ctx context.Context, q *custodydb.Queries, in value.ReplayQuery) (custodydb.ContextCapture, bool, error) {
	var zero custodydb.ContextCapture
	row, err := q.FindContextCapture(ctx, custodydb.FindContextCaptureParams{RootID: id(in.RootID), RequestKey: contextRequestKey(in.Identity.Principal, in.IdempotencyKey)})
	if err == nil {
		return row, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return zero, false, err
	}
	row, err = q.FindContextCaptureByPreview(ctx, custodydb.FindContextCaptureByPreviewParams{RootID: id(in.RootID), PreviewID: id(in.PreviewID)})
	if err == nil {
		scope, e := requestRecordScope(row)
		if e != nil {
			return zero, false, e
		}
		if scope.Actor == in.Identity.Principal {
			return row, true, nil
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return zero, false, err
	}
	actor := in.Identity.Principal
	rows, err := q.FindLegacyContextPreviewCapture(ctx, custodydb.FindLegacyContextPreviewCaptureParams{RootID: id(in.RootID), SubmissionDigest: in.SubmissionDigest[:], Issuer: actor.Issuer, Subject: actor.Subject, Client: actor.ClientID, Kind: string(actor.Kind)})
	if err != nil {
		return zero, false, err
	}
	if len(rows) > 1 {
		return zero, false, value.ErrUnavailable
	}
	if len(rows) == 1 {
		scope, e := requestRecordScope(rows[0])
		if e != nil {
			return zero, false, e
		}
		if scope.Actor != actor {
			return zero, false, value.ErrUnavailable
		}
		return rows[0], true, nil
	}
	return zero, false, nil
}

func resolveContextRequest(ctx context.Context, l *Ledger, root string, guard *RecoveryTransactionGuard, in value.ReplayQuery, closeMissing bool) (value.ContextRequestDisposition, error) {
	var out value.ContextRequestDisposition
	if l == nil || guard == nil || !contextRequestQueryShape(root, in) {
		return out, value.ErrInvalid
	}
	if closeMissing && !slices.Contains(in.Identity.Scopes, "evidence:read") {
		return out, value.ErrDenied
	}
	in.Identity.Groups = slices.Clone(in.Identity.Groups)
	in.Identity.Scopes = slices.Clone(in.Identity.Scopes)
	err := l.transaction(ctx, func(q *custodydb.Queries) error {
		out = value.ContextRequestDisposition{}
		recovery, err := guard.lock(ctx, q, root, in.Recovery)
		if err != nil {
			return err
		}
		stream, err := q.LockPermissionStream(ctx, id(root))
		if err != nil {
			return err
		}
		var permissionUntil time.Time
		check := func() error {
			if err := guard.check(ctx, q, recovery, root, in.Recovery); err != nil {
				return err
			}
			n, err := q.CurrentTime(ctx)
			if err != nil {
				return err
			}
			if !app.ValidReplayQuery(in, n.Time) || !permissionUntil.IsZero() && !n.Time.Before(permissionUntil) {
				return value.ErrDenied
			}
			return ctx.Err()
		}
		authorize := func(target authorization.Target) error {
			p, err := permissionProjection(ctx, q, stream, target)
			if err != nil {
				return value.ErrUnavailable
			}
			n, err := q.CurrentTime(ctx)
			if err != nil {
				return err
			}
			if closeMissing {
				eligible := authorization.ScopeEligibility(in.Identity, p, authorization.ReadApproved, target, n.Time)
				if !eligible.Eligible {
					return value.ErrDenied
				}
				permissionUntil = eligible.ValidUntil
			} else {
				eligible := authorization.ContextEligibility(in.Identity, p, target, n.Time)
				if !eligible.Eligible {
					return value.ErrDenied
				}
				permissionUntil = eligible.ValidUntil
			}
			return check()
		}
		deadline := func() time.Time {
			until := contextMetadataDeadline(ctx, in.Identity.ValidUntil, in.Recovery.FreshUntil)
			if !permissionUntil.IsZero() {
				until = identity.Earlier(until, permissionUntil)
			}
			return until
		}
		if err = check(); err != nil {
			return err
		}
		row, found, err := findContextRequest(ctx, q, in)
		if err != nil {
			return err
		}
		if found {
			scope, err := requestRecordScope(row)
			if err != nil {
				return err
			}
			if scope.Actor != in.Identity.Principal {
				return value.ErrDenied
			}
			if err = authorize(scope.Target); err != nil {
				return err
			}
			if !bytes.Equal(row.SubmissionDigest, in.SubmissionDigest[:]) {
				return value.ErrConflict
			}
			a, err := admittedRecord(row)
			if err != nil {
				return err
			}
			a.Replay = true
			a.MetadataValidUntil = deadline()
			out = value.ContextRequestDisposition{State: value.RequestAccepted, Accepted: &a, ValidUntil: a.MetadataValidUntil}
			return check()
		}
		if !closeMissing {
			return check()
		}
		preview, err := q.FindContextPreview(ctx, custodydb.FindContextPreviewParams{RootID: id(root), ID: id(in.PreviewID), ActorKey: previewActorKey(in.Identity.Principal)})
		if err == nil {
			p, err := previewRecord(preview)
			if err != nil {
				return err
			}
			if p.Actor != in.Identity.Principal {
				return value.ErrDenied
			}
			// Closing this actor/client's passive review only reduces authority.
			// It discloses no target fields and remains possible after losing
			// target permissions; inaccessible accepted work was handled above.
			if !preview.ClosedAt.Valid {
				n, err := q.CloseContextPreview(ctx, custodydb.CloseContextPreviewParams{RootID: id(root), ID: id(in.PreviewID), ActorKey: previewActorKey(in.Identity.Principal), ClosedRequestKey: contextRequestKey(in.Identity.Principal, in.IdempotencyKey), ClosedSubmissionDigest: in.SubmissionDigest[:]})
				if err != nil {
					return err
				}
				if n != 1 {
					return value.ErrUnavailable
				}
			}
		} else if errors.Is(err, pgx.ErrNoRows) {
			if err = closeMissingContextPreview(ctx, q, in); err != nil {
				return err
			}
		} else {
			return err
		}
		out = value.ContextRequestDisposition{State: value.RequestClosed, ValidUntil: deadline()}
		return check()
	})
	if err != nil {
		return value.ContextRequestDisposition{}, captureError(err)
	}
	return out, nil
}

func closeMissingContextPreview(ctx context.Context, q *custodydb.Queries, in value.ReplayQuery) error {
	actor := in.Identity.Principal
	fence, err := q.FindContextPreviewFence(ctx, custodydb.FindContextPreviewFenceParams{RootID: id(in.RootID), PreviewID: id(in.PreviewID), ActorKey: previewActorKey(actor)})
	if err == nil {
		if !bytes.Equal(fence.SubmissionDigest, in.SubmissionDigest[:]) || !bytes.Equal(fence.PrincipalKey, principalKey(actor)) {
			return value.ErrUnavailable
		}
		return nil // also closed for another key of this exact owned preview
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err = q.DeleteExpiredContextPreviews(ctx, id(in.RootID)); err != nil {
		return err
	}
	if _, err = q.DeleteExpiredContextPreviewFences(ctx, id(in.RootID)); err != nil {
		return err
	}
	count, err := q.CountContextPreviews(ctx, id(in.RootID))
	if err != nil {
		return err
	}
	if count >= value.MaxPreviewsPerRoot {
		return value.ErrCapacity
	}
	count, err = q.CountPrincipalContextPreviews(ctx, custodydb.CountPrincipalContextPreviewsParams{RootID: id(in.RootID), PrincipalKey: principalKey(actor)})
	if err != nil {
		return err
	}
	if count >= value.MaxPreviewsPerPrincipal {
		return value.ErrCapacity
	}
	_, err = q.InsertContextPreviewFence(ctx, custodydb.InsertContextPreviewFenceParams{RootID: id(in.RootID), PreviewID: id(in.PreviewID), ActorKey: previewActorKey(actor), PrincipalKey: principalKey(actor), RequestKey: contextRequestKey(actor, in.IdempotencyKey), SubmissionDigest: in.SubmissionDigest[:]})
	return err
}

// Structural validation uses each observation's own original instant. Identity
// is normally checked before recovery; comparing newer recovery to the older
// identity start would reject every legitimate sequential request. SQL-now is
// the common freshness instant inside the locked transaction.
func contextRequestQueryShape(root string, in value.ReplayQuery) bool {
	return in.RootID == root && authorization.UUID(root) && authorization.UUID(in.PreviewID) && identity.Text(in.IdempotencyKey, 128) && in.SubmissionDigest == app.ContextRequestDigest(in.PreviewID) && in.Identity.Valid(in.Identity.VerifiedAt) && in.Recovery.Valid(in.Recovery.ObservedAt)
}
