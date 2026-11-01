package postgres

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// A history purpose projection is not an evidence capture. A group contributes
// only its real control ID and the individually authorized real child records.
type historyCaptureProjection struct {
	ID, RootID                pgtype.UUID
	CreatedAt                 pgtype.Timestamptz
	HistoryOrigin             pgtype.Text
	HistoryParametersRequired bool
	RepeatedFromCaptureID     pgtype.UUID
	RepeatedFromExpiresAt     pgtype.Timestamptz
	ScopeDigest               artifact.Digest
	Target                    authorization.Target // Actual retained retention-selector witness, not parent Pod identity.
	Backing                   historyCaptureBacking
}

// This projection carries routing/accounting only, never a child's artifact ID.
type historyCaptureBacking struct {
	ClusterID, StoreID, AllocationID string
	PoolRevision, AllocationRevision int64
}

func historyCaptureBackingFor(r artifact.Registration) historyCaptureBacking {
	return historyCaptureBacking{ClusterID: r.Location.ClusterID, StoreID: r.StoreID, AllocationID: r.AllocationID, PoolRevision: r.PoolRevision, AllocationRevision: r.AllocationRevision}
}

func historyAuthorizedCapture(ctx context.Context, q *custodydb.Queries, root, installation, capture string, i identity.Identity, stream custodydb.PermissionStream, trust custodydb.FleetCurrentTrust, write bool) (historyCaptureProjection, time.Time, error) {
	var out historyCaptureProjection
	c, err := q.ReadHistoryCapture(ctx, custodydb.ReadHistoryCaptureParams{RootID: id(root), ID: id(capture)})
	if err == nil {
		until, e := authorizeHistoryChild(ctx, q, root, installation, i, stream, trust, c, write)
		if e != nil {
			return out, time.Time{}, e
		}
		accepted, e := admittedRecord(c)
		if e != nil {
			return out, time.Time{}, e
		}
		intent, e := captureIntent(c)
		if e != nil {
			return out, time.Time{}, e
		}
		return historyCaptureProjection{ID: c.ID, RootID: c.RootID, CreatedAt: c.CreatedAt, HistoryOrigin: c.HistoryOrigin, HistoryParametersRequired: c.HistoryParametersRequired, RepeatedFromCaptureID: c.RepeatedFromCaptureID, RepeatedFromExpiresAt: c.RepeatedFromExpiresAt, ScopeDigest: accepted.ScopeDigest, Target: intent.Target, Backing: historyCaptureBackingFor(accepted.Expectation.Registration)}, until, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, time.Time{}, err
	}
	g, err := q.ReadRecordingSaveGroup(ctx, custodydb.ReadRecordingSaveGroupParams{RootID: id(root), ID: id(capture)})
	if err != nil {
		return out, time.Time{}, value.ErrDenied
	}
	children, err := q.ReadRecordingSaveGroupChildren(ctx, custodydb.ReadRecordingSaveGroupChildrenParams{RootID: id(root), GroupID: g.ID})
	if err != nil {
		return out, time.Time{}, err
	}
	accepted, err := recordingGroupAcceptedRows(g, children)
	if err != nil {
		return out, time.Time{}, err
	}
	out = historyCaptureProjection{ID: g.ID, RootID: g.RootID, CreatedAt: g.AcceptedAt, HistoryParametersRequired: true, HistoryOrigin: pgtype.Text{String: string(value.HistoryManual), Valid: true}, ScopeDigest: accepted.ScopeDigest}
	var until time.Time
	for n, child := range children {
		end, e := authorizeHistoryChild(ctx, q, root, installation, i, stream, trust, child, write)
		if e != nil {
			return historyCaptureProjection{}, time.Time{}, e
		}
		if until.IsZero() {
			until = end
		} else {
			until = identity.Earlier(until, end)
		}
		intent, e := captureIntent(child)
		if e != nil {
			return out, time.Time{}, e
		}
		registration := accepted.Group.Children[n].Expectation.Registration
		if n == 0 {
			out.Target = intent.Target
			out.Backing = historyCaptureBackingFor(registration)
			out.RepeatedFromCaptureID = child.RepeatedFromCaptureID
			out.RepeatedFromExpiresAt = child.RepeatedFromExpiresAt
		} else if intent.Target.ClusterID != out.Target.ClusterID || intent.Target.NamespaceUID != out.Target.NamespaceUID || intent.Target.WorkloadUID != out.Target.WorkloadUID || registration.StoreID != out.Backing.StoreID || registration.AllocationID != out.Backing.AllocationID || registration.PoolRevision != out.Backing.PoolRevision || registration.AllocationRevision != out.Backing.AllocationRevision || child.RepeatedFromCaptureID != out.RepeatedFromCaptureID || !child.RepeatedFromExpiresAt.Time.Equal(out.RepeatedFromExpiresAt.Time) {
			return historyCaptureProjection{}, time.Time{}, value.ErrUnavailable
		}
	}
	return out, until, nil
}

func authorizeHistoryChild(ctx context.Context, q *custodydb.Queries, root, installation string, i identity.Identity, stream custodydb.PermissionStream, trust custodydb.FleetCurrentTrust, c custodydb.ContextCapture, write bool) (time.Time, error) {
	accepted, err := admittedRecord(c)
	if err != nil {
		return time.Time{}, value.ErrUnavailable
	}
	intent, err := captureIntent(c)
	if err != nil {
		return time.Time{}, err
	}
	projection, err := permissionProjection(ctx, q, stream, intent.Target)
	if err != nil {
		return time.Time{}, value.ErrDenied
	}
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if !i.Valid(now.Time) {
		return time.Time{}, value.ErrDenied
	}
	var result authorization.Result
	if write {
		if intent.Requester() != i.Principal {
			return time.Time{}, value.ErrDenied
		}
		result = contextEligibilityIn(ctx, q, stream, trust, root, installation, i, projection, intent.Target, now.Time).Result
	} else {
		result = authorization.CaptureHistoryEligibility(i, projection, intent.Target, intent.Requester(), accepted.Expectation.Audience, now.Time)
	}
	if !result.Eligible {
		return time.Time{}, value.ErrDenied
	}
	return identity.Earlier(result.ValidUntil, i.ValidUntil), nil
}
