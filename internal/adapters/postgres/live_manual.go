package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/execution"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var _ app.LiveManualWorks = (*APIContextExecutions)(nil)

// LiveManualTarget is a four-UID locator only. C3 checks ordinary entitlement
// before requesting original work/audience. No node or execution authority is
// inferred from this lookup, and a viewer cannot start or renew collection.
func (s *APIContextExecutions) LiveManualTarget(ctx context.Context, captureID string) (authorization.Target, error) {
	var out authorization.Target
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(captureID) {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		r, err := q.ReadLiveManualTarget(ctx, custodydb.ReadLiveManualTargetParams{RootID: id(s.root), CaptureID: id(captureID)})
		if err != nil {
			return err
		}
		out = authorization.Target{ClusterID: r.ClusterID, NamespaceUID: r.NamespaceUid, WorkloadUID: r.WorkloadUid, PodUID: r.PodUid}
		if !out.Valid() {
			return value.ErrUnavailable
		}
		return ctx.Err()
	})
	if err != nil {
		return authorization.Target{}, value.ErrUnavailable
	}
	return out, nil
}

func liveManualIDs(ids []string) ([]pgtype.UUID, bool) {
	if len(ids) == 0 || len(ids) > 16 {
		return nil, false
	}
	out := make([]pgtype.UUID, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, v := range ids {
		if !authorization.UUID(v) || seen[v] {
			return nil, false
		}
		seen[v] = true
		out = append(out, id(v))
	}
	return out, true
}

// A finite source continues under its original committed execution, not a
// reconstructed token or groups. The actual holder independently supplies its
// work/node identity and original capture end. In particular, NotAfter below
// is the old preparation interval and is never used as a source lifetime.
func liveManualMatches(w app.APIContextWork, r value.APIExecution, now time.Time) bool {
	e := w.Accepted.Expectation
	return w.Accepted.State == capture.IntentAudited && !w.CancellationRequested && w.SourceBinding == nil && w.Actor.Kind == identity.Human && w.Actor.Valid() &&
		e.Validate() == nil && e.ExecutionClass == artifact.ContextAPIExecution && e.Recording != nil && e.Snapshot == nil && e.Profile == nil && e.Logs == nil &&
		(e.Recording.Kind == "packetCapture" || e.Recording.Kind == "syscallTrace") && r.Valid() && r.Phase == "started" && !now.Before(r.StartedAt) &&
		r.Binding.CaptureID == w.Accepted.CaptureID && r.Binding.CaptureID == e.CaptureUID && r.Binding.ActionID == e.ActionID && r.Binding.AttemptID == e.Registration.Location.AttemptID &&
		r.Binding.PodUID == e.PodUID && r.Binding.ClusterID == e.Registration.Location.ClusterID && r.Binding.ScopeDigest == e.PlanDigest && r.Binding.ScopeDigest == w.Accepted.ScopeDigest &&
		r.Binding.AuditDigest == w.IntentDigest && r.ExpectationDigest == evidence.ContextExpectationDigest(e) && r.Binding.NativeBytes == e.Registration.NativeLimit &&
		w.Target.ClusterID == e.Registration.Location.ClusterID && w.Target.Namespace.UID == e.NamespaceUID && w.Target.Workload.UID == e.WorkloadUID && w.Target.PodUID == e.PodUID &&
		now.Before(w.Accepted.Deadline) && now.Before(e.Registration.WriteUntil)
}

func (s *APIContextExecutions) withLiveManualRead(ctx context.Context, recovery artifact.RecoveryProof, read func(context.Context, *custodydb.Queries, time.Time, time.Time) (time.Time, error)) error {
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !recovery.Valid(time.Now()) {
		return value.ErrInvalid
	}
	call, stop := context.WithDeadline(ctx, identity.Earlier(time.Now().Add(5*time.Second), recovery.FreshUntil))
	defer stop()
	return s.ledger.transaction(call, func(q *custodydb.Queries) error {
		first, err := q.CurrentTime(call)
		if err != nil {
			return err
		}
		until := identity.Earlier(first.Time.Add(5*time.Second), recovery.FreshUntil)
		if d, ok := call.Deadline(); ok {
			until = identity.Earlier(until, d)
		}
		trust, err := s.guards.Recovery.lock(call, q, s.root, recovery)
		if err != nil {
			return err
		}
		if _, err = q.LockPermissionStream(call, id(s.root)); err != nil {
			return err
		}
		until, err = read(call, q, first.Time, until)
		if err != nil {
			return err
		}
		if err = s.guards.Recovery.check(call, q, trust, s.root, recovery); err != nil {
			return err
		}
		last, err := q.CurrentTime(call)
		if err != nil || !last.Time.Before(until) || call.Err() != nil {
			return value.ErrUnavailable
		}
		return nil
	})
}

func (s *APIContextExecutions) liveManualRecord(ctx context.Context, q *custodydb.Queries, c custodydb.ContextCapture, execution custodydb.ContextExecution, at, until time.Time) (app.LiveManualWork, error) {
	var zero app.LiveManualWork
	if uid(c.RootID) != s.root || c.RootID != execution.RootID || c.SnapshotCancelRequestedAt.Valid || c.SnapshotCancelJoinedAt.Valid {
		return zero, value.ErrDenied
	}
	w, err := apiWork(c)
	if err != nil {
		return zero, err
	}
	r, err := apiExecution(execution)
	if err != nil || !liveManualMatches(w, r, at) {
		return zero, value.ErrDenied
	}
	// Reuse the original compiled approval predicate and exact current grant
	// lock. Ordinary metadata does not acquire a new approval requirement.
	if err = currentRecordingGrant(ctx, q, c); err != nil {
		return zero, err
	}
	until = identity.Earlier(until, identity.Earlier(w.Accepted.Deadline, w.Accepted.Expectation.Registration.WriteUntil))
	out := app.LiveManualWork{Work: w, Execution: r, ObservedAt: at}
	rec := w.Accepted.Expectation.Recording
	if compiler.MeteredRecording(rec) || rec.Arguments != nil {
		o, err := q.ReadPolicyObservation(ctx, custodydb.ReadPolicyObservationParams{RootID: c.RootID, CaptureID: c.ID})
		if err != nil {
			return zero, err
		}
		g, err := q.ReadGrantByCapture(ctx, custodydb.ReadGrantByCaptureParams{RootID: c.RootID, CaptureID: c.ID})
		digest := evidence.ContextExpectationDigest(w.Accepted.Expectation)
		if err != nil || o.GrantID != g.ID || o.PolicyUid.Valid || o.AcceptanceID.Valid || o.CaptureID != c.ID || o.AttemptID != c.AttemptID || o.ActionID != w.Accepted.Expectation.ActionID || o.PodUid != w.Accepted.Expectation.PodUID || !bytes.Equal(o.ExpectationDigest, digest[:]) {
			return zero, value.ErrDenied
		}
		if rec.Arguments != nil {
			permit, err := argumentObservationPermit(o)
			if err != nil || !argumentObservationMatches(o, w.Accepted.Expectation) {
				return zero, value.ErrDenied
			}
			out.Arguments = &permit.Binding
		} else {
			permit, err := policyObservationPermit(o)
			if err != nil || !bytes.Equal(o.ProgramDigest, policyObservationProgramDigest(recordingProgram(rec))) || o.DurationMillis != rec.DurationMillis {
				return zero, value.ErrDenied
			}
			out.Observation = &permit.Binding
		}
		until, err = liveManualObservationUntil(o, at, until)
		if err != nil {
			return zero, err
		}
	}
	out.FreshUntil = until
	return out, nil
}

// Known-ended original sessions are omitted like other ended finite work.
// A session that ends during blocking work still fails the final read check.
func liveManualObservationUntil(o custodydb.PolicyObservationSession, at, until time.Time) (time.Time, error) {
	if !at.Before(o.SessionUntil.Time) || !at.Before(o.LeaseUntil.Time) {
		return time.Time{}, value.ErrDenied
	}
	return identity.Earlier(until, identity.Earlier(o.SessionUntil.Time, o.LeaseUntil.Time)), nil
}

func recordingProgram(r *artifact.Recording) []artifact.FilterInstruction {
	if r.Filter == nil {
		return nil
	}
	return r.Filter.Program
}

func (s *APIContextExecutions) ReadLiveManualWork(ctx context.Context, captures []string, recovery artifact.RecoveryProof) ([]app.LiveManualWork, error) {
	ids, valid := liveManualIDs(captures)
	if !valid {
		return nil, value.ErrInvalid
	}
	var out []app.LiveManualWork
	err := s.withLiveManualRead(ctx, recovery, func(call context.Context, q *custodydb.Queries, at, until time.Time) (time.Time, error) {
		rows, err := q.ReadLiveManualWorks(call, custodydb.ReadLiveManualWorksParams{RootID: id(s.root), CaptureIds: ids})
		if err != nil {
			return until, err
		}
		found := make(map[string]app.LiveManualWork, len(rows))
		for _, row := range rows {
			r, err := s.liveManualRecord(call, q, row.ContextCapture, row.ContextExecution, at, until)
			if err != nil {
				if errors.Is(err, value.ErrDenied) || errors.Is(err, pgx.ErrNoRows) {
					continue
				}
				return until, err
			}
			found[r.Work.Accepted.CaptureID] = r
		}
		for _, id := range captures {
			if r, ok := found[id]; ok {
				out = append(out, r)
				until = identity.Earlier(until, r.FreshUntil)
			}
		}
		return until, nil
	})
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return out, nil
}

func (s *APIContextExecutions) ListLiveManualWork(ctx context.Context, target authorization.WorkloadTarget, after string, limit int, recovery artifact.RecoveryProof) ([]app.LiveManualWork, string, error) {
	if !target.Valid() || after != "" && !authorization.UUID(after) || limit < 1 || limit > 100 {
		return nil, "", value.ErrInvalid
	}
	var out []app.LiveManualWork
	next := ""
	err := s.withLiveManualRead(ctx, recovery, func(call context.Context, q *custodydb.Queries, at, until time.Time) (time.Time, error) {
		rows, err := q.ListLiveManualWorks(call, custodydb.ListLiveManualWorksParams{RootID: id(s.root), AfterCaptureID: id(after), ClusterID: target.ClusterID, NamespaceUid: target.NamespaceUID, WorkloadUid: target.WorkloadUID, PageLimit: int32(limit + 1)})
		if err != nil {
			return until, err
		}
		if len(rows) > limit {
			next = uid(rows[limit-1].ContextCapture.ID)
			rows = rows[:limit]
		}
		for _, row := range rows {
			r, err := s.liveManualRecord(call, q, row.ContextCapture, row.ContextExecution, at, until)
			if err != nil {
				if errors.Is(err, value.ErrDenied) || errors.Is(err, pgx.ErrNoRows) {
					continue
				}
				return until, err
			}
			out = append(out, r)
			until = identity.Earlier(until, r.FreshUntil)
		}
		return until, nil
	})
	if err != nil {
		return nil, "", value.ErrUnavailable
	}
	return out, next, nil
}
