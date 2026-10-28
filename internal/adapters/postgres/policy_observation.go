package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Policy-only companion: the original API preparation and observation debit
// share one transaction. No production caller is wired until the complete
// authority/channel/prefix/backing qualification succeeds.
func (s *APIContextExecutions) PreparePolicyRecording(ctx context.Context, c app.APIExecutionCheck, source targets.PacketSourceObservation) (value.APIExecution, bool, collector.ObservationPermit, error) {
	p := policyObservationPreparation{source: source}
	execution, first, err := s.prepareAPIExecution(ctx, c, &p)
	if err != nil {
		return value.APIExecution{}, false, collector.ObservationPermit{}, err
	}
	return execution, first, p.permit, nil
}

type policyObservationPreparation struct {
	source targets.PacketSourceObservation
	permit collector.ObservationPermit
}

func sensitivePolicyRecording(c app.APIExecutionCheck) bool {
	_, _, policy := authorization.PolicyExecutor(c.Work.Actor)
	r := c.Work.Accepted.Expectation.Recording
	return policy && r != nil && r.Filter != nil && planning.RawBytePredicate(r.Filter.Expression)
}

func (s *APIContextExecutions) preparePolicyObservation(ctx context.Context, q *custodydb.Queries, c app.APIExecutionCheck, capture custodydb.ContextCapture, original *policyCaptureGrantState, checkedAt time.Time, first bool, p *policyObservationPreparation) error {
	e := c.Work.Accepted.Expectation
	if !sensitivePolicyRecording(c) || original == nil || !policyObservationSourceCurrent(p.source, c, checkedAt) {
		return value.ErrDenied
	}
	expectedDigest := evidence.ContextExpectationDigest(e)
	existing, err := q.ReadPolicyObservation(ctx, custodydb.ReadPolicyObservationParams{RootID: capture.RootID, CaptureID: capture.ID})
	if err == nil {
		if first || existing.GrantID != original.reservation.GrantID || existing.AcceptanceID != original.reservation.AcceptanceID ||
			existing.PolicyUid != original.reservation.PolicyUid || existing.AttemptID != capture.AttemptID ||
			existing.NodeUid != p.source.NodeUID || existing.BootID != p.source.BootID || existing.CollectorPodUid != p.source.CollectorPodUID || existing.CollectorEpoch != p.source.CollectorEpoch ||
			existing.ActionID != e.ActionID || existing.PodUid != e.PodUID || !bytes.Equal(existing.ExpectationDigest, expectedDigest[:]) {
			return value.ErrConflict
		}
		p.permit, err = policyObservationPermit(existing)
		return err // passive replay; original credit, dates and sequence are unchanged
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if !first {
		return value.ErrConflict
	} // cannot retrofit/rearm an existing preparation
	a, err := q.ReadPolicyAcceptance(ctx, custodydb.ReadPolicyAcceptanceParams{RootID: capture.RootID, ID: original.reservation.AcceptanceID})
	if err != nil {
		return err
	}
	if a.PolicyUid != original.reservation.PolicyUid || !a.AcknowledgedAt.Valid {
		return value.ErrDenied
	}
	active, err := q.CountActivePolicyObservations(ctx, custodydb.CountActivePolicyObservationsParams{RootID: capture.RootID, AcceptanceID: a.ID})
	if err != nil {
		return err
	}
	g := original.grant
	remaining := g.Policy.Authority.Limits.MaxObservedBytes - a.ObservedBytesSpent
	hard := identity.Earlier(c.Work.Accepted.Deadline, e.Registration.WriteUntil)
	hard = identity.Earlier(hard, e.Registration.ExpiresAt)
	finite, err := authorization.PlanFinitePolicyObservation(g, g.Policy.Authority, c.Eligibility.Target, time.Duration(e.Recording.DurationMillis)*time.Millisecond, remaining, active, checkedAt.Add(collector.PacketCaptureStartWithin), hard, checkedAt)
	if err != nil {
		return err
	}
	ed := evidence.ContextExpectationDigest(e)
	row := custodydb.PolicyObservationSession{
		ID: id(uuid.NewString()), RootID: capture.RootID, PolicyUid: a.PolicyUid, AcceptanceID: a.ID, GrantID: original.reservation.GrantID, CaptureID: capture.ID, AttemptID: capture.AttemptID, Fence: id(uuid.NewString()),
		ActionID: e.ActionID, PodUid: e.PodUID, NodeUid: p.source.NodeUID, BootID: p.source.BootID, CollectorPodUid: p.source.CollectorPodUID, CollectorEpoch: p.source.CollectorEpoch,
		ExpectationDigest: ed[:], ProgramDigest: policyObservationProgramDigest(e.Recording.Filter.Program), AccountingRule: observationRuleBytes(),
		SourceObservedAt: ts(p.source.ObservedAt.UTC().Truncate(time.Microsecond)), SourceFreshUntil: ts(p.source.FreshUntil.UTC().Truncate(time.Microsecond)), StartedAt: ts(finite.StartedAt), SessionUntil: ts(finite.Until), LeaseUntil: ts(finite.Until), StartBy: ts(finite.LatestStart), DurationMillis: e.Recording.DurationMillis,
		Sequence: 1, Credit: finite.Credit, MaxBytesPerSecond: finite.BytesPerSecond,
	}
	row.BindingScope = policyObservationScope(row)
	n, err := q.SpendPolicyObservedBytes(ctx, custodydb.SpendPolicyObservedBytesParams{RootID: capture.RootID, ID: a.ID, Bytes: finite.Credit})
	if err != nil {
		return err
	}
	if n != 1 {
		return value.ErrDenied
	}
	n, err = q.SpendPolicyGrantObservedBytes(ctx, custodydb.SpendPolicyGrantObservedBytesParams{RootID: capture.RootID, ID: row.GrantID, Bytes: finite.Credit})
	if err != nil {
		return err
	}
	if n != 1 {
		return value.ErrDenied
	}
	row, err = q.InsertPolicyObservation(ctx, custodydb.InsertPolicyObservationParams{
		ID: row.ID, RootID: row.RootID, PolicyUid: row.PolicyUid, AcceptanceID: row.AcceptanceID, GrantID: row.GrantID, CaptureID: row.CaptureID, AttemptID: row.AttemptID, Fence: row.Fence, ActionID: row.ActionID, PodUid: row.PodUid, NodeUid: row.NodeUid, BootID: row.BootID, CollectorPodUid: row.CollectorPodUid, CollectorEpoch: row.CollectorEpoch,
		ExpectationDigest: row.ExpectationDigest, ProgramDigest: row.ProgramDigest, BindingScope: row.BindingScope, AccountingRule: row.AccountingRule, SourceObservedAt: row.SourceObservedAt, SourceFreshUntil: row.SourceFreshUntil,
		StartedAt: row.StartedAt, SessionUntil: row.SessionUntil, StartBy: row.StartBy, DurationMillis: row.DurationMillis, Credit: row.Credit, MaxBytesPerSecond: row.MaxBytesPerSecond,
	})
	if err != nil {
		return err
	}
	// INSERT checks the original source/start cutoff with database time;
	// checked() then rechecks all original bounds after the SQL effects. All
	// writes roll back together if a blocking read/mutation consumed the interval.
	p.permit, err = policyObservationPermit(row)
	return err
}

func policyObservationSourceCurrent(source targets.PacketSourceObservation, c app.APIExecutionCheck, now time.Time) bool {
	t := c.Plan.Input.Target
	return source.Valid(now) && source.PodUID == c.Work.Accepted.Expectation.PodUID && source.PodUID == t.Pin.UID && !source.ObservedAt.Before(t.ObservedAt) && !source.FreshUntil.After(t.FreshUntil)
}

func observationRuleBytes() []byte { r := collector.ObservationAccountingRule(); return r[:] }

// All immutable identity, interval and ceiling values are included. ended_at
// is terminal bookkeeping; it never changes the scope or original pool spend.
func policyObservationScope(row custodydb.PolicyObservationSession) []byte {
	row.BindingScope = nil
	row.EndedAt = pgtype.Timestamptz{}
	return digest(struct {
		Format string
		Row    custodydb.PolicyObservationSession
	}{"finite-policy-observation/v1", row})
}

func policyObservationPermit(row custodydb.PolicyObservationSession) (collector.ObservationPermit, error) {
	var zero collector.ObservationPermit
	if len(row.BindingScope) != 32 || len(row.ProgramDigest) != 32 || len(row.ExpectationDigest) != 32 || !bytes.Equal(row.BindingScope, policyObservationScope(row)) || !bytes.Equal(row.AccountingRule, observationRuleBytes()) || row.Sequence != 1 || row.EndedAt.Valid {
		return zero, value.ErrDenied
	}
	b := collector.ObservationBinding{SessionID: uid(row.ID), Fence: uid(row.Fence), CaptureID: uid(row.CaptureID), ActionID: row.ActionID, PodUID: row.PodUid, NodeUID: row.NodeUid, BootID: row.BootID, CollectorPodUID: row.CollectorPodUid, CollectorEpoch: row.CollectorEpoch, AccountingRule: collector.ObservationAccountingRule()}
	copy(b.Scope[:], row.BindingScope)
	permit := collector.ObservationPermit{Binding: b, StartedAt: row.StartedAt.Time, SessionUntil: row.SessionUntil.Time, LeaseUntil: row.LeaseUntil.Time, Sequence: 1, Credit: row.Credit, BytesPerSecond: row.MaxBytesPerSecond, StartBy: row.StartBy.Time, Duration: time.Duration(row.DurationMillis) * time.Millisecond}
	if !b.Valid() || !permit.Lease().Valid(permit.StartedAt) || !permit.LeaseUntil.Equal(permit.SessionUntil) || permit.LeaseUntil.Sub(permit.StartedAt) > 20*time.Second || permit.Duration < time.Second || permit.Duration > 15*time.Second || !permit.StartBy.After(permit.StartedAt) || permit.StartBy.After(permit.StartedAt.Add(collector.PacketCaptureStartWithin)) || permit.StartBy.Add(permit.Duration).After(permit.LeaseUntil) {
		return zero, value.ErrDenied
	}
	return permit, nil
}

var _ app.PolicyRecordingPreparer = (*APIContextExecutions)(nil)

func policyObservationProgramDigest(program []artifact.FilterInstruction) []byte {
	native := make([]planvalue.BPFInstruction, len(program))
	for i, ins := range program {
		native[i] = planvalue.BPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	sum := planning.FilterProgramDigest(native)
	return sum[:]
}
