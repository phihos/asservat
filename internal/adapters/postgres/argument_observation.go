package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// PrepareArgumentRecording uses the existing original execution transaction.
// Both aggregate debits and the source-fenced permit commit together, once.
func (s *APIContextExecutions) PrepareArgumentRecording(ctx context.Context, c app.APIExecutionCheck, source targets.PacketSourceObservation) (value.APIExecution, bool, collector.ArgumentObservationPermit, error) {
	p := policyObservationPreparation{source: source, arguments: true}
	execution, first, err := s.prepareAPIExecution(ctx, c, &p)
	if err != nil {
		return value.APIExecution{}, false, collector.ArgumentObservationPermit{}, err
	}
	return execution, first, p.argumentPermit, nil
}

func sensitiveArgumentRecording(c app.APIExecutionCheck) bool {
	r := c.Work.Accepted.Expectation.Recording
	return r != nil && r.Kind == "syscallTrace" && r.Profile == "arguments"
}
func argumentRuleBytes() []byte { r := collector.ArgumentObservationAccountingRule(); return r[:] }

func (s *APIContextExecutions) prepareArgumentObservation(ctx context.Context, q *custodydb.Queries, c app.APIExecutionCheck, capture custodydb.ContextCapture, original *policyCaptureGrantState, checkedAt time.Time, first bool, p *policyObservationPreparation) error {
	e := c.Work.Accepted.Expectation
	if !p.arguments || !sensitiveArgumentRecording(c) || !e.Recording.Valid() || !bytes.Equal(e.Recording.Arguments.AccountingRule[:], argumentRuleBytes()) || !policyObservationSourceCurrent(p.source, c, checkedAt) {
		return value.ErrDenied
	}
	_, _, policy := authorization.PolicyExecutor(c.Work.Actor)
	var g authorization.Grant
	var grantID, acceptanceID pgtype.UUID
	var policyUID pgtype.Text
	if policy {
		if original == nil {
			return value.ErrDenied
		}
		g = original.grant
		grantID = original.reservation.GrantID
		acceptanceID = original.reservation.AcceptanceID
		policyUID = pgtype.Text{String: original.reservation.PolicyUid, Valid: true}
	} else {
		row, err := q.ReadGrantByCapture(ctx, custodydb.ReadGrantByCaptureParams{RootID: capture.RootID, CaptureID: capture.ID})
		if err != nil {
			return value.ErrDenied
		}
		g, err = grantFromRow(row)
		if err != nil || g.Kind != authorization.GrantAdHocCapture || g.Requester != c.Work.Actor {
			return value.ErrDenied
		}
		grantID = row.ID
	}
	ed := evidence.ContextExpectationDigest(e)
	existing, err := q.ReadPolicyObservation(ctx, custodydb.ReadPolicyObservationParams{RootID: capture.RootID, CaptureID: capture.ID})
	if err == nil {
		if first || existing.GrantID != grantID || existing.AcceptanceID != acceptanceID || existing.PolicyUid != policyUID || existing.AttemptID != capture.AttemptID || existing.NodeUid != p.source.NodeUID || existing.BootID != p.source.BootID || existing.CollectorPodUid != p.source.CollectorPodUID || existing.CollectorEpoch != p.source.CollectorEpoch || existing.ActionID != e.ActionID || existing.PodUid != e.PodUID || !bytes.Equal(existing.ExpectationDigest, ed[:]) {
			return value.ErrConflict
		}
		p.argumentPermit, err = argumentObservationPermit(existing)
		if err == nil && !argumentObservationMatches(existing, e) {
			return value.ErrConflict
		}
		return err // no debit, new fence, dates, or authority on passive replay
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if !first {
		return value.ErrConflict
	}
	hard := identity.Earlier(c.Work.Accepted.Deadline, identity.Earlier(e.Registration.WriteUntil, e.Registration.ExpiresAt))
	var finite authorization.FiniteArgumentObservation
	if policy {
		a, err := q.ReadPolicyAcceptance(ctx, custodydb.ReadPolicyAcceptanceParams{RootID: capture.RootID, ID: acceptanceID})
		if err != nil {
			return err
		}
		if a.PolicyUid != policyUID.String || !a.AcknowledgedAt.Valid {
			return value.ErrDenied
		}
		active, err := q.CountActivePolicyObservations(ctx, custodydb.CountActivePolicyObservationsParams{RootID: capture.RootID, AcceptanceID: acceptanceID})
		if err != nil {
			return err
		}
		finite, err = authorization.PlanFinitePolicyArgumentObservation(g, g.Policy.Authority, c.Eligibility.Target, e.Recording, g.Policy.Authority.Limits.MaxObservedBytes-a.ObservedBytesSpent, g.Policy.Authority.Limits.MaxObservedEvents-a.ObservedEventsSpent, active, checkedAt.Add(collector.PacketCaptureStartWithin), hard, checkedAt)
		if err != nil {
			return err
		}
	} else {
		active, err := q.CountActiveAdHocObservations(ctx, custodydb.CountActiveAdHocObservationsParams{RootID: capture.RootID, GrantID: grantID})
		if err != nil {
			return err
		}
		finite, err = authorization.PlanFiniteAdHocArgumentObservation(g, adHocObservationLimits(g.Scope), e.Recording, active, checkedAt.Add(collector.PacketCaptureStartWithin), hard, checkedAt)
		if err != nil {
			return err
		}
	}
	r := e.Recording
	args := r.Arguments
	row := custodydb.PolicyObservationSession{
		ID: id(uuid.NewString()), RootID: capture.RootID, PolicyUid: policyUID, AcceptanceID: acceptanceID, GrantID: grantID, CaptureID: capture.ID, AttemptID: capture.AttemptID, Fence: id(uuid.NewString()),
		ActionID: e.ActionID, PodUid: e.PodUID, NodeUid: p.source.NodeUID, BootID: p.source.BootID, CollectorPodUid: p.source.CollectorPodUID, CollectorEpoch: p.source.CollectorEpoch,
		ExpectationDigest: ed[:], ProgramDigest: args.ProgramDigest[:], AccountingRule: argumentRuleBytes(), ArgumentDefinitionDigest: args.DefinitionDigest[:],
		SourceObservedAt: ts(p.source.ObservedAt.UTC().Truncate(time.Microsecond)), SourceFreshUntil: ts(p.source.FreshUntil.UTC().Truncate(time.Microsecond)),
		StartedAt: ts(finite.StartedAt), SessionUntil: ts(finite.Until), LeaseUntil: ts(finite.Until), StartBy: ts(finite.LatestStart), DurationMillis: r.DurationMillis, Sequence: 1,
		Credit: finite.ByteCredit, EventCredit: finite.EventCredit, MaxBytesPerSecond: finite.BytesPerSecond, MaxEventsPerSecond: finite.EventsPerSecond,
		MaxProbeBytes: args.MaxProbeBytes, MaxBytesPerEvent: args.MaxBytesPerEvent, MaxTrackedThreads: r.Syscalls.MaxTrackedThreads, CaptureBuffers: args.CaptureBuffers,
	}
	row.BindingScope = argumentObservationScope(row)
	if policy {
		n, err := q.SpendPolicyObservation(ctx, custodydb.SpendPolicyObservationParams{RootID: capture.RootID, ID: acceptanceID, Bytes: finite.ByteCredit, Events: finite.EventCredit})
		if err != nil {
			return err
		}
		if n != 1 {
			return collector.ErrObservationBudgetExhausted
		}
		n, err = q.SpendPolicyGrantObservation(ctx, custodydb.SpendPolicyGrantObservationParams{RootID: capture.RootID, ID: grantID, Bytes: finite.ByteCredit, Events: finite.EventCredit})
		if err != nil {
			return err
		}
		if n != 1 {
			return collector.ErrObservationBudgetExhausted
		}
	} else {
		spent, err := q.SpendAdHocObservation(ctx, custodydb.SpendAdHocObservationParams{RootID: capture.RootID, GrantID: grantID, Bytes: finite.ByteCredit, Events: finite.EventCredit})
		if err != nil {
			return err
		}
		if !spent {
			return collector.ErrObservationBudgetExhausted
		}
	}
	row, err = q.InsertArgumentObservation(ctx, custodydb.InsertArgumentObservationParams{
		ID: row.ID, RootID: row.RootID, PolicyUid: row.PolicyUid, AcceptanceID: row.AcceptanceID, GrantID: row.GrantID, CaptureID: row.CaptureID, AttemptID: row.AttemptID, Fence: row.Fence, ActionID: row.ActionID, PodUid: row.PodUid, NodeUid: row.NodeUid, BootID: row.BootID, CollectorPodUid: row.CollectorPodUid, CollectorEpoch: row.CollectorEpoch,
		ExpectationDigest: row.ExpectationDigest, ProgramDigest: row.ProgramDigest, BindingScope: row.BindingScope, AccountingRule: row.AccountingRule, SourceObservedAt: row.SourceObservedAt, SourceFreshUntil: row.SourceFreshUntil,
		StartedAt: row.StartedAt, SessionUntil: row.SessionUntil, StartBy: row.StartBy, DurationMillis: row.DurationMillis, Credit: row.Credit, MaxBytesPerSecond: row.MaxBytesPerSecond,
		ArgumentDefinitionDigest: row.ArgumentDefinitionDigest, EventCredit: row.EventCredit, MaxEventsPerSecond: row.MaxEventsPerSecond, MaxProbeBytes: row.MaxProbeBytes, MaxBytesPerEvent: row.MaxBytesPerEvent, MaxTrackedThreads: row.MaxTrackedThreads, CaptureBuffers: row.CaptureBuffers,
	})
	if err != nil {
		return err
	}
	p.argumentPermit, err = argumentObservationPermit(row)
	return err
}

func argumentObservationScope(row custodydb.PolicyObservationSession) []byte {
	row.BindingScope = nil
	row.EndedAt = pgtype.Timestamptz{}
	row.AdhocCaptureID = pgtype.UUID{}
	for _, field := range []*pgtype.Timestamptz{&row.SourceObservedAt, &row.SourceFreshUntil, &row.StartedAt, &row.SessionUntil, &row.LeaseUntil, &row.StartBy} {
		if field.Valid {
			field.Time = field.Time.UTC()
		}
	}
	return digest(struct {
		Format string
		Row    custodydb.PolicyObservationSession
	}{"finite-argument-observation/v1", row})
}
func argumentObservationPermit(row custodydb.PolicyObservationSession) (collector.ArgumentObservationPermit, error) {
	var zero collector.ArgumentObservationPermit
	if len(row.BindingScope) != 32 || len(row.ProgramDigest) != 32 || len(row.ArgumentDefinitionDigest) != 32 || len(row.ExpectationDigest) != 32 || !bytes.Equal(row.BindingScope, argumentObservationScope(row)) || !bytes.Equal(row.AccountingRule, argumentRuleBytes()) || row.Sequence != 1 || row.EndedAt.Valid {
		return zero, value.ErrDenied
	}
	b := collector.ArgumentObservationBinding{SessionID: uid(row.ID), Fence: uid(row.Fence), CaptureID: uid(row.CaptureID), ActionID: row.ActionID, PodUID: row.PodUid, NodeUID: row.NodeUid, BootID: row.BootID, CollectorPodUID: row.CollectorPodUid, CollectorEpoch: row.CollectorEpoch, AccountingRule: collector.ArgumentObservationAccountingRule()}
	copy(b.Scope[:], row.BindingScope)
	copy(b.ProgramDigest[:], row.ProgramDigest)
	copy(b.DefinitionDigest[:], row.ArgumentDefinitionDigest)
	copy(b.ExpectationDigest[:], row.ExpectationDigest)
	p := collector.ArgumentObservationPermit{Binding: b, StartedAt: row.StartedAt.Time, SessionUntil: row.SessionUntil.Time, LeaseUntil: row.LeaseUntil.Time, StartBy: row.StartBy.Time, Duration: time.Duration(row.DurationMillis) * time.Millisecond, Sequence: 1, EventCredit: row.EventCredit, ByteCredit: row.Credit, EventsPerSecond: row.MaxEventsPerSecond, BytesPerSecond: row.MaxBytesPerSecond, MaxProbeBytes: row.MaxProbeBytes, MaxBytesPerEvent: row.MaxBytesPerEvent, MaxTrackedThreads: row.MaxTrackedThreads, CaptureBuffers: row.CaptureBuffers}
	if !p.ValidFinite(p.StartedAt) {
		return zero, value.ErrDenied
	}
	return p, nil
}
func argumentObservationMatches(row custodydb.PolicyObservationSession, e artifact.ContextExpectation) bool {
	r := e.Recording
	if r == nil || !r.Valid() || r.Arguments == nil || r.Syscalls == nil {
		return false
	}
	a := r.Arguments
	ed := evidence.ContextExpectationDigest(e)
	return uid(row.CaptureID) == e.CaptureUID && uid(row.AttemptID) == e.Registration.Location.AttemptID && row.ActionID == e.ActionID && row.PodUid == e.PodUID && bytes.Equal(row.ExpectationDigest, ed[:]) && bytes.Equal(row.ProgramDigest, a.ProgramDigest[:]) && bytes.Equal(row.ArgumentDefinitionDigest, a.DefinitionDigest[:]) && bytes.Equal(row.AccountingRule, a.AccountingRule[:]) && row.MaxProbeBytes == a.MaxProbeBytes && row.MaxBytesPerEvent == a.MaxBytesPerEvent && row.MaxBytesPerSecond == a.MaxBytesPerSecond && row.MaxEventsPerSecond == r.Syscalls.MaxEventsPerSecond && row.MaxTrackedThreads == r.Syscalls.MaxTrackedThreads && row.CaptureBuffers == a.CaptureBuffers && row.DurationMillis == r.DurationMillis
}

var _ app.ArgumentRecordingPreparer = (*APIContextExecutions)(nil)
