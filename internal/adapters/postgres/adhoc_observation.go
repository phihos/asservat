package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"asservat.local/asservat/internal/domain/collector"
)

// sensitiveManualRecording is a human's approved finite raw packet
// (ADR-279) or HTTP header (ADR-282) recording; both read payload and run
// only with an observation preparation.
func sensitiveManualRecording(c app.APIExecutionCheck) bool {
	_, _, policy := authorization.PolicyExecutor(c.Work.Actor)
	r := c.Work.Accepted.Expectation.Recording
	return !policy && r != nil && (r.Profile == "rawPackets" || r.Profile == "httpHeaders")
}

// prepareAdHocObservation is preparePolicyObservation for a manual raw or
// HTTP header recording: the session is prepaid once from the approved ad hoc grant's
// reviewed pool (migration 00117) and never refilled; an exact existing
// session is passive replay.
func (s *APIContextExecutions) prepareAdHocObservation(ctx context.Context, q *custodydb.Queries, c app.APIExecutionCheck, capture custodydb.ContextCapture, checkedAt time.Time, first bool, p *policyObservationPreparation) error {
	e := c.Work.Accepted.Expectation
	if !sensitiveManualRecording(c) || !policyObservationSourceCurrent(p.source, c, checkedAt) {
		return value.ErrDenied
	}
	row, err := q.ReadGrantByCapture(ctx, custodydb.ReadGrantByCaptureParams{RootID: capture.RootID, CaptureID: capture.ID})
	if err != nil {
		return value.ErrDenied
	}
	g, err := grantFromRow(row)
	if err != nil || g.Kind != authorization.GrantAdHocCapture || g.Requester != c.Work.Actor {
		return value.ErrDenied
	}
	expectedDigest := evidence.ContextExpectationDigest(e)
	existing, err := q.ReadPolicyObservation(ctx, custodydb.ReadPolicyObservationParams{RootID: capture.RootID, CaptureID: capture.ID})
	if err == nil {
		if first || existing.GrantID != row.ID || existing.PolicyUid.Valid || existing.AcceptanceID.Valid || existing.AttemptID != capture.AttemptID ||
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
		return value.ErrConflict // cannot retrofit/rearm an existing preparation
	}
	active, err := q.CountActiveAdHocObservations(ctx, custodydb.CountActiveAdHocObservationsParams{RootID: capture.RootID, GrantID: row.ID})
	if err != nil {
		return err
	}
	hard := identity.Earlier(c.Work.Accepted.Deadline, e.Registration.WriteUntil)
	hard = identity.Earlier(hard, e.Registration.ExpiresAt)
	finite, err := authorization.PlanFiniteAdHocObservation(g, adHocObservationLimits(g.Scope), time.Duration(e.Recording.DurationMillis)*time.Millisecond, active, checkedAt.Add(collector.PacketCaptureStartWithin), hard, checkedAt)
	if err != nil {
		return err
	}
	var program []byte
	if e.Recording.Filter != nil {
		program = policyObservationProgramDigest(e.Recording.Filter.Program)
	} else {
		program = policyObservationProgramDigest(nil)
	}
	session := custodydb.PolicyObservationSession{
		ID: id(uuid.NewString()), RootID: capture.RootID, PolicyUid: pgtype.Text{}, AcceptanceID: pgtype.UUID{}, GrantID: row.ID, CaptureID: capture.ID, AttemptID: capture.AttemptID, Fence: id(uuid.NewString()),
		ActionID: e.ActionID, PodUid: e.PodUID, NodeUid: p.source.NodeUID, BootID: p.source.BootID, CollectorPodUid: p.source.CollectorPodUID, CollectorEpoch: p.source.CollectorEpoch,
		ExpectationDigest: expectedDigest[:], ProgramDigest: program, AccountingRule: observationRuleBytes(),
		SourceObservedAt: ts(p.source.ObservedAt.UTC().Truncate(time.Microsecond)), SourceFreshUntil: ts(p.source.FreshUntil.UTC().Truncate(time.Microsecond)), StartedAt: ts(finite.StartedAt), SessionUntil: ts(finite.Until), LeaseUntil: ts(finite.Until), StartBy: ts(finite.LatestStart), DurationMillis: e.Recording.DurationMillis,
		Sequence: 1, Credit: finite.Credit, MaxBytesPerSecond: finite.BytesPerSecond,
	}
	session.BindingScope = policyObservationScope(session)
	spent, err := q.SpendAdHocObservedBytes(ctx, custodydb.SpendAdHocObservedBytesParams{RootID: capture.RootID, GrantID: row.ID, Bytes: finite.Credit})
	if err != nil {
		return err
	}
	if !spent {
		return collector.ErrObservationBudgetExhausted
	}
	session, err = q.InsertPolicyObservation(ctx, custodydb.InsertPolicyObservationParams{
		ID: session.ID, RootID: session.RootID, PolicyUid: session.PolicyUid, AcceptanceID: session.AcceptanceID, GrantID: session.GrantID, CaptureID: session.CaptureID, AttemptID: session.AttemptID, Fence: session.Fence, ActionID: session.ActionID, PodUid: session.PodUid, NodeUid: session.NodeUid, BootID: session.BootID, CollectorPodUid: session.CollectorPodUid, CollectorEpoch: session.CollectorEpoch,
		ExpectationDigest: session.ExpectationDigest, ProgramDigest: session.ProgramDigest, BindingScope: session.BindingScope, AccountingRule: session.AccountingRule, SourceObservedAt: session.SourceObservedAt, SourceFreshUntil: session.SourceFreshUntil,
		StartedAt: session.StartedAt, SessionUntil: session.SessionUntil, StartBy: session.StartBy, DurationMillis: session.DurationMillis, Credit: session.Credit, MaxBytesPerSecond: session.MaxBytesPerSecond,
	})
	if err != nil {
		return err
	}
	p.permit, err = policyObservationPermit(session)
	return err
}

// adHocObservationLimits reads the reviewed observation limits frozen in an
// approved ad hoc grant's plan scope (ADR-279); zero (invalid) without them.
func adHocObservationLimits(scope []byte) authorization.ObservationLimits {
	var s struct {
		Approval struct {
			ObservationLimits authorization.ObservationLimits `json:"observationLimits"`
		} `json:"approval"`
	}
	if json.Unmarshal(scope, &s) != nil {
		return authorization.ObservationLimits{}
	}
	return s.Approval.ObservationLimits
}
