package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capacity"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
)

var _ app.CapacityEnrollmentStore = (*CapacityEnrollments)(nil)
var _ app.CapacityCaptureBacking = (*CapacityCaptureEnrollments)(nil)
var _ app.CapacityBindingObservations = (*CapacityEnrollments)(nil)

func (s *CapacityEnrollments) RefreshCapacityEnrollment(ctx context.Context, o app.EnrollmentObservation, v app.Enrollment) error {
	if s == nil || v.ReadyAt == nil {
		return cfg.ErrUnavailable
	}
	_, err := s.read.effect(ctx, o, &v, "observe")
	return err
}

func (s *CapacityEnrollments) ReserveCapacityEnrollment(ctx context.Context, o app.EnrollmentObservation) (app.Enrollment, error) {
	if s == nil {
		return app.Enrollment{}, cfg.ErrUnavailable
	}
	return s.read.effect(ctx, o, nil, "reserve")
}
func (s *CapacityEnrollments) PublishCapacityEnrollment(ctx context.Context, o app.EnrollmentObservation, v app.Enrollment) (app.Enrollment, error) {
	if s == nil {
		return app.Enrollment{}, cfg.ErrUnavailable
	}
	return s.read.effect(ctx, o, &v, "publish")
}
func (s *CapacityEnrollments) ContinueCapacityPublication(ctx context.Context, o app.EnrollmentObservation, v app.Enrollment) (app.Enrollment, error) {
	if s == nil {
		return app.Enrollment{}, cfg.ErrUnavailable
	}
	return s.read.effect(ctx, o, &v, "continue-publish")
}
func (s *CapacityCaptureEnrollments) BackCapacityCapture(ctx context.Context, o app.EnrollmentObservation, v app.Enrollment) (app.Enrollment, error) {
	if s == nil {
		return app.Enrollment{}, cfg.ErrUnavailable
	}
	return s.read.effect(ctx, o, &v, "capture")
}
func (s *CapacityCaptureEnrollments) ContinueCapacityCapture(ctx context.Context, o app.EnrollmentObservation, v app.Enrollment) (app.Enrollment, error) {
	if s == nil {
		return app.Enrollment{}, cfg.ErrUnavailable
	}
	return s.read.effect(ctx, o, &v, "continue-capture")
}

func capacityEnrollmentOriginal(a, b app.Enrollment) bool {
	return a.Format == b.Format && a.Key == b.Key && a.ID == b.ID && a.AttemptID == b.AttemptID && a.AllocationID == b.AllocationID && a.DownloadAllocationID == b.DownloadAllocationID && a.SourceDigest == b.SourceDigest && a.PlanDigest == b.PlanDigest && a.Revision == b.Revision && a.AccountVersion == b.AccountVersion && a.AccountDigest == b.AccountDigest && a.InitialObservedAt.Equal(b.InitialObservedAt) && a.InitialUntil.Equal(b.InitialUntil) && a.ReservedAt.Equal(b.ReservedAt) &&
		(a.CaptureBackedAt == nil || b.CaptureBackedAt != nil && a.CaptureBackedAt.Equal(*b.CaptureBackedAt)) && (a.ReadyAt == nil || b.ReadyAt != nil && a.ReadyAt.Equal(*b.ReadyAt))
}

// The private switch has exactly six compiled SQL effects. No operation name,
// candidate account ID, grant list or SQL text comes from a capture caller.
func (s *capacityEnrollmentReader) effect(ctx context.Context, o app.EnrollmentObservation, expected *app.Enrollment, phase string) (app.Enrollment, error) {
	var zero app.Enrollment
	capture := phase == "capture" || phase == "continue-capture"
	if s == nil || s.ledger == nil || s.accounts == nil || ctx == nil || ctx.Err() != nil || s.capture != capture || o.Key.RootID != s.root || o.Recovery.InstallationID != s.installation || !o.Valid(time.Now()) || o.Plan.AccountVersion() != s.accounts.AccountVersion() {
		return zero, cfg.ErrUnavailable
	}
	if phase != "reserve" && phase != "publish" && phase != "continue-publish" && phase != "observe" && !capture {
		return zero, cfg.ErrUnavailable
	}
	if (phase == "reserve") != (expected == nil) {
		return zero, cfg.ErrUnavailable
	}
	if expected != nil && (!expected.Valid() || expected.Key != o.Key || expected.SourceDigest != o.SourceDigest || expected.PlanDigest != o.PlanDigest || expected.AccountVersion != s.accounts.AccountVersion()) {
		return zero, cfg.ErrUnavailable
	}
	if expected != nil {
		mac, e := s.accounts.CaptureAccount(s.root, expected.AllocationID)
		if e != nil || mac != expected.AccountDigest {
			return zero, cfg.ErrUnavailable
		}
	}
	plan, pool, source, e := o.Plan.CanonicalValues()
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	observation, e := json.Marshal(o)
	if e != nil || len(observation) > 128<<10 {
		return zero, cfg.ErrUnavailable
	}
	var receipt []byte
	if expected != nil {
		receipt, e = json.Marshal(expected)
		if e != nil || len(receipt) > 8<<10 {
			return zero, cfg.ErrUnavailable
		}
	}
	until := o.FreshUntil
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	// Candidate IDs become original only in the first committed SQL reservation.
	// Any unknown result must be read on the next observation, never recreated.
	var candidates [4]uuid.UUID
	if phase == "reserve" {
		for i := range candidates {
			candidates[i], e = uuid.NewRandom()
			if e != nil {
				return zero, cfg.ErrUnavailable
			}
		}
	}
	var out capacityEnrollmentRead
	var narrow *time.Timer
	var joined chan struct{}
	defer func() {
		if narrow != nil && !narrow.Stop() {
			<-joined
		}
	}()
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		var raw []byte
		var err error
		switch phase {
		case "reserve":
			mac, err := s.accounts.CaptureAccount(s.root, candidates[2].String())
			if err != nil {
				return cfg.ErrUnavailable
			}
			raw, err = q.ReserveCapacityEnrollment(live, custodydb.ReserveCapacityEnrollmentParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, SourceCanonical: source, AccountID: id(candidates[0].String()), AttemptID: id(candidates[1].String()), AllocationID: id(candidates[2].String()), DownloadAllocationID: id(candidates[3].String()), AccountDigest: mac[:]})
			if err != nil {
				return err
			}
		case "capture":
			raw, err = q.BackCapacityEnrollment(live, custodydb.BackCapacityEnrollmentParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, SourceCanonical: source, ExpectedValue: receipt})
		case "continue-capture":
			raw, err = q.ContinueCapacityCapture(live, custodydb.ContinueCapacityCaptureParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, SourceCanonical: source, ExpectedValue: receipt})
		case "publish":
			raw, err = q.PublishCapacityEnrollment(live, custodydb.PublishCapacityEnrollmentParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, SourceCanonical: source, ExpectedValue: receipt})
		case "continue-publish":
			raw, err = q.ContinueCapacityPublication(live, custodydb.ContinueCapacityPublicationParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, SourceCanonical: source, ExpectedValue: receipt})
		case "observe":
			raw, err = q.RefreshCapacityEnrollment(live, custodydb.RefreshCapacityEnrollmentParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, SourceCanonical: source, ExpectedValue: receipt})
		}
		if err != nil {
			return err
		}
		out, err = decodeCapacityEnrollment(raw)
		if err != nil || out.Enrollment == nil || !out.matches(o, time.Now()) || expected != nil && !capacityEnrollmentOriginal(*expected, *out.Enrollment) {
			return cfg.ErrUnavailable
		}
		mac, err := s.accounts.CaptureAccount(s.root, out.Enrollment.AllocationID)
		if err != nil || mac != out.Enrollment.AccountDigest {
			return cfg.ErrUnavailable
		}
		if capture && out.Enrollment.CaptureBackedAt == nil || (phase == "publish" || phase == "continue-publish" || phase == "observe") && out.Enrollment.ReadyAt == nil {
			return cfg.ErrUnavailable
		}
		if !capture && out.Enrollment.ReadyAt != nil {
			if err = q.EnsureSharedContextQueryAllocation(live, custodydb.EnsureSharedContextQueryAllocationParams{RootID: id(s.root), ClusterID: id(o.Key.ClusterID), NamespaceUid: o.Key.NamespaceUID, WorkloadUid: o.Key.WorkloadUID}); err != nil {
				return err
			}
		}
		until = identity.Earlier(until, out.FreshUntil)
		if live.Err() != nil || !time.Now().Before(until) {
			return cfg.ErrUnavailable
		}
		done := make(chan struct{})
		joined = done
		narrow = time.AfterFunc(time.Until(until), func() { end(); close(done) })
		return nil
	})
	if e != nil || live.Err() != nil || !time.Now().Before(until) || out.Enrollment == nil || !out.matches(o, time.Now()) {
		return zero, cfg.ErrUnavailable
	}
	return *out.Enrollment, nil
}
