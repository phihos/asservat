package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// All authority, acknowledgement and persistence here is explicitly synthetic.
// These tests establish coordinator ordering, current-source checks and original
// deadlines; SQL/native qualification supplies the separate production proof.
type connectorBackingReviewFixture struct {
	t                                              *testing.T
	process                                        *connectorProcessFixture
	before                                         ConnectorIdentityBacking
	configuration                                  ConnectorIdentityConfiguration
	admission                                      *ConnectorBackingAdmission
	sourceReads, prepares, stores                  int
	starts, finishes, promotions                   int
	intentAcknowledged, outcomeAcknowledged        bool
	failBegin, failFinish, losePromotion           bool
	sourceUntil                                    time.Time
	sourceHook, storeHook, promoteHook             func(*connectorBackingReviewFixture)
	storeDeadline, finishDeadline, promoteDeadline time.Time
}

func newConnectorBackingReviewFixture(t *testing.T) (*connectorBackingReviewFixture, ConnectorBackingAcceptance) {
	t.Helper()
	process, _, _ := newConnectorProcessFixture(t)
	source, _ := connectorSourceConfiguration(t)
	before := source.cfg.Backing.Clone()
	before.SourceBackupReservedBytes = 6 << 20
	configuration := source.cfg.Clone()
	configuration.Backing = before.Clone()
	configuration.Backing.Policy.BackingRevision++
	configuration.Backing.Policy.ValidUntil = configuration.Backing.Policy.ValidUntil.Add(time.Hour)
	configuration.Source.Observation.Backing = value.ConnectorBackingObservation{Revision: configuration.Backing.Policy.BackingRevision, Digest: artifact.Digest{41}, SourceDigest: artifact.Digest{42}}
	f := &connectorBackingReviewFixture{t: t, process: process, before: before, configuration: configuration}
	s := ConnectorBackingAcceptance{Source: f, Proof: f, Recovery: process, Journal: f, Promotion: f, Audit: f, MAC: process.mac, Now: func() time.Time { return process.now }}
	return f, s
}

func (f *connectorBackingReviewFixture) ReadConnectorIdentityConfiguration(ctx context.Context) (ConnectorIdentityConfiguration, error) {
	f.sourceReads++
	if f.sourceHook != nil {
		f.sourceHook(f)
	}
	if ctx.Err() != nil {
		return ConnectorIdentityConfiguration{}, ctx.Err()
	}
	c := f.configuration.Clone()
	c.Source.Observation.ObservedAt = f.process.now
	c.Source.Observation.FreshUntil = f.process.now.Add(5 * time.Second)
	if !f.sourceUntil.IsZero() {
		c.Source.Observation.FreshUntil = identity.Earlier(c.Source.Observation.FreshUntil, f.sourceUntil)
	}
	return c, nil
}

func (f *connectorBackingReviewFixture) ReadConnectorProcessProof(ctx context.Context, r value.ConnectorProcessRequest) (value.ConnectorProcessProof, error) {
	p, e := f.process.ReadConnectorProcessProof(ctx, r)
	if e != nil {
		return p, e
	}
	p.Configuration = f.configuration.Source.Observation
	p.Configuration.Profile = p.Configuration.Profile.Clone()
	p.Configuration.ObservedAt = f.process.now
	p.Configuration.FreshUntil = f.process.now.Add(5 * time.Second)
	if !f.sourceUntil.IsZero() {
		p.Configuration.FreshUntil = identity.Earlier(p.Configuration.FreshUntil, f.sourceUntil)
	}
	p.FreshUntil = identity.Earlier(p.FreshUntil, p.Configuration.FreshUntil)
	return p, nil
}

func (f *connectorBackingReviewFixture) PrepareConnectorBacking(ctx context.Context, id string, c ConnectorBackingCurrent) (ConnectorBackingAdmission, error) {
	f.prepares++
	if ctx.Err() != nil || !c.Valid(f.process.now) {
		return ConnectorBackingAdmission{}, value.ErrUnavailable
	}
	if f.admission != nil {
		if id != f.admission.Intent.ID {
			return ConnectorBackingAdmission{}, value.ErrConflict
		}
		return *f.admission, nil
	}
	actor := connectorProcessActor(c.Proof)
	in := audit.OperationIntent{ID: id, RootID: c.Configuration.Backing.Policy.RootID, TraceID: id, Name: "connector_backing_acceptance", InputFormat: "connector-backing/v1", MACVersion: "mac-v1", AccountVersion: f.before.AccountVersion, Process: &actor, PrincipalDigest: artifact.Digest{43}, InputDigest: artifact.Digest{44}, CreatedAt: c.ObservedAt, RequestUntil: c.Until, WriteUntil: c.ObservedAt.Add(30 * time.Second), RetainUntil: c.ObservedAt.Add(time.Duration(f.before.RetainedSeconds) * time.Second)}
	var e error
	in, e = auditapp.BindOperationLifecycle(in, f.before.Policy)
	if e != nil {
		f.t.Fatal("invalid synthetic backing admission", e)
	}
	a := ConnectorBackingAdmission{Before: f.before.Clone(), Proposed: c.Configuration.Clone(), Intent: in}
	f.admission = &a
	return a, nil
}

func (f *connectorBackingReviewFixture) StoreConnectorBackingOutcome(ctx context.Context, a ConnectorBackingAdmission, o audit.OperationOutcome) error {
	f.stores++
	f.storeDeadline, _ = ctx.Deadline()
	if f.storeHook != nil {
		f.storeHook(f)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if f.admission == nil || f.admission.Intent.ID != a.Intent.ID || !f.intentAcknowledged {
		return value.ErrDenied
	}
	f.admission.Outcome = &o
	return nil
}

func (f *connectorBackingReviewFixture) Begin(ctx context.Context, in audit.OperationIntent) error {
	f.starts++
	if f.failBegin || ctx.Err() != nil || f.admission == nil || !sameConnectorJSON(in, f.admission.Intent) {
		return value.ErrUnavailable
	}
	f.intentAcknowledged = true
	return nil
}

func (f *connectorBackingReviewFixture) Finish(ctx context.Context, o audit.OperationOutcome) error {
	f.finishes++
	f.finishDeadline, _ = ctx.Deadline()
	if f.failFinish || ctx.Err() != nil || f.admission == nil || f.admission.Outcome == nil || !sameConnectorJSON(o, *f.admission.Outcome) {
		return value.ErrUnavailable
	}
	f.outcomeAcknowledged = true
	return nil
}

func (f *connectorBackingReviewFixture) PromoteConnectorBacking(ctx context.Context, a ConnectorBackingAdmission, c ConnectorBackingCurrent) (ConnectorIdentityBacking, error) {
	f.promotions++
	f.promoteDeadline, _ = ctx.Deadline()
	if !f.intentAcknowledged || !f.outcomeAcknowledged || !c.Valid(f.process.now) || ctx.Err() != nil {
		return ConnectorIdentityBacking{}, value.ErrDenied
	}
	f.admission.Activated = true
	if f.promoteHook != nil {
		f.promoteHook(f)
	}
	if f.losePromotion {
		return ConnectorIdentityBacking{}, value.ErrUnavailable
	}
	return a.Proposed.Backing.Clone(), nil
}

func TestConnectorBackingAcceptanceRequiresBothAcknowledgements(t *testing.T) {
	for _, which := range []string{"intent", "outcome"} {
		t.Run(which, func(t *testing.T) {
			f, s := newConnectorBackingReviewFixture(t)
			f.failBegin, f.failFinish = which == "intent", which == "outcome"
			_, e := s.Accept(context.Background(), f.process.request.Process.ProcessEpoch, f.process.request)
			if e == nil || f.promotions != 0 || f.admission == nil || f.admission.Activated {
				t.Fatal("failed independent audit permitted backing promotion", e, f.promotions)
			}
			if which == "intent" && (f.stores != 0 || f.finishes != 0) {
				t.Fatal("outcome work started without acknowledged intent")
			}
		})
	}
}

func TestConnectorBackingAcceptanceRejectsCompleteSourceChangeWithSameBehavior(t *testing.T) {
	for _, read := range []int{2, 3} {
		f, s := newConnectorBackingReviewFixture(t)
		originalProfile := f.configuration.Source.Observation.Profile.Clone()
		f.sourceHook = func(f *connectorBackingReviewFixture) {
			if f.sourceReads == read {
				f.configuration.Backing.Policy.PolicyDigest[0]++
				f.configuration.Source.Observation.Backing.Digest[0]++
				f.configuration.Source.Observation.Backing.SourceDigest[0]++
			}
		}
		_, e := s.Accept(context.Background(), f.process.request.Process.ProcessEpoch, f.process.request)
		if !originalProfile.Equal(f.configuration.Source.Observation.Profile) {
			t.Fatal("test accidentally changed behavioral identity")
		}
		if e == nil || f.promotions != 0 {
			t.Fatal("same behavior hid changed complete backing", read, e, f.promotions)
		}
	}
}

func TestConnectorBackingAcceptanceKeepsShortenedSourceDeadlineThroughOutcome(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		f, s := newConnectorBackingReviewFixture(t)
		until := f.process.now.Add(2 * time.Second)
		f.sourceHook = func(f *connectorBackingReviewFixture) {
			if f.sourceReads == 2 {
				f.sourceUntil = until
			}
		}
		if blocked {
			// The synthetic store settles after the known shorter observation;
			// a success return must not start new provider work under the old five.
			f.storeHook = func(f *connectorBackingReviewFixture) { f.process.now = until.Add(time.Microsecond) }
		}
		_, e := s.Accept(context.Background(), f.process.request.Process.ProcessEpoch, f.process.request)
		if !f.storeDeadline.Equal(until) {
			t.Fatal("store did not inherit shortened observation", f.storeDeadline, until)
		}
		if blocked {
			if e == nil || f.finishes != 0 || f.promotions != 0 {
				t.Fatal("late store started outcome provider/promotion work", e, f.finishes, f.promotions)
			}
		} else if e != nil || !f.finishDeadline.Equal(until) || !f.promoteDeadline.Equal(until) {
			t.Fatal("shortened authority was extended for later stages", e, f.finishDeadline, f.promoteDeadline, until)
		}
	}
}

func TestConnectorBackingAcceptanceRechecksAfterBlockingPromotion(t *testing.T) {
	for _, which := range []string{"original deadline", "caller cancellation"} {
		t.Run(which, func(t *testing.T) {
			f, s := newConnectorBackingReviewFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			until := f.process.now.Add(5 * time.Second)
			f.promoteHook = func(f *connectorBackingReviewFixture) {
				if which == "original deadline" {
					f.process.now = until.Add(time.Microsecond)
				} else {
					cancel()
				}
			}
			_, e := s.Accept(ctx, f.process.request.Process.ProcessEpoch, f.process.request)
			if e == nil || f.promotions != 1 || !f.admission.Activated || !f.promoteDeadline.Equal(until) {
				t.Fatal("late/unknown committed promotion delivered success or reset its original bound", e, f.promotions, f.promoteDeadline)
			}
		})
	}
}

func TestConnectorBackingAcceptanceReplaysOriginalWithoutRepeatingAudit(t *testing.T) {
	f, s := newConnectorBackingReviewFixture(t)
	id := f.process.request.Process.ProcessEpoch
	f.losePromotion = true
	if _, e := s.Accept(context.Background(), id, f.process.request); !errors.Is(e, value.ErrUnavailable) || !f.admission.Activated {
		t.Fatal("fixture did not lose the original committed promotion reply", e)
	}
	originalIntent := f.admission.Intent
	originalPolicy := f.admission.Before.Clone()
	f.losePromotion = false
	f.process.now = f.process.now.Add(10 * time.Second)
	got, e := s.Accept(context.Background(), id, f.process.request)
	if e != nil || !sameConnectorJSON(got, f.configuration.Backing) || f.starts != 1 || f.stores != 1 || f.finishes != 1 || f.promotions != 2 {
		t.Fatal("accepted replay repeated audit or lost original backing", e, f.starts, f.stores, f.finishes, f.promotions)
	}
	if !sameConnectorJSON(f.admission.Intent, originalIntent) || !sameConnectorJSON(f.admission.Before, originalPolicy) {
		t.Fatal("accepted replay renewed original audit or funding policy")
	}
}
