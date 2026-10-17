package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Only the application boundary is synthetic. Concrete native-read counts and
// initial/final I/O live in the Kubernetes tests; these assertions cover exact
// current/effect ordering, CSR/phase binding and unchanged uncertain spend.
type lifecycleEffectReader struct {
	f          *connectorProcessFixture
	operations []*lifecycleEffectOperation
	hook       func(*lifecycleEffectOperation, value.ConnectorLifecyclePhase, *value.ConnectorLifecycleObservation)
}

type lifecycleEffectOperation struct {
	reader   *lifecycleEffectReader
	request  ConnectorLifecycleRequest
	original value.ConnectorProcessProof
	phases   []value.ConnectorLifecyclePhase
	closed   int
}

func (r *lifecycleEffectReader) BeginConnectorLifecycle(ctx context.Context, request ConnectorLifecycleRequest) (ConnectorLifecycleOperation, error) {
	if ctx.Err() != nil || !request.Binding.Valid(r.f.now) {
		return nil, value.ErrUnavailable
	}
	p, err := r.f.ReadConnectorProcessProof(ctx, request.Request)
	if err != nil {
		return nil, err
	}
	p.FreshUntil = request.Binding.NotAfter
	p.Configuration.FreshUntil = request.Binding.NotAfter
	o := &lifecycleEffectOperation{reader: r, request: request, original: p}
	r.operations = append(r.operations, o)
	return o, nil
}

func (o *lifecycleEffectOperation) Read(ctx context.Context, phase value.ConnectorLifecyclePhase) (value.ConnectorLifecycleObservation, error) {
	f := o.reader.f
	if o.closed != 0 || ctx.Err() != nil {
		return value.ConnectorLifecycleObservation{}, value.ErrUnavailable
	}
	o.phases = append(o.phases, phase)
	source, err := f.ReadConnectorIdentitySource(ctx)
	if err != nil {
		return value.ConnectorLifecycleObservation{}, err
	}
	source.Observation.FreshUntil = o.request.Binding.NotAfter
	out := value.ConnectorLifecycleObservation{Binding: o.request.Binding, Phase: phase, Original: o.original.Clone(), Source: source, Until: o.request.Binding.NotAfter}
	if phase == value.ConnectorLifecycleFinal {
		final := o.original.Clone()
		final.ObservedAt = f.now
		final.Configuration = source.Observation
		out.FinalProof = &final
	}
	if o.reader.hook != nil {
		o.reader.hook(o, phase, &out)
	}
	return out, nil
}
func (o *lifecycleEffectOperation) Close() { o.closed++ }

func lifecycleServices(t *testing.T) (*connectorProcessFixture, *lifecycleEffectReader, ConnectorLifecycleEnrollment, ConnectorLifecycleRenewal) {
	t.Helper()
	f, _, old := newConnectorProcessFixture(t)
	native := &lifecycleEffectReader{f: f}
	enroll := ConnectorLifecycleEnrollment{Native: native, Keys: f, Recovery: f, Journal: f, Audit: f, MAC: f.mac, Now: old.Now}
	renew := ConnectorLifecycleRenewal{Native: native, Keys: f, Recovery: f, Journal: f, Audit: f, MAC: f.mac, Issuer: f, Verifier: f, Now: old.Now}
	return f, native, enroll, renew
}

func TestConnectorLifecycleEffectsUseOneOriginalHandleAndAllPhases(t *testing.T) {
	for _, usage := range []string{"enroll", "client", "server"} {
		t.Run(usage, func(t *testing.T) {
			f, native, enroll, renew := lifecycleServices(t)
			var err error
			if usage == "enroll" {
				_, err = enroll.Enroll(context.Background(), f.connectorRenewalFixture.request.ID, f.request)
			} else {
				_, err = renew.IssueProcess(context.Background(), f.connectorRenewalFixture.request.ID, usage, f.request)
			}
			if err != nil || len(native.operations) != 1 || native.operations[0].closed != 1 {
				t.Fatal("explicit native operation not joined", err, len(native.operations))
			}
			op := native.operations[0]
			if len(op.phases) != 4 {
				t.Fatal("missing independent current phase")
			}
			for i, phase := range op.phases {
				if phase != value.ConnectorLifecyclePhase(i+1) {
					t.Fatal("wrong phase order")
				}
			}
			if usage == "enroll" && f.processAccepts != 1 || usage != "enroll" && (f.claims != 1 || f.signs != 1 || f.activations != 1) {
				t.Fatal("effect ordering changed")
			}
		})
	}
}

func TestConnectorLifecycleEffectsRejectWrongCSRPhaseAndOriginal(t *testing.T) {
	for _, mode := range []string{"client-key", "server-key", "purpose", "id", "phase", "original-date", "missing-final", "source-role", "late"} {
		t.Run(mode, func(t *testing.T) {
			f, native, enroll, _ := lifecycleServices(t)
			native.hook = func(_ *lifecycleEffectOperation, phase value.ConnectorLifecyclePhase, out *value.ConnectorLifecycleObservation) {
				switch mode {
				case "client-key":
					out.Original.ClientKeyDigest = artifact.Digest{90}
				case "server-key":
					out.Original.ServerKeyDigest = artifact.Digest{90}
				case "purpose":
					out.Binding.Purpose = value.ConnectorLifecycleClient
				case "id":
					out.Binding.ID = "20000000-0000-4000-8000-000000000001"
				case "phase":
					out.Phase = value.ConnectorLifecycleBeforeEffect
				case "original-date":
					if phase == value.ConnectorLifecycleBeforeEffect {
						out.Original.ObservedAt = out.Original.ObservedAt.Add(time.Microsecond)
					}
				case "missing-final":
					if phase == value.ConnectorLifecycleFinal {
						out.FinalProof = nil
					}
				case "source-role":
					if phase == value.ConnectorLifecycleBeforeEffect {
						out.Source.Roles.Source = "changed_source"
					}
				case "late":
					if phase == value.ConnectorLifecycleBeforeEffect {
						f.now = f.now.Add(6 * time.Second)
					}
				}
			}
			if _, err := enroll.Enroll(context.Background(), f.connectorRenewalFixture.request.ID, f.request); err == nil {
				t.Fatal("invalid native result authorized enrollment")
			}
			if mode == "missing-final" {
				if f.processAccepts != 1 || f.admission == nil || !f.admission.Activated {
					t.Fatal("failed final check erased already accepted spend")
				}
			} else if f.processAccepts != 0 {
				t.Fatal("known failure admitted effect")
			}
			if len(native.operations) != 1 || native.operations[0].closed != 1 {
				t.Fatal("failed operation did not join once")
			}
		})
	}
}

type lifecycleRecoveryDeadline struct {
	f        *connectorProcessFixture
	deadline time.Time
	called   int
	shorten  time.Duration
	deny     bool
}

func (r *lifecycleRecoveryDeadline) RecoveryState(ctx context.Context) (value.RecoveryState, error) {
	r.called++
	r.deadline, _ = ctx.Deadline()
	if r.deny {
		return value.RecoveryState{}, value.ErrUnavailable
	}
	p, err := r.f.RecoveryState(ctx)
	p.FreshUntil = p.FreshUntil.Add(-r.shorten)
	return p, err
}

func TestConnectorLifecycleEffectsNarrowBeforeFollowingRecoveryAndSQL(t *testing.T) {
	f, native, enroll, _ := lifecycleServices(t)
	cut := f.now.Add(2 * time.Second)
	recovery := &lifecycleRecoveryDeadline{f: f}
	enroll.Recovery = recovery
	native.hook = func(_ *lifecycleEffectOperation, _ value.ConnectorLifecyclePhase, out *value.ConnectorLifecycleObservation) {
		out.Until = cut
	}
	f.prepareHook = func(_ *connectorProcessFixture) {
		if !recovery.deadline.Equal(cut) {
			t.Fatal("native shortening did not bound following recovery read")
		}
	}
	if _, err := enroll.Enroll(context.Background(), f.connectorRenewalFixture.request.ID, f.request); err != nil {
		t.Fatal(err)
	}
	if !f.admission.Intent.RequestUntil.Equal(cut) || recovery.called != 4 {
		t.Fatal("original narrowing/current recovery lost")
	}
	f, native, enroll, _ = lifecycleServices(t)
	enroll.Recovery = &lifecycleRecoveryDeadline{f: f, deny: true}
	if _, err := enroll.Enroll(context.Background(), f.connectorRenewalFixture.request.ID, f.request); err == nil || f.admission != nil || len(native.operations) != 1 || native.operations[0].closed != 1 {
		t.Fatal("native proof substituted for independent recovery")
	}
}

func TestConnectorLifecycleEffectsUnknownSigningNeverRetriesOrRefunds(t *testing.T) {
	f, native, _, renew := lifecycleServices(t)
	f.loseProvider = true
	id := f.connectorRenewalFixture.request.ID
	if _, err := renew.IssueProcess(context.Background(), id, "server", f.request); err == nil || f.signs != 1 || f.claims != 1 || f.row == nil || !f.row.ProviderStarted {
		t.Fatal("unknown provider attempt not retained")
	}
	f.loseProvider = false
	if _, err := renew.IssueProcess(context.Background(), id, "server", f.request); !errors.Is(err, value.ErrPending) || f.signs != 1 || f.claims != 1 || f.activations != 0 {
		t.Fatal("new bounded request repeated unknown signing", err)
	}
	if len(native.operations) != 2 || native.operations[0] == native.operations[1] || native.operations[0].closed != 1 || native.operations[1].closed != 1 {
		t.Fatal("operation ownership crossed requests")
	}
}

func TestConnectorLifecycleEffectsStoredReplyUsesExplicitMonotonicSkip(t *testing.T) {
	f, native, _, renew := lifecycleServices(t)
	f.loseActivation = true
	id := f.connectorRenewalFixture.request.ID
	if _, err := renew.IssueProcess(context.Background(), id, "server", f.request); err == nil || f.signs != 1 {
		t.Fatal("activation uncertainty missing")
	}
	f.loseActivation = false
	if _, err := renew.IssueProcess(context.Background(), id, "server", f.request); err != nil || f.signs != 1 || f.claims != 1 {
		t.Fatal("stored certificate repeated signing", err)
	}
	last := native.operations[len(native.operations)-1]
	if len(last.phases) != 3 || last.phases[0] != value.ConnectorLifecycleInitial || last.phases[1] != value.ConnectorLifecycleBeforeActivation || last.phases[2] != value.ConnectorLifecycleFinal {
		t.Fatal("stored receipt did not use explicit skip")
	}
}
