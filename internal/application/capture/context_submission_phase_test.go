package capture

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
)

// The actual investigation, request-owned identity and submission coordinator
// run together. SQL admission/replay and the start effect are explicit synthetic
// ports. Advancing the shared clock models blocking work without wall-clock races.
type phaseAdmission struct {
	*investigationFixture
	until time.Time
}

func (p phaseAdmission) AdmitReviewedContext(ctx context.Context, preview string, in value.Admission) (value.Accepted, error) {
	a, err := p.investigationFixture.AdmitReviewedContext(ctx, preview, in)
	a.MetadataValidUntil = p.until
	return a, err
}

type phaseReplay struct {
	*investigationFixture
	initialUntil  time.Time
	acceptedReads int
	after         func(*value.Accepted, *bool, *error)
}

func (p *phaseReplay) LookupContextAdmission(ctx context.Context, q value.ReplayQuery) (value.Accepted, bool, error) {
	a, found, err := p.investigationFixture.LookupContextAdmission(ctx, q)
	if found {
		p.acceptedReads++
		if p.acceptedReads == 1 && !p.initialUntil.IsZero() {
			a.MetadataValidUntil = p.initialUntil
		}
		if p.after != nil {
			p.after(&a, &found, &err)
		}
	}
	return a, found, err
}

type phaseStart struct {
	delegate ContextAcceptedStart
	f        *investigationFixture
	before   func(context.Context) error
}

func (p phaseStart) StartContext(ctx context.Context, current identities.CurrentIdentity, id string) error {
	if p.before != nil {
		if err := p.before(ctx); err != nil {
			return err
		}
	}
	// A real start checks the received original deadline before preparing effects.
	until, ok := ctx.Deadline()
	if !ok || !p.f.now.Before(until) || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	return p.delegate.StartContext(ctx, current, id)
}

func TestContextSubmissionConsumesMetadataBeforeIndependentStart(t *testing.T) {
	for _, continuation := range []bool{false, true} {
		for _, phase := range []string{"intent", "start"} {
			name := "request/" + phase
			if continuation {
				name = "continue/" + phase
			}
			t.Run(name, func(t *testing.T) {
				f, x, s, p := submissionTest(t)
				original := f.now
				ctx, cancel := context.WithDeadline(context.Background(), original.Add(5*time.Second))
				defer cancel()
				x.current = f.source(t, ctx)
				metadataUntil := original.Add(100 * time.Millisecond)
				s.Admission = phaseAdmission{f, metadataUntil}
				replay := &phaseReplay{investigationFixture: f}
				s.Replay = replay
				if continuation {
					if _, err := f.svc.Request(ctx, x.current, p.ID, "original"); err != nil {
						t.Fatal(err)
					}
					replay.initialUntil = metadataUntil
				}
				advance := func() { f.now = original.Add(200 * time.Millisecond) }
				if phase == "intent" {
					x.intentHook = advance
				} else {
					x.startHook = advance
				}
				s.Start = phaseStart{delegate: x, f: f, before: func(call context.Context) error {
					until, _ := call.Deadline()
					if !until.Equal(original.Add(5 * time.Second)) {
						t.Errorf("response metadata shortened start context: got %v, caller %v", until, original.Add(5*time.Second))
					}
					return nil
				}}
				var a value.Accepted
				var err error
				if continuation {
					a, err = s.Continue(ctx, x.current, p.ID, "original")
				} else {
					a, err = s.Request(ctx, x.current, p.ID, "original")
				}
				if err != nil || x.starts != 1 || x.intentReads != 1 {
					t.Fatalf("consumed response metadata blocked independent start: err=%v starts=%d intent=%d", err, x.starts, x.intentReads)
				}
				wantReads := 1
				if continuation {
					wantReads++
				}
				if replay.acceptedReads != wantReads {
					t.Fatalf("expired metadata did not use one exact read-only lookup: %d", replay.acceptedReads)
				}
				stored := f.accepted[fixtureKey(f.actor, "original")]
				if a.CaptureID != p.CaptureID || !reflect.DeepEqual(a.Expectation, stored.Expectation) || a.Pin != stored.Pin || a.ScopeDigest != stored.ScopeDigest || a.SubmissionDigest != stored.SubmissionDigest || !a.CreatedAt.Equal(stored.CreatedAt) || !a.Deadline.Equal(stored.Deadline) || a.Replay != continuation || !f.now.Before(a.MetadataValidUntil) || a.MetadataValidUntil.After(original.Add(5*time.Second)) || f.admissions.Load() != 1 {
					t.Fatal("final observation changed original operation or lost current metadata")
				}
			})
		}
	}
}

func TestContextSubmissionMetadataRefreshCannotReplaceAcceptedOperation(t *testing.T) {
	for _, mode := range []string{"missing", "read-error", "capture", "scope", "submission", "pin", "registration", "created", "deadline", "expired-metadata", "identity-after-read", "recovery-after-read", "cancel-after-read"} {
		t.Run(mode, func(t *testing.T) {
			f, x, s, p := submissionTest(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			x.current = f.source(t, ctx)
			s.Admission = phaseAdmission{f, f.now.Add(100 * time.Millisecond)}
			replay := &phaseReplay{investigationFixture: f}
			s.Replay = replay
			x.startHook = func() { f.now = f.now.Add(200 * time.Millisecond) }
			replay.after = func(a *value.Accepted, found *bool, err *error) {
				switch mode {
				case "missing":
					*found = false
				case "read-error":
					*err = value.ErrUnavailable
				case "capture":
					a.CaptureID = fixtureID(999)
				case "scope":
					a.ScopeDigest[0]++
				case "submission":
					a.SubmissionDigest[0]++
				case "pin":
					a.Pin.UID = "replacement"
				case "registration":
					a.Expectation.Registration.ExpiresAt = a.Expectation.Registration.ExpiresAt.Add(time.Second)
				case "created":
					a.CreatedAt = a.CreatedAt.Add(time.Microsecond)
				case "deadline":
					a.Deadline = a.Deadline.Add(time.Second)
				case "expired-metadata":
					a.MetadataValidUntil = f.now
				case "identity-after-read":
					f.identityChange = "groups"
				case "recovery-after-read":
					f.now = f.now.Add(6 * time.Second)
				case "cancel-after-read":
					cancel()
				}
			}
			a, err := s.Request(ctx, x.current, p.ID, "original")
			if err == nil || x.starts != 1 || x.intentReads != 1 || replay.acceptedReads != 1 || f.admissions.Load() != 1 || a.CaptureID != p.CaptureID {
				t.Fatalf("failed final observation changed known admission or repeated effects: err=%v starts=%d intent=%d reads=%d", err, x.starts, x.intentReads, replay.acceptedReads)
			}
		})
	}
}

func TestContextSubmissionPreservesCurrentMetadataWithoutExtraLookup(t *testing.T) {
	for _, passive := range []bool{false, true} {
		name := "first"
		if passive {
			name = "passive-replay"
		}
		t.Run(name, func(t *testing.T) {
			f, x, s, p := submissionTest(t)
			x.current = f.source(t, context.Background())
			cutoff := f.now.Add(time.Second)
			s.Admission = phaseAdmission{f, cutoff}
			replay := &phaseReplay{investigationFixture: f, initialUntil: cutoff}
			s.Replay = replay
			if passive {
				if _, err := f.svc.Request(context.Background(), x.current, p.ID, "original"); err != nil {
					t.Fatal(err)
				}
			}
			a, err := s.Request(context.Background(), x.current, p.ID, "original")
			wantReads, wantStarts := 0, 1
			if passive {
				wantReads, wantStarts = 1, 0
			}
			if err != nil || !a.MetadataValidUntil.Equal(cutoff) || a.Replay != passive || replay.acceptedReads != wantReads || x.starts != wantStarts || x.intentReads != wantStarts {
				t.Fatalf("metadata was renewed or passive replay acquired effects: err=%v reads=%d starts=%d", err, replay.acceptedReads, x.starts)
			}
		})
	}
}

func TestContextSubmissionPhaseSeparationKeepsAuthorityCutoffs(t *testing.T) {
	for _, mode := range []string{"caller", "identity", "fresh-start", "cancel", "expired-handoff"} {
		t.Run(mode, func(t *testing.T) {
			f, x, s, p := submissionTest(t)
			original := f.now
			callerUntil := original.Add(5 * time.Second)
			if mode == "caller" {
				callerUntil = original.Add(100 * time.Millisecond)
			}
			ctx, cancel := context.WithDeadline(context.Background(), callerUntil)
			defer cancel()
			x.current = f.source(t, ctx)
			metadataUntil := original.Add(50 * time.Millisecond)
			if mode == "expired-handoff" {
				metadataUntil = original
			}
			s.Admission = phaseAdmission{f, metadataUntil}
			replay := &phaseReplay{investigationFixture: f}
			s.Replay = replay
			x.intentHook = func() {
				f.now = original.Add(200 * time.Millisecond)
				if mode == "identity" {
					f.now = original.Add(5 * time.Second)
				}
				if mode == "cancel" {
					cancel()
				}
			}
			s.Start = phaseStart{delegate: x, f: f, before: func(context.Context) error {
				if mode == "fresh-start" {
					return value.ErrDenied
				} // independently current start authority refuses
				return nil
			}}
			_, err := s.Request(ctx, x.current, p.ID, "original")
			if err == nil || x.starts != 0 || replay.acceptedReads != 0 || f.admissions.Load() != 1 {
				t.Fatalf("authority expiry was mistaken for consumed metadata: err=%v starts=%d reads=%d", err, x.starts, replay.acceptedReads)
			}
			if mode == "fresh-start" && !errors.Is(err, value.ErrDenied) {
				t.Fatal("fresh start denial lost", err)
			}
		})
	}
}
