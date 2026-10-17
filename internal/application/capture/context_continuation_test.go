package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

func TestContextContinuationUsesAcceptedKeyWithFreshRequestAfterPassiveReplay(t *testing.T) {
	f, x, s, p := submissionTest(t)
	x.current = f.source(t, context.Background())
	x.intentErr = value.ErrUnavailable
	accepted, err := s.Request(context.Background(), x.current, p.ID, "original")
	if err == nil || accepted.CaptureID != p.CaptureID || x.starts != 0 {
		t.Fatal("fixture did not retain pending admission", err)
	}
	firstIDs, firstReads := f.newIDs.Load(), f.previewReads.Load()
	f.now = f.now.Add(6 * time.Second)
	delete(f.previews, p.ID) // Continuation is not dependent on the passive draft.
	x.current = f.source(t, context.Background())
	x.intentErr = nil
	replay, err := s.Request(context.Background(), x.current, p.ID, "original")
	if err != nil || !replay.Replay || x.starts != 0 || x.intentReads != 1 {
		t.Fatal("historical request replay started work", err)
	}
	continued, err := s.Continue(context.Background(), x.current, p.ID, "original")
	if err != nil || continued.CaptureID != accepted.CaptureID {
		t.Fatal("fresh continuation failed", err)
	}
	if continued.Expectation.Registration != accepted.Expectation.Registration || continued.ScopeDigest != accepted.ScopeDigest || continued.Pin != accepted.Pin || !continued.Deadline.Equal(accepted.Deadline) || x.starts != 1 || x.intentReads != 2 || f.admissions.Load() != 1 || f.newIDs.Load() != firstIDs || f.previewReads.Load() != firstReads {
		t.Fatal("continuation replaced original work or consulted preview")
	}
}

func TestContextContinuationMissingForeignOrChangedKeyNeverAdmits(t *testing.T) {
	for _, mode := range []string{"missing", "foreign-actor", "foreign-client", "changed-preview"} {
		t.Run(mode, func(t *testing.T) {
			f, x, s, p := submissionTest(t)
			x.current = f.source(t, context.Background())
			if mode != "missing" {
				if _, err := f.svc.Request(context.Background(), x.current, p.ID, "original"); err != nil {
					t.Fatal(err)
				}
			}
			count := f.admissions.Load()
			ids := f.newIDs.Load()
			switch mode {
			case "foreign-actor":
				f.actor.Subject = "other"
			case "foreign-client":
				f.actor.ClientID = "other"
			case "changed-preview":
				p.ID = fixtureID(999)
			}
			x.current = f.source(t, context.Background())
			if _, err := s.Continue(context.Background(), x.current, p.ID, "original"); err == nil || x.starts != 0 || x.intentReads != 0 || f.admissions.Load() != count || f.newIDs.Load() != ids {
				t.Fatal("continuation admitted or selected foreign work", err)
			}
		})
	}
}

func TestContextContinuationCannotRenewCallerOrAcceptedInterval(t *testing.T) {
	for _, mode := range []string{"old-current", "cancelled", "capture-scope-lost", "original-interval", "audit-uncertain", "preparation-spent"} {
		t.Run(mode, func(t *testing.T) {
			f, x, s, p := submissionTest(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			x.current = f.source(t, ctx)
			if _, err := f.svc.Request(ctx, x.current, p.ID, "original"); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "old-current":
				f.now = f.now.Add(6 * time.Second)
			case "cancelled":
				cancel()
			case "capture-scope-lost":
				f.identityChange = "scopes"
				x.current = f.source(t, ctx)
			case "original-interval":
				f.now = p.Deadline.Add(time.Second)
				x.current = f.source(t, ctx)
			case "audit-uncertain":
				x.intentErr = value.ErrUnavailable
			case "preparation-spent":
				x.startErr = value.ErrPreparationUncertain
			}
			_, err := s.Continue(ctx, x.current, p.ID, "original")
			if err == nil || f.admissions.Load() != 1 {
				t.Fatal("expired or uncertain operation renewed", err)
			}
			if mode != "preparation-spent" && x.starts != 0 {
				t.Fatal("unavailable continuation reached start")
			}
			if mode == "preparation-spent" && !errors.Is(err, value.ErrPreparationUncertain) {
				t.Fatal("lost uncertainty", err)
			}
		})
	}
}

type shortenedContinuationIdentity struct {
	source identities.CurrentIdentity
	until  time.Time
}

func (s *shortenedContinuationIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	i, e := s.source.ResolveIdentity(ctx)
	if !s.until.IsZero() {
		i.ValidUntil = identity.Earlier(i.ValidUntil, s.until)
	}
	return i, e
}
func TestContextContinuationCarriesKnownShorterIdentityIntoStart(t *testing.T) {
	f, x, s, p := submissionTest(t)
	original := f.source(t, context.Background())
	if _, err := f.svc.Request(context.Background(), original, p.ID, "original"); err != nil {
		t.Fatal(err)
	}
	shortened := &shortenedContinuationIdentity{source: original}
	x.current = shortened
	x.intentHook = func() { shortened.until = f.now.Add(200 * time.Millisecond) }
	// Start receives the same caller, while the coordinator narrows its context.
	observer := continuationStartObserver{delegate: x, check: func(ctx context.Context) {
		d, ok := ctx.Deadline()
		if !ok || !d.Equal(shortened.until) {
			t.Error("known shorter identity bound discarded")
		}
	}}
	s.Start = observer
	if _, err := s.Continue(context.Background(), shortened, p.ID, "original"); err != nil {
		t.Fatal(err)
	}
}

type continuationStartObserver struct {
	delegate ContextAcceptedStart
	check    func(context.Context)
}

func (s continuationStartObserver) StartContext(ctx context.Context, current identities.CurrentIdentity, id string) error {
	s.check(ctx)
	return s.delegate.StartContext(ctx, current, id)
}
