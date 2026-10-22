package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

var errInitialAuthorityReserved = errors.New("synthetic first worker reservation reached")

// This component probe stops at the first worker reservation. It performs no
// SQL, provider work or Job creation and does not attribute a native failure.
type initialAuthorityReservation struct {
	DownloadWorkerLedger
	calls     int
	authority artifact.DownloadAuthority
	deadline  time.Time
}

func (p *initialAuthorityReservation) ReserveDownloadWorker(ctx context.Context, _, _ string, a artifact.DownloadAuthority, _ value.DownloadWorkerProfile) (value.DownloadWorkerIntent, error) {
	p.calls++
	p.authority = a
	p.deadline, _ = ctx.Deadline()
	return value.DownloadWorkerIntent{}, errInitialAuthorityReserved
}

type initialAuthorityAttachment struct {
	ContextDownloadAttachments
	before func(context.Context, artifact.DownloadAuthority)
}

func (p initialAuthorityAttachment) ReadContextDownloadAttachment(ctx context.Context, id string, a artifact.DownloadAuthority) (ContextDownloadAttachment, error) {
	if p.before != nil {
		p.before(ctx, a)
	}
	return p.ContextDownloadAttachments.ReadContextDownloadAttachment(ctx, id, a)
}

func initialAuthorityFixture(t *testing.T) (boundWorkerFixture, *initialAuthorityReservation) {
	t.Helper()
	f := newBoundWorkerFixture(t)
	f.lookup.value = ContextDownloadAttachment{SessionID: f.f.s.ID, Scope: f.f.s.Scope, State: artifact.DownloadPreparing, ObservedAt: f.f.now, ValidUntil: f.f.a.ValidUntil}
	probe := &initialAuthorityReservation{DownloadWorkerLedger: f.launch}
	f.r.config.Dispatcher.Ledger = probe
	return f, probe
}

func TestContextRuntimeOneAuthorityObservationReachesFirstReservation(t *testing.T) {
	for _, delay := range []time.Duration{0, 1700 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			f, reserve := initialAuthorityFixture(t)
			original := f.f.a.ValidUntil
			beforeRead := 0
			f.lookup.before = func(int) { beforeRead = f.f.count("current-authority") }
			f.r.config.Authority = workerCurrentGateFunc(func(ctx context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
				// Deterministic elapsed source cost within the unchanged original
				// five seconds; no real sleep or renewed observation.
				f.advance(delay)
				return f.f.CheckDownloadCurrent(ctx, current, scope)
			})
			_, err := f.r.ContinueContextDownload(t.Context(), f.f, f.f.s, f.source)
			if !errors.Is(err, errInitialAuthorityReserved) || reserve.calls != 1 {
				t.Fatalf("first reservation not reached: calls=%d authority=%d err=%v", reserve.calls, f.f.count("current-authority"), err)
			}
			if beforeRead != 1 || f.lookup.reads != 1 || f.f.count("current-authority") != 1 {
				t.Fatalf("full authority checks before first SQL=%d total=%d SQL reads=%d; want one request-owned observation", beforeRead, f.f.count("current-authority"), f.lookup.reads)
			}
			if reserve.deadline.After(original) || reserve.authority.ValidUntil.After(original) || !f.f.now.Before(original) {
				t.Fatal("first reservation escaped the original interval")
			}
		})
	}
}

func TestContextRuntimeInitialAuthorityPreservesEveryOriginalCutoff(t *testing.T) {
	for _, which := range []string{"caller", "identity", "authority", "session", "source"} {
		t.Run(which, func(t *testing.T) {
			f, reserve := initialAuthorityFixture(t)
			short := f.f.now.Add(800 * time.Millisecond)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch which {
			case "caller":
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(ctx, short)
				defer stop()
			case "identity":
				f.f.identity.ValidUntil = short
			case "authority":
				f.f.a.ValidUntil = short
			case "session":
				f.f.s.Deadline = short
			case "source":
				f.source.ValidUntil = short
			}
			originalAuthority := f.f.a
			var readUntil, proofUntil time.Time
			f.r.config.Workers = initialAuthorityAttachment{ContextDownloadAttachments: f.lookup, before: func(call context.Context, a artifact.DownloadAuthority) {
				readUntil, _ = call.Deadline()
				proofUntil = a.ValidUntil
			}}
			_, err := f.r.ContinueContextDownload(ctx, f.f, f.f.s, f.source)
			if !errors.Is(err, errInitialAuthorityReserved) || reserve.calls != 1 || readUntil.IsZero() || proofUntil.IsZero() || readUntil.After(short) || proofUntil.After(short) || reserve.deadline.After(short) || reserve.authority.ValidUntil.After(short) {
				t.Fatal("an original cutoff was lost", which, readUntil, proofUntil, reserve.deadline, err)
			}
			if f.f.a != originalAuthority {
				t.Fatal("consuming the authority mutated its producer's value")
			}
		})
	}
}

func TestContextRuntimeInitialAuthorityRejectsInvalidFirstRead(t *testing.T) {
	for _, which := range []string{"source-expired-during-authority", "invalid-source", "wrong-profile", "authority-denied"} {
		t.Run(which, func(t *testing.T) {
			f, reserve := initialAuthorityFixture(t)
			switch which {
			case "source-expired-during-authority":
				f.source.ValidUntil = f.f.now.Add(100 * time.Millisecond)
				f.r.config.Authority = workerCurrentGateFunc(func(ctx context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
					f.advance(200 * time.Millisecond)
					return f.f.CheckDownloadCurrent(ctx, current, scope)
				})
			case "invalid-source":
				f.source.Scope.ArtifactID = "invalid"
			case "wrong-profile":
				f.r.config.Profile.Configuration.Generation++
			case "authority-denied":
				f.f.failure = "current-authority"
			}
			if _, err := f.r.ContinueContextDownload(t.Context(), f.f, f.f.s, f.source); err == nil || f.lookup.reads != 0 || reserve.calls != 0 {
				t.Fatal("invalid original authority reached a read or effect", which, f.lookup.reads, reserve.calls, err)
			}
		})
	}
}

func TestContextRuntimeInitialAuthorityHandoffRechecksLocalChanges(t *testing.T) {
	for _, which := range []string{"clock-rollback", "proof-expired", "caller-cancelled", "scope-changed", "current-path-missing"} {
		t.Run(which, func(t *testing.T) {
			f, reserve := initialAuthorityFixture(t)
			// A valid authority may begin before this owner. Rolling back only
			// past the owner's start must still refuse the immediate handoff.
			f.f.identity.VerifiedAt = f.f.now.Add(-time.Second)
			f.f.identity.ValidUntil = f.f.now.Add(4 * time.Second)
			f.f.a.CheckedAt = f.f.identity.VerifiedAt
			f.f.a.ValidUntil = f.f.identity.ValidUntil
			f.f.a.Environment.ObservedAt = f.f.identity.VerifiedAt
			f.f.a.Environment.ValidUntil = f.f.identity.ValidUntil
			f.f.a.Environment.Processing.ObservedAt = f.f.identity.VerifiedAt
			f.f.a.Environment.Processing.ValidUntil = f.f.identity.ValidUntil
			f.f.a.Retention.ObservedAt = f.f.identity.VerifiedAt
			f.f.a.Retention.ValidUntil = f.f.identity.ValidUntil
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			bound, call, end, first, err := f.r.beginRequest(ctx, f.f, f.f.s)
			if err != nil {
				t.Fatal("initial check", err)
			}
			defer end()
			switch which {
			case "clock-rollback":
				f.advance(-100 * time.Millisecond)
				if !first.Valid(f.f.now) {
					t.Fatal("test must distinguish owner rollback from proof expiry")
				}
			case "proof-expired":
				f.advance(5 * time.Second)
			case "caller-cancelled":
				cancel()
			case "scope-changed":
				first.Scope.ArtifactID = "30000000-0000-4000-8000-000000000099"
			case "current-path-missing":
				first.Environment.Path = artifact.DownloadPath{}
			}
			if _, _, err = bound.attachmentWithAuthority(call, f.f.s, first); err == nil || f.lookup.reads != 0 || reserve.calls != 0 {
				t.Fatal("invalid handoff reached SQL", which, f.lookup.reads, reserve.calls, err)
			}
		})
	}
}

func TestContextRuntimeOriginalObservationSurvivesUntilItsCutoff(t *testing.T) {
	for _, which := range []string{"revoked", "identity-changed", "expired", "cancelled"} {
		t.Run(which, func(t *testing.T) {
			f, reserve := initialAuthorityFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.lookup.before = func(int) {
				switch which {
				case "revoked":
					f.f.failure = "current-authority"
				case "identity-changed":
					f.f.identity.Groups = []string{"changed"}
				case "expired":
					f.advance(6 * time.Second)
				case "cancelled":
					cancel()
				}
			}
			_, err := f.r.ContinueContextDownload(ctx, f.f, f.f.s, f.source)
			if which == "revoked" || which == "identity-changed" {
				if !errors.Is(err, errInitialAuthorityReserved) || f.lookup.reads != 1 || reserve.calls != 1 || f.f.count("current-authority") != 1 {
					t.Fatal("bounded observation was reconstructed after attachment", which, f.lookup.reads, reserve.calls, err)
				}
			} else if err == nil || f.lookup.reads != 1 || reserve.calls != 0 {
				t.Fatal("an expired or cancelled operation reached reservation", which, f.lookup.reads, reserve.calls, err)
			}
		})
	}
}

func TestContextRuntimeInitialAuthorityCancellationJoinsBlockingRead(t *testing.T) {
	for _, which := range []string{"authority", "attachment"} {
		t.Run(which, func(t *testing.T) {
			f, reserve := initialAuthorityFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			block := func() { close(entered); <-release }
			if which == "authority" {
				f.r.config.Authority = workerCurrentGateFunc(func(call context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
					block()
					return f.f.CheckDownloadCurrent(call, current, scope)
				})
			} else {
				f.r.config.Workers = initialAuthorityAttachment{ContextDownloadAttachments: f.lookup, before: func(context.Context, artifact.DownloadAuthority) { block() }}
			}
			done := make(chan error, 1)
			go func() { _, err := f.r.ContinueContextDownload(ctx, f.f, f.f.s, f.source); done <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				close(release)
				t.Fatal("owned read did not start")
			}
			cancel()
			select {
			case err := <-done:
				close(release)
				t.Fatal("returned before the blocked read joined", err)
			default:
			}
			close(release)
			select {
			case err := <-done:
				if err == nil || reserve.calls != 0 {
					t.Fatal("cancelled original request reached reservation", err, reserve.calls)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled owned read did not join")
			}
		})
	}
}
