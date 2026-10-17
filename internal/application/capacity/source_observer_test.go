package capacity

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

type capacityObserverFixture struct {
	now                                                                time.Time
	observation                                                        CapacitySourceObservation
	protection                                                         CapacitySourceProtection
	recovery                                                           artifact.RecoveryProof
	accepted                                                           AcceptedCapacitySource
	journalReads, sourceReads, protectionReads, accepts, invalidations int
	lastInvalidated                                                    int64
	lastDeadline                                                       time.Time
	phase                                                              func(string)
	fail                                                               string
}

func (f *capacityObserverFixture) step(ctx context.Context, name string) error {
	if d, ok := ctx.Deadline(); ok {
		f.lastDeadline = d
	}
	if f.phase != nil {
		f.phase(name)
	}
	if name == f.fail {
		return cfg.ErrUnavailable
	}
	return ctx.Err()
}
func (f *capacityObserverFixture) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, f.step(ctx, "recovery")
}
func (f *capacityObserverFixture) CapacityProtection(ctx context.Context) (CapacitySourceProtection, error) {
	f.protectionReads++
	return f.protection, f.step(ctx, "protection")
}
func (f *capacityObserverFixture) ReadCapacitySource(ctx context.Context) (CapacitySourceObservation, error) {
	f.sourceReads++
	return f.observation, f.step(ctx, "source")
}
func (f *capacityObserverFixture) ReadCapacitySourceRevision(ctx context.Context, _ artifact.RecoveryProof) (int64, error) {
	f.journalReads++
	return 7, f.step(ctx, "revision")
}
func (f *capacityObserverFixture) AcceptCapacitySource(ctx context.Context, in CapacitySourceAcceptance) (AcceptedCapacitySource, error) {
	f.accepts++
	if in.ExpectedRevision != 7 || !in.Valid(f.now) {
		return AcceptedCapacitySource{}, cfg.ErrChanged
	}
	return f.accepted, f.step(ctx, "accept")
}
func (f *capacityObserverFixture) InvalidateCapacitySource(ctx context.Context, root string, revision int64, r artifact.RecoveryProof, start, end time.Time) error {
	f.invalidations++
	f.lastInvalidated = revision
	if root != f.accepted.RootID || !r.Valid(f.now) || end.After(f.lastDeadline) || start.After(f.now) || !f.now.Before(end) {
		return cfg.ErrChanged
	}
	return f.step(ctx, "invalidate")
}
func capacityObserverTestFixture() (*CapacitySourceObserver, *capacityObserverFixture) {
	a, _, _, _, prior, old := enrollmentObservationFacts()
	n := time.Now().UTC().Truncate(time.Microsecond)
	shift := n.Sub(old)
	a.ObservedAt = a.ObservedAt.Add(shift)
	a.FreshUntil = a.FreshUntil.Add(shift)
	a.Observation.Snapshot.ObservedAt = a.Observation.Snapshot.ObservedAt.Add(shift)
	a.Observation.Snapshot.FreshUntil = a.Observation.Snapshot.FreshUntil.Add(shift)
	prior.Recovery.ObservedAt = prior.Recovery.ObservedAt.Add(shift)
	prior.Recovery.FreshUntil = prior.Recovery.FreshUntil.Add(shift)
	a.Revision = 8
	f := &capacityObserverFixture{now: n, observation: a.Observation, recovery: prior.Recovery, accepted: a, protection: CapacitySourceProtection{ClusterID: a.Observation.Snapshot.ClusterID, ControlNamespaceUID: a.Observation.Snapshot.ControlNamespace.UID, Digest: a.ProtectionDigest, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}}
	s := &CapacitySourceObserver{RootID: a.RootID, InstallationID: a.InstallationID, QualificationID: a.QualificationID, QualificationDigest: a.QualificationDigest, Source: f, Protection: f, Recovery: f, Journal: f, Now: func() time.Time { return f.now }}
	return s, f
}
func TestCapacitySourceObserverAcceptsOnlyJoinedCurrentFacts(t *testing.T) {
	s, f := capacityObserverTestFixture()
	out, e := s.Observe(context.Background())
	if e != nil || out.Revision != 8 || out.Observation.Digest != f.observation.Digest || f.accepts != 1 || f.invalidations != 0 || f.journalReads != 1 {
		t.Fatalf("current accepted source unavailable: %v", e)
	}
}
func TestCapacitySourceObserverPreservesOriginalDeadlinesAfterEveryRead(t *testing.T) {
	for _, phase := range []string{"recovery", "protection", "source", "parent"} {
		t.Run(phase, func(t *testing.T) {
			s, f := capacityObserverTestFixture()
			until := f.now.Add(100 * time.Millisecond)
			ctx := context.Background()
			var cancel context.CancelFunc
			switch phase {
			case "recovery":
				f.recovery.FreshUntil = until
			case "protection":
				f.protection.FreshUntil = until
			case "source":
				f.observation.Snapshot.FreshUntil = until
				f.accepted.Observation = f.observation
			case "parent":
				ctx, cancel = context.WithDeadline(ctx, until)
				defer cancel()
			}
			f.accepted.FreshUntil = until
			f.phase = func(p string) {
				if p == "accept" {
					if !f.lastDeadline.Equal(until) {
						t.Error("SQL acceptance received later bound")
					}
					f.now = until
				}
			}
			if _, e := s.Observe(ctx); !errors.Is(e, cfg.ErrUnavailable) || f.accepts != 1 || f.invalidations != 0 {
				t.Fatalf("late SQL result became current or repeated: %v", e)
			}
		})
	}
}
func TestCapacitySourceObserverFailureFencesOnlyObservedCAS(t *testing.T) {
	for _, phase := range []string{"recovery", "revision", "protection", "source", "accept"} {
		t.Run(phase, func(t *testing.T) {
			s, f := capacityObserverTestFixture()
			f.fail = phase
			_, e := s.Observe(context.Background())
			if !errors.Is(e, cfg.ErrUnavailable) {
				t.Fatalf("phase error lost: %v", e)
			}
			// The source fixture phase is labelled "read" in diagnostics.
			label := map[string]string{"source": "read"}[phase]
			if label == "" {
				label = phase
			}
			var step interface{ FixedStep() string }
			if !errors.As(e, &step) || step.FixedStep() != label {
				t.Fatalf("phase %s labelled %v", phase, e)
			}
			want := 0
			if phase == "protection" || phase == "source" {
				want = 1
			}
			if f.invalidations != want || want == 1 && f.lastInvalidated != 7 {
				t.Fatal("failure inferred a new sequence or replayed uncertain acceptance")
			}
		})
	}
}
func TestCapacitySourceObserverCancellationCannotDetachInvalidation(t *testing.T) {
	s, f := capacityObserverTestFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.phase = func(p string) {
		if p == "source" {
			cancel()
		}
	}
	if _, e := s.Observe(ctx); e == nil || f.accepts != 0 || f.invalidations != 0 {
		t.Fatal("cancelled source spawned effects outside caller ownership")
	}
}
func TestCapacitySourceObserverRejectsChangedAcknowledgementAndExpiredProof(t *testing.T) {
	for _, phase := range []string{"root", "qualification", "protection", "revision", "extended", "expired"} {
		t.Run(phase, func(t *testing.T) {
			s, f := capacityObserverTestFixture()
			switch phase {
			case "root":
				f.accepted.RootID = f.accepted.InstallationID
			case "qualification":
				f.accepted.QualificationDigest[0]++
			case "protection":
				f.accepted.ProtectionDigest[0]++
			case "revision":
				f.accepted.Revision = 9
			case "extended":
				f.protection.FreshUntil = f.now.Add(time.Second)
			case "expired":
				f.phase = func(p string) {
					if p == "source" {
						f.now = f.protection.FreshUntil
					}
				}
			}
			if _, e := s.Observe(context.Background()); e == nil {
				t.Fatal("changed or expired result accepted")
			}
			if phase == "expired" && f.accepts != 0 {
				t.Fatal("expired protection authorized SQL acceptance")
			}
		})
	}
}
