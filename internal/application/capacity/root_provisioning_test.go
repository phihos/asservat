package capacity

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func rootProvisioningFixture(now time.Time) (RootBackingObservation, RootConfiguration) {
	in, pool := capacityRootBackingFixture()
	in.Capture.Policy.ValidUntil = now.Add(time.Hour)
	in.Normal.Policy.ValidUntil = in.Capture.Policy.ValidUntil
	in.Resolution.Policy.ValidUntil = in.Capture.Policy.ValidUntil
	in.Processing.Policy.ValidUntil = in.Capture.Policy.ValidUntil
	in.ProcessingState.ValidUntil = in.Capture.Policy.ValidUntil
	in.ProcessingState.RetireBy = in.Capture.Policy.ValidUntil.Add(7260 * time.Second)
	plan, e := CompileRootBacking(in, pool)
	if e != nil {
		panic(e)
	}
	_, d := plan.Canonical()
	recovery := artifact.RecoveryProof{InstallationID: in.InstallationID, IssuerEpoch: in.RootID, Revision: identity.Revision{UID: in.RootID, Generation: 1, Digest: artifact.Digest{1}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	o := RootBackingObservation{RootID: in.RootID, InstallationID: in.InstallationID, QualificationID: in.QualificationID, QualificationDigest: in.QualificationDigest, PlanDigest: d, SourceDigest: artifact.Digest{2}, SourceRevision: 1, Recovery: recovery, Processing: RootProcessingObservation{Revision: identity.Revision{UID: in.ProcessingSourceUID, Generation: 1, Digest: artifact.Digest{3}}, ProtectionDigest: in.ProcessingProtectionDigest, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Plan: plan, poolCanonical: "synthetic unit source"}
	v := RootConfiguration{Format: RootConfigurationFormat, RootID: in.RootID, AttemptID: "80000000-0000-4000-8000-000000000008", PlanDigest: d, Revision: 1, InitialObservedAt: now, InitialUntil: o.FreshUntil, RevisionObservedAt: now, RevisionUntil: o.FreshUntil, PlannedUntil: in.Capture.Policy.ValidUntil, ReservedAt: now}
	return o, v
}

type rootProvisioningStore struct {
	row    *RootConfiguration
	first  RootConfiguration
	now    *time.Time
	calls  []string
	lost   string
	mutate string
	hook   func(string)
}

func (s *rootProvisioningStore) step(ctx context.Context, name string) error {
	s.calls = append(s.calls, name)
	if s.hook != nil {
		s.hook(name)
	}
	return ctx.Err()
}
func (s *rootProvisioningStore) ReadCapacityRoot(ctx context.Context, o RootBackingObservation) (*RootConfiguration, error) {
	if e := s.step(ctx, "read"); e != nil || s.lost == "read" {
		return nil, errors.New("synthetic read failure")
	}
	if s.row == nil {
		return nil, nil
	}
	v := *s.row
	return &v, nil
}
func (s *rootProvisioningStore) ReserveCapacityRoot(ctx context.Context, o RootBackingObservation) (RootConfiguration, error) {
	if e := s.step(ctx, "reserve"); e != nil {
		return RootConfiguration{}, e
	}
	v := s.first
	s.row = &v
	if s.lost == "reserve" {
		return RootConfiguration{}, errors.New("synthetic lost SQL reply")
	}
	return v, nil
}
func (s *rootProvisioningStore) RenewCapacityRoot(ctx context.Context, o RootBackingObservation, v RootConfiguration) (RootConfiguration, error) {
	if e := s.step(ctx, "renew"); e != nil {
		return RootConfiguration{}, e
	}
	next := v
	next.Revision++
	next.RevisionObservedAt, next.RevisionUntil = o.ObservedAt, o.FreshUntil
	next.PlannedUntil, _ = o.ConfigurationUntil()
	next.ReservedAt = *s.now
	next.CaptureBackedAt, next.ReadyAt, next.ReconciledAt = nil, nil, nil
	next.PreviousDigest = artifact.Digest{7}
	next.ReconciledDigest = artifact.Digest{}
	s.row = &next
	if s.lost == "renew" {
		return RootConfiguration{}, errors.New("synthetic lost SQL renewal reply")
	}
	if s.mutate == "renew" {
		next.InitialUntil = o.FreshUntil
	}
	return next, nil
}

func (s *rootProvisioningStore) phase(ctx context.Context, v RootConfiguration, name string) (RootConfiguration, error) {
	if e := s.step(ctx, name); e != nil {
		return RootConfiguration{}, e
	}
	n := *s.now
	if name == "capture" {
		v.CaptureBackedAt = &n
	} else {
		v.ReadyAt = &n
	}
	s.row = &v
	if s.lost == name {
		return RootConfiguration{}, errors.New("synthetic lost SQL reply")
	}
	if s.mutate == name {
		v.AttemptID = "90000000-0000-4000-8000-000000000009"
	}
	return v, nil
}
func (s *rootProvisioningStore) BackCapacityRoot(ctx context.Context, o RootBackingObservation, v RootConfiguration) (RootConfiguration, error) {
	return s.phase(ctx, v, "capture")
}
func (s *rootProvisioningStore) PublishCapacityRoot(ctx context.Context, o RootBackingObservation, v RootConfiguration) (RootConfiguration, error) {
	return s.phase(ctx, v, "publish")
}

func TestCapacityRootUnknownReplyContinuesOnlyExactCommittedSQLPhase(t *testing.T) {
	for _, phase := range []string{"reserve", "capture", "publish"} {
		t.Run(phase, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			o, first := rootProvisioningFixture(now)
			s := &rootProvisioningStore{first: first, now: &now, lost: phase}
			c := RootBackingCoordinator{Store: s, Capture: s, Now: func() time.Time { return now }}
			if _, e := c.Reconcile(context.Background(), o); e == nil {
				t.Fatal("lost reply reported complete")
			}
			if s.row == nil || s.row.AttemptID != first.AttemptID {
				t.Fatal("committed original identity missing")
			}
			// Independently current source/recovery can finish SQL configuration past
			// the first permit, without changing any original first interval/date.
			now = now.Add(6 * time.Second)
			o.ObservedAt = now
			o.FreshUntil = now.Add(5 * time.Second)
			o.Recovery.ObservedAt = now
			o.Recovery.FreshUntil = o.FreshUntil
			o.Processing.ObservedAt = now
			o.Processing.FreshUntil = o.FreshUntil
			s.lost = ""
			s.calls = nil
			got, e := c.Reconcile(context.Background(), o)
			if e != nil || !got.AdmissionReady(now) || !got.InitialUntil.Equal(first.InitialUntil) || !got.RevisionUntil.Equal(first.RevisionUntil) || got.AttemptID != first.AttemptID {
				t.Fatal("original SQL continuation unavailable", e)
			}
			want := []string{"read"}
			if phase == "reserve" {
				want = append(want, "capture", "publish")
			}
			if phase == "capture" {
				want = append(want, "publish")
			}
			if !slices.Equal(s.calls, want) {
				t.Fatalf("repeated committed phase: %v", s.calls)
			}
		})
	}
}

func TestCapacityRootFailedReadOrExpiryDoesNotSelectNewAttempt(t *testing.T) {
	for _, mode := range []string{"read-failure", "expire-read", "expire-capture", "wrong-attempt", "reconciled"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			o, first := rootProvisioningFixture(now)
			s := &rootProvisioningStore{first: first, now: &now}
			c := RootBackingCoordinator{Store: s, Capture: s, Now: func() time.Time { return now }}
			switch mode {
			case "read-failure":
				s.lost = "read"
			case "expire-read":
				s.hook = func(name string) {
					if name == "read" {
						now = o.FreshUntil
					}
				}
			case "expire-capture":
				s.hook = func(name string) {
					if name == "capture" {
						now = o.FreshUntil
					}
				}
			case "wrong-attempt":
				s.mutate = "capture"
			case "reconciled":
				first.ReconciledAt = &now
				first.ReconciledDigest = artifact.Digest{9}
				s.row = &first
			}
			if _, e := c.Reconcile(context.Background(), o); e == nil {
				t.Fatal("unavailable root progressed")
			}
			if slices.Contains(s.calls, "publish") {
				t.Fatal("failed original state reached Ready")
			}
			if (mode == "read-failure" || mode == "expire-read" || mode == "reconciled") && slices.Contains(s.calls, "reserve") {
				t.Fatal("failed read manufactured an absence")
			}
		})
	}
}
