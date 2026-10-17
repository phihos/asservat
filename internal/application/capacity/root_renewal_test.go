package capacity

import (
	"context"
	"slices"
	"testing"
	"time"
)

func currentRootObservation(o RootBackingObservation, now time.Time) RootBackingObservation {
	o.ObservedAt, o.FreshUntil = now, now.Add(5*time.Second)
	o.Recovery.ObservedAt, o.Recovery.FreshUntil = o.ObservedAt, o.FreshUntil
	o.Processing.ObservedAt, o.Processing.FreshUntil = o.ObservedAt, o.FreshUntil
	return o
}

func TestCapacityRootFirstDatesComeFromOriginalCurrentObservation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	old, _ := rootProvisioningFixture(now.Add(-2 * time.Hour))
	// Immutable qualification was packaged earlier. It must not manufacture a
	// current permit or prevent initial setup under a new protected observation.
	o := currentRootObservation(old, now)
	planned, ok := o.ConfigurationUntil()
	if !ok || !planned.Equal(now.Add(time.Hour)) || !o.Valid(now) {
		t.Fatal("current observation cannot derive fixed first configuration")
	}
	_, first := rootProvisioningFixture(now)
	first.PlanDigest = o.PlanDigest
	s := &rootProvisioningStore{first: first, now: &now}
	c := RootBackingCoordinator{Store: s, Capture: s, Now: func() time.Time { return now }}
	got, err := c.Reconcile(context.Background(), o)
	if err != nil || !got.AdmissionReady(now) || !got.PlannedUntil.Equal(planned) {
		t.Fatal("delayed first setup did not use its protected observation", err)
	}
	// Ordinary replay must retain the persisted end rather than derive a later
	// one from the fresh caller's clock.
	now = now.Add(time.Minute)
	s.calls = nil
	got2, err := c.Reconcile(context.Background(), currentRootObservation(o, now))
	if err != nil || !got2.PlannedUntil.Equal(got.PlannedUntil) || !slices.Equal(s.calls, []string{"read"}) {
		t.Fatal("ordinary replay extended first grant", err, s.calls)
	}
}

func TestCapacityRootRejectsUnboundFirstConfigurationDates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	o, first := rootProvisioningFixture(now)
	first.PlannedUntil = first.PlannedUntil.Add(time.Microsecond)
	s := &rootProvisioningStore{first: first, now: &now}
	c := RootBackingCoordinator{Store: s, Capture: s, Now: func() time.Time { return now }}
	if _, err := c.Reconcile(context.Background(), o); err == nil || slices.Contains(s.calls, "capture") {
		t.Fatal("unbound first dates reached capture credential")
	}
}

func TestCapacityRootExpiredPartialRenewalRetainsInitialIdentityAndLostReply(t *testing.T) {
	for _, phase := range []string{"reserve", "capture", "publish"} {
		t.Run(phase, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			o, first := rootProvisioningFixture(now)
			s := &rootProvisioningStore{first: first, now: &now, lost: phase}
			c := RootBackingCoordinator{Store: s, Capture: s, Now: func() time.Time { return now }}
			if _, err := c.Reconcile(context.Background(), o); err == nil {
				t.Fatal("unknown original phase reported success")
			}
			prior := *s.row
			now = prior.PlannedUntil.Add(time.Second)
			fresh := currentRootObservation(o, now)
			s.lost, s.calls = "renew", nil
			if _, err := c.Reconcile(context.Background(), fresh); err == nil || !slices.Equal(s.calls, []string{"read", "renew"}) {
				t.Fatal("unknown renewal continued effects", err, s.calls)
			}
			committed := *s.row
			if !prior.CompatibleRenewal(committed, fresh) || committed.InitialUntil != first.InitialUntil || committed.AttemptID != first.AttemptID {
				t.Fatal("renewal replaced original attempt or interval")
			}
			s.lost, s.calls = "", nil
			got, err := c.Reconcile(context.Background(), fresh)
			if err != nil || !got.AdmissionReady(now) || !slices.Equal(s.calls, []string{"read", "capture", "publish"}) || !got.PlannedUntil.Equal(committed.PlannedUntil) {
				t.Fatal("exact committed renewal lookup unavailable", err, s.calls)
			}
		})
	}
}

func TestCapacityRootRenewalRejectsLateOrReplacedOriginalResult(t *testing.T) {
	for _, mode := range []string{"late", "cancelled", "replaced-original"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			o, first := rootProvisioningFixture(now)
			now = first.PlannedUntil
			fresh := currentRootObservation(o, now)
			s := &rootProvisioningStore{row: &first, now: &now}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.hook = func(name string) {
				if name == "renew" {
					switch mode {
					case "late":
						now = fresh.FreshUntil
					case "cancelled":
						cancel()
					case "replaced-original":
						s.mutate = "renew"
					}
				}
			}
			c := RootBackingCoordinator{Store: s, Capture: s, Now: func() time.Time { return now }}
			if _, err := c.Reconcile(ctx, fresh); err == nil || slices.Contains(s.calls, "capture") || slices.Contains(s.calls, "publish") {
				t.Fatal("late or mismatched renewal reached another purpose", err, s.calls)
			}
		})
	}
}
