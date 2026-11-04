package authorization

import (
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/privacy"
	"context"
	"testing"
	"time"
)

func TestProjectionPoliciesUseExactSharedPlacementWithoutDownloadEntitlement(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	s, err := NewContextProjectionPolicies(f, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	path := f.policy.Paths[0]
	out, err := s.ContextProjectionPolicy(context.Background(), path.TargetClusterID, path.StoreID, "")
	if err != nil || !out.Valid(f.now) || out.Path.Purpose != value.ContextProjectionPurpose || out.Path.ID != path.ID || out.Path.WorkerConfiguration != path.WorkerConfiguration || f.policyReads != 1 {
		t.Fatal("shared protected placement", err)
	}
	if !out.ObservedAt.Equal(f.policy.ObservedAt) || !out.FreshUntil.Equal(f.policy.FreshUntil) {
		t.Fatal("policy dates renewed")
	}
	f.policy.Clients[0].Purposes[0] = "changed"
	f.policy.PermittedRegions[0] = "changed"
	if out.Clients[0].Purposes[0] == "changed" || out.PermittedRegions[0] == "changed" {
		t.Fatal("policy retains source slices")
	}
}

func TestProjectionPoliciesRefuseUnavailableOrAmbiguousPlacement(t *testing.T) {
	for _, mode := range []string{"wrong-target", "wrong-store", "ambiguous", "suspended", "expired", "beyond-shared-lease", "cancel-after-read", "short-parent"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _, _ := newEnvironmentFixture()
			s, _ := NewContextProjectionPolicies(f, func() time.Time { return f.now })
			path := f.policy.Paths[0]
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			switch mode {
			case "wrong-target":
				path.TargetClusterID = "90000000-0000-4000-8000-000000000001"
			case "wrong-store":
				path.StoreID = "90000000-0000-4000-8000-000000000001"
			case "ambiguous":
				other := path
				other.ID = "90000000-0000-4000-8000-000000000001"
				f.policy.Paths = append(f.policy.Paths, other)
			case "suspended":
				f.policy.Suspended = true
			case "expired":
				f.now = f.policy.FreshUntil
			case "beyond-shared-lease":
				f.policy.FreshUntil = f.policy.ObservedAt.Add(time.Minute + time.Microsecond)
			case "cancel-after-read":
				f.policyHook = stop
			case "short-parent":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, f.now.Add(time.Second))
				defer cancel()
			}
			out, err := s.ContextProjectionPolicy(ctx, path.TargetClusterID, path.StoreID, "")
			if mode == "short-parent" {
				d, _ := ctx.Deadline()
				if err != nil || !out.FreshUntil.Equal(d) {
					t.Fatal("original caller bound lost", err)
				}
				return
			}
			if err == nil {
				t.Fatal("unavailable protected placement accepted")
			}
		})
	}
}

// The installed approved query shares the download path's bounded policy
// observation. Composed over the raw protected source, every authority check
// paid four full live policy reads (each about 14 API reads, 3 probe requests
// and a denied dry-run) inside one five-second request (native63).
func TestProjectionPoliciesReuseTheSharedPolicyObservation(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	now := func() time.Time { return f.now }
	shared, err := NewDownloadPolicyObservations(f, now)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewContextProjectionPolicies(shared, now)
	if err != nil {
		t.Fatal(err)
	}
	path := f.policy.Paths[0]
	for range 4 {
		out, err := s.ContextProjectionPolicy(context.Background(), path.TargetClusterID, path.StoreID, "")
		if err != nil || !out.Valid(f.now) || !out.ObservedAt.Equal(f.policy.ObservedAt) {
			t.Fatal("shared placement observation refused", err)
		}
	}
	if f.policyReads != 1 {
		t.Fatal("live protected policy reads per query", f.policyReads)
	}
	if value.ContextProjectionPolicyInterval != privacy.DownloadPolicyObservationInterval {
		t.Fatal("projection and download share one observation interval")
	}
}

// The lookup budget bounds I/O, not the lifetime of its completed protected
// observation. A six-second approved read still belongs to its original caller.
func TestProjectionPoliciesKeepSharedObservationBeyondLookupDeadline(t *testing.T) {
	for _, parentInterval := range []time.Duration{0, 20 * time.Second, time.Second} {
		t.Run(parentInterval.String(), func(t *testing.T) {
			f, _, _, _ := newEnvironmentFixture()
			started := f.now
			originalObserved, originalFresh := f.policy.ObservedAt, f.policy.FreshUntil
			now := func() time.Time { return f.now }
			readDeadlineChecked := false
			shared, err := NewDownloadPolicyObservations(observationPolicyReader(func(read context.Context) (privacy.DownloadPolicy, error) {
				deadline, ok := read.Deadline()
				if !ok || deadline.After(started.Add(5*time.Second)) {
					t.Fatal("protected lookup exceeded its original five-second I/O budget", deadline)
				}
				readDeadlineChecked = true
				return f.DownloadPolicy(read)
			}), now)
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewContextProjectionPolicies(shared, now)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			wantUntil := started.Add(privacy.DownloadPolicyObservationInterval)
			if parentInterval > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, started.Add(parentInterval))
				defer cancel()
				wantUntil, _ = ctx.Deadline()
			}
			path := f.policy.Paths[0]
			out, err := service.ContextProjectionPolicy(ctx, path.TargetClusterID, path.StoreID, "")
			if err != nil || !out.Valid(f.now) || !out.ObservedAt.Equal(originalObserved) || !out.FreshUntil.Equal(wantUntil) {
				t.Fatalf("lookup deadline replaced source/caller bound: observed=%v until=%v want=%v error=%v", out.ObservedAt, out.FreshUntil, wantUntil, err)
			}
			if !readDeadlineChecked || f.policyReads != 1 || !f.policy.ObservedAt.Equal(originalObserved) || !f.policy.FreshUntil.Equal(originalFresh) {
				t.Fatal("lookup changed source observation or repeated live reads")
			}
			f.now = started.Add(6 * time.Second)
			wantValid := parentInterval == 0 || parentInterval > 6*time.Second
			if out.Valid(f.now) != wantValid {
				t.Fatal("six-second consumption lost original source/caller interval", out.FreshUntil)
			}
			if wantValid {
				again, err := service.ContextProjectionPolicy(ctx, path.TargetClusterID, path.StoreID, "")
				if err != nil || !again.ObservedAt.Equal(out.ObservedAt) || !again.FreshUntil.Equal(wantUntil) || f.policyReads != 1 {
					t.Fatal("cache hit renewed original observation or lost caller cutoff", err)
				}
			}
		})
	}
}
