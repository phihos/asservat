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
	out, err := s.ContextProjectionPolicy(context.Background(), path.TargetClusterID, path.StoreID)
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
			out, err := s.ContextProjectionPolicy(ctx, path.TargetClusterID, path.StoreID)
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
		out, err := s.ContextProjectionPolicy(context.Background(), path.TargetClusterID, path.StoreID)
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
