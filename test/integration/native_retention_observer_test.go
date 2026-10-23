package integration

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This owns only ongoing observations of the original synthetic fixture roots.
// No request, operation, identity, evidence lifetime, revision or activation is
// renewed. The worker source joins this owner only after its exact acceptance.
// A failed refresh cancels the whole native fixture and is reported at Close.
type nativeFixtureSourceOwner struct {
	ctx       context.Context
	closeOnce sync.Once
	close     func()
	workerMu  sync.Mutex
	worker    func(context.Context) error
}

func newNativeFixtureSourceOwner(t *testing.T, parent context.Context, base func(context.Context) error) *nativeFixtureSourceOwner {
	t.Helper()
	o := &nativeFixtureSourceOwner{}
	o.ctx, o.close = startNativeFixtureObservations(t, parent, func(call context.Context) error {
		if err := base(call); err != nil {
			return err
		}
		o.workerMu.Lock()
		worker := o.worker
		o.workerMu.Unlock()
		// No callback runs while holding the hook-registration mutex.
		if worker != nil {
			return worker(call)
		}
		return nil
	})
	t.Cleanup(o.Close) // Includes setup failures before a normal defer exists.
	return o
}
func (o *nativeFixtureSourceOwner) Close() { o.closeOnce.Do(o.close) }
func (o *nativeFixtureSourceOwner) SetWorker(t *testing.T, observe func(context.Context) error) {
	t.Helper()
	o.workerMu.Lock()
	defer o.workerMu.Unlock()
	if observe == nil || o.worker != nil || o.ctx.Err() != nil {
		t.Fatal("native worker observation registration unavailable")
	}
	o.worker = observe
}

func startNativeScenarioSources(t *testing.T, parent context.Context, admin *pgxpool.Pool, s captureAdmissionScenario) *nativeFixtureSourceOwner {
	t.Helper()
	binding := s.recovery.observation
	if binding.installation != s.recovery.installation || binding.sourceUID != "synthetic-recovery" || binding.sourceGeneration != 1 || binding.sourceDigest != "6161616161616161616161616161616161616161616161616161616161616161" {
		t.Fatal("original synthetic recovery binding unavailable")
	}
	return newNativeFixtureSourceOwner(t, parent, func(call context.Context) error {
		if err := renewSyntheticFleetObservation(call, admin, binding, 30*time.Second, true); err != nil {
			return err
		}
		if _, err := s.p.RenewPermissions(call, cfg.PermissionFence{RootID: s.batch.RootID, Epoch: s.batch.Epoch, TrustDigest: s.batch.TrustDigest}); err != nil {
			return err
		}
		// This is the sole writer of this native scenario's retention fence.
		// Accepted readers below perform no observation or ownership writes.
		fence, err := s.retention.sources.RenewRetention(call, s.retention.fence)
		if err != nil {
			return err
		}
		s.retention.fence = fence
		if err = s.retention.observe(call); err != nil {
			return err
		}
		batch := s.batch
		batch.Initial = nil
		batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		batch.FreshUntil = batch.ObservedAt.Add(5 * time.Second)
		return s.p.RefreshPermissions(call, batch)
	})
}

func nativeFixtureAcceptedRetention(s captureAdmissionScenario) privacyapp.AcceptedRetentionReader {
	return privacyapp.AcceptedRetentionReader{Topology: s.retention.topology, Sources: s.retention.reader, Now: time.Now}
}
func nativeFixtureRetainedPolicies(s captureAdmissionScenario) privacyapp.RetainedPolicyReader {
	if s.nativeSources == nil {
		return s.retention // Preserve ordinary fixtures' existing setup contract.
	}
	return nativeFixtureAcceptedRetention(s)
}
func nativeFixturePublicationPolicies(ctx context.Context, s captureAdmissionScenario) (privacy.PolicySet, error) {
	if s.nativeSources == nil {
		return s.retention.policies(ctx)
	}
	return nativeFixtureAcceptedRetention(s).RetentionPolicies(ctx, s.retention.target)
}

// Read the exact source under a separate fixture-admin observation, never add
// privileges to its runtime reader. No UPDATE, freshening or synthetic expiry
// is used by this regression; it crosses the actual original observation end.
func qualifyNativeRetentionObservation(t *testing.T, admin *pgxpool.Pool, s captureAdmissionScenario, gate authapp.ContextDownloadAuthority) {
	t.Helper()
	if s.nativeSources == nil {
		t.Fatal("native retention owner missing")
	}
	s.nativeSources.Close()
	// The accepted observation lives up to 30 seconds (migration 00075).
	ctx, stop := context.WithTimeout(context.Background(), 40*time.Second)
	defer stop()
	type stamp struct {
		observed, fresh, lease time.Time
		epoch                  string
		sequence               int64
	}
	read := func() stamp {
		t.Helper()
		var row stamp
		ref := s.retention.fence.Source
		err := admin.QueryRow(ctx, "SELECT observed_at,fresh_until,lease_until,epoch::text,sequence FROM retention_source WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3", s.a.RootID, ref.ClusterID, ref.ControlNamespaceUID).Scan(&row.observed, &row.fresh, &row.lease, &row.epoch, &row.sequence)
		if err != nil {
			t.Fatal("native retention source snapshot", err)
		}
		return row
	}
	original := read()
	resolver, ok := gate.Retention.(privacyapp.RetentionResolver)
	if !ok {
		t.Fatal("native retained reader composition")
	}
	var origins []artifact.RetentionRule
	// The accepted original capture rules remain the exact historical scope.
	for _, p := range s.a.Plan.Input.Retention.Policies {
		origins = append(origins, p)
	}
	for i := 0; i < 3; i++ {
		policy, err := resolver.RetainedPolicies.RetainedRetentionPolicies(ctx, s.retention.target, origins)
		if err != nil || !policy.Proof.Valid(time.Now()) || policy.FreshUntil.After(original.fresh) {
			t.Fatal("current native retention read", err)
		}
		if read() != original {
			t.Fatal("retention read refreshed the original source")
		}
	}
	timer := time.NewTimer(time.Until(original.fresh.Add(20 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("retention observation expiry wait", ctx.Err())
	}
	if _, err := resolver.RetainedPolicies.RetainedRetentionPolicies(ctx, s.retention.target, origins); err == nil {
		t.Fatal("expired observer source was refreshed by a read")
	}
	if read() != original {
		t.Fatal("denied read changed expired retention source")
	}
}

func TestNativeFixtureSourceOwnerJoinsRefresh(t *testing.T) {
	for _, end := range []string{"close", "parent-cancel", "setup-goexit"} {
		t.Run(end, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			entered, joined := make(chan struct{}), make(chan struct{})
			refresh := func(ctx context.Context) error {
				if calls.Add(1) == 1 {
					return nil
				}
				close(entered)
				<-ctx.Done()
				close(joined)
				return ctx.Err()
			}
			var owner *nativeFixtureSourceOwner
			t.Run("setup", func(t *testing.T) {
				owner = newNativeFixtureSourceOwner(t, parent, refresh)
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("fixture refresh never entered")
				}
				switch end {
				case "close":
					owner.Close()
				case "parent-cancel":
					cancel()
					owner.Close()
				case "setup-goexit":
					t.Skip("exercise the cleanup path used by setup Goexit")
				}
			})
			select {
			case <-joined:
			default:
				t.Fatal("source cleanup returned before the admitted refresh joined")
			}
			if owner.ctx.Err() == nil {
				t.Fatal("closed owner retained live fixture context")
			}
			owner.Close() // Multiple cleanup owners still join one original loop.
		})
	}
}
