package kubernetes

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestConfigurationWorkerLaunchOpaqueZeroAndForeignPhaseDeny(t *testing.T) {
	var zero *ConfigurationWorkerLaunchOperation
	if _, _, err := zero.enter(context.Background(), nil, configurationWorkerPhaseIntent, configurationWorkerPhasePostLock); err == nil {
		t.Fatal("zero launch operation admitted a phase")
	}
	for _, mode := range []string{"foreign root", "unbound context", "out of order", "closed owner", "expired"} {
		t.Run(mode, func(t *testing.T) {
			owner, worker := configurationWorkerOperationFixture(t)
			launch, err := newConfigurationWorkerLaunchOperation(owner, worker.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer launch.close()
			worker = launch.worker
			worker.phase = configurationWorkerPhaseIntent
			root, call := owner.roles, worker.ctx
			switch mode {
			case "foreign root":
				root = &ConfigurationRuntimeRoleRoot{}
			case "unbound context":
				call = context.Background()
			case "closed owner":
				owner.mu.Lock()
				owner.closed = true
				owner.mu.Unlock()
			case "expired":
				worker.until = time.Now().Add(-time.Millisecond)
			case "out of order":
				worker.phase = configurationWorkerPhaseJoined
			}
			if _, done, err := launch.enter(call, root, configurationWorkerPhaseIntent, configurationWorkerPhasePostLock); err == nil || done != nil {
				if done != nil {
					done(context.Canceled)
				}
				t.Fatal("foreign launch phase admitted")
			}
		})
	}
}

func TestConfigurationWorkerLaunchRejectsCopiedOpaqueWrapper(t *testing.T) {
	owner, base := configurationWorkerOperationFixture(t)
	launch, err := newConfigurationWorkerLaunchOperation(owner, base.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer launch.close()
	launch.worker.phase = configurationWorkerPhaseIntent // Phase ownership only; no native/SQL authority.
	copied := *launch
	if _, done, err := copied.enter(launch.worker.ctx, owner.roles, configurationWorkerPhaseIntent, configurationWorkerPhasePostLock); err == nil || done != nil {
		if done != nil {
			done(context.Canceled)
		}
		t.Fatal("copied launch wrapper consumed the original opaque phase")
	}
	// Rejecting copies must not be implemented as rejecting every launch handle.
	_, done, err := launch.enter(launch.worker.ctx, owner.roles, configurationWorkerPhaseIntent, configurationWorkerPhasePostLock)
	if err != nil || done == nil {
		t.Fatal("original opaque launch handle rejected", err)
	}
	done(nil)
}

func TestConfigurationWorkerLaunchReceiptTransitionRetainsOriginalClaim(t *testing.T) {
	input, resources, roles, inert, now := configurationWorkerLaunchPlanFixture(t)
	plan, err := configurationWorkerLaunchPlanFor(input, resources, roles, inert, ownerID(17310), now, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	old := roles.State
	claimed := old
	claimed.Launch = &plan.claim
	if !configurationWorkerLaunchTransition(old, claimed) {
		t.Fatal("original launch claim rejected")
	}
	observed := plan.claim
	observed.Receipt = &contracts.ConfigurationRuntimeLaunchReceipt{ResourceVersion: "20", ObservedAt: now.Add(6 * time.Second)}
	complete := claimed
	complete.Launch = &observed
	if !configurationWorkerLaunchTransition(claimed, complete) || !configurationRoleStateValid(roles.State.Input, complete, now.Add(6*time.Second)) {
		t.Fatal("truthful later original launch receipt rejected")
	}
	for _, mode := range []string{"renew end", "new operation", "different input", "different original workload", "replace receipt", "remove claim", "alter role"} {
		t.Run(mode, func(t *testing.T) {
			from, to := claimed, complete
			copyLaunch := *complete.Launch
			to.Launch = &copyLaunch
			switch mode {
			case "renew end":
				to.Launch.Until = to.Launch.Until.Add(time.Second)
			case "new operation":
				to.Launch.OperationID = ownerID(17311)
			case "different input":
				to.Launch.Configuration.UID = ownerID(17312)
			case "different original workload":
				to.Launch.Sources.WorkloadDigest = "changed"
			case "replace receipt":
				from = complete
			case "remove claim":
				to.Launch = nil
			case "alter role":
				to.OperationID = ownerID(17313)
			}
			if configurationWorkerLaunchTransition(from, to) {
				t.Fatal("receipt changed original launch authority")
			}
		})
	}
}

func TestConfigurationWorkerLaunchDriverUncertainReceiptIsInspectionOnly(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "committed"}[committed], func(t *testing.T) {
			run := configurationWorkerLaunchRun{}
			first := ConfigurationWorkerLaunchAdvance{Progress: ConfigurationWorkerLaunchPending}
			if !run.continueAfter(first, nil, true) {
				t.Fatal("positive original launch did not progress to receipt")
			}
			unknown := ConfigurationWorkerLaunchAdvance{Progress: ConfigurationWorkerLaunchSpent, receiptUncertain: true, needsInspection: true, Snapshot: contracts.ConfigurationRuntimeRoleSnapshot{UID: ownerID(17400)}}
			unknown = run.observed(unknown, cfg.ErrUnavailable)
			if !run.continueAfter(unknown, cfg.ErrUnavailable, true) || !run.receiptUncertain {
				t.Fatal("unknown receipt lost its one inspection")
			}
			next := unknown
			next.Progress = ConfigurationWorkerLaunchPending
			if committed {
				next.Progress = ConfigurationWorkerLaunchAcknowledged
			}
			next = run.observed(next, nil)
			if run.continueAfter(next, nil, true) {
				t.Fatal("inspection admitted another launch/receipt attempt")
			}
			if next.Snapshot.UID != unknown.Snapshot.UID {
				t.Fatal("inspection changed original root")
			}
		})
	}
	run := configurationWorkerLaunchRun{}
	spent := ConfigurationWorkerLaunchAdvance{Progress: ConfigurationWorkerLaunchSpent}
	if run.continueAfter(spent, cfg.ErrUnavailable, true) {
		t.Fatal("spent claim without effect triggered generic retry")
	}
}
