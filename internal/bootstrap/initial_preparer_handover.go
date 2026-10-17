package bootstrap

import (
	"context"
	"errors"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

func (d *InitialPreparationDeployment) prepareHistory(ctx context.Context) error {
	if d == nil || d.historyPool == nil || d.preparer == nil || d.configuration.Plan.HistoryManager == nil {
		return mounts.ErrUnavailable
	}
	protection, e := d.preparer.NewHistoryProtection(ctx)
	if e != nil {
		return e
	}
	scope, plan := protection.Scope()
	if e = postgres.CheckInitialSQLHistoryRole(ctx, d.historyPool, scope.InstallationID, *d.configuration.Plan.HistoryManager); e != nil {
		return e
	}
	d.history, e = postgres.NewInitialInstallationReader(ctx, d.historyPool, scope, plan, protection)
	return e
}

// continueHandover is the actual supervisor continuation. It never turns a saved
// unknown launch outcome into another UPDATE. Passive startup needs only the current
// bootstrap administrator/probe and SELECT-only history credentials; expired
// setup SQL/provider tokens are not reopened or used as a fallback.
func (d *InitialPreparationDeployment) continueHandover(ctx context.Context) (_ contracts.InitialPreparationRoot, err error) {
	phase := "handover-inputs"
	defer func() {
		if err != nil {
			err = initialPreparerRunFailure{phase, err}
		}
	}()
	var zero contracts.InitialPreparationRoot
	if d == nil || d.preparer == nil || !d.preparer.HandoverEnabled() {
		return zero, mounts.ErrUnavailable
	}
	if !d.passive {
		phase = "handover-review"
		if _, e := d.preparer.BeginHandover(ctx, d.providerIssuer); e != nil {
			return zero, e
		}
		phase = "history-reader"
		if e := d.prepareHistory(ctx); e != nil {
			return zero, e
		}
	}

	root, _, e := d.preparer.ReadHandover(ctx)
	if e != nil {
		return zero, e
	}
	if root.Activation.Handover.Cleanup != nil {
		return d.finishHandoverCleanup(ctx)
	}
	phase = "staging-retirement"
	for {
		_, e := d.preparer.RetireStaging(ctx)
		if e == nil {
			break
		}
		if !errors.Is(e, cfg.ErrUnavailable) {
			return zero, e
		}
		// Unknown outcomes permit exact read reconciliation only. A durably
		// acknowledged conflict permits one separately claimed conditional retry
		// within the original interval; a saved retry cannot dispatch again.
		select {
		case <-ctx.Done():
			return zero, mounts.ErrUnavailable
		case <-time.After(250 * time.Millisecond):
		}
	}
	phase = "original-pod-launch"
	if _, e := d.preparer.LaunchOriginalPod(ctx); e != nil {
		return zero, e
	}
	phase = "original-activation-result"
	for {
		observed, pod, e := observeInitialPreparationResult(ctx, d.history, func(ctx context.Context) (kube.InitialPreparationPodDisposition, error) {
			_, pod, err := d.preparer.ObserveOriginalActivation(ctx)
			return pod, err
		}, time.Now)
		if e != nil {
			return zero, e
		}
		if pod.Terminated {
			if pod.Phase != core.PodSucceeded || pod.ExitCode != 0 || observed.Disposition != fleetapp.InitialInstallationActivated {
				return zero, mounts.ErrUnavailable
			}

			d.historical = observed
			phase = "retirement-join"
			if _, e = d.preparer.BeginHandoverCleanup(ctx, observed); e != nil {
				return zero, e
			}
			return d.finishHandoverCleanup(ctx)

		}
		select {
		case <-ctx.Done():
			return zero, mounts.ErrUnavailable
		case <-time.After(time.Second):
		}
	}
}

func (d *InitialPreparationDeployment) finishHandoverCleanup(ctx context.Context) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	// ADR-187: completed cleanup is read through the bridge-aware handover
	// check; retirement, an effect path, is never repeated after the bridge.
	if root, passive, e := d.preparer.ReadHandover(ctx); e == nil && passive && d.preparer.HandoverCleanupComplete(root) {
		return d.completedHandover(ctx, root)
	}
	for {
		root, e := d.preparer.RetireHandover(ctx, d)
		if e != nil {
			if !errors.Is(e, cfg.ErrUnavailable) {
				return zero, e
			}
			// Only fixed idempotent rights reductions or exact original-object
			// absence checks are retried; this path has no CREATE/issuance operation.
			select {
			case <-ctx.Done():
				return zero, mounts.ErrUnavailable
			case <-time.After(250 * time.Millisecond):
			}
			continue
		}
		if d.preparer.HandoverCleanupComplete(root) {
			return d.completedHandover(ctx, root)
		}
	}
}

func (d *InitialPreparationDeployment) completedHandover(ctx context.Context, root contracts.InitialPreparationRoot) (contracts.InitialPreparationRoot, error) {
	observed, e := d.history.ObserveInitialInstallation(ctx)
	if e != nil || observed.Disposition != fleetapp.InitialInstallationActivated || observed.Record == nil || observed.Record.Claim.ID != root.Activation.Handover.Cleanup.ActivatedClaimID || !time.Now().Before(observed.ValidUntil) {
		return contracts.InitialPreparationRoot{}, mounts.ErrUnavailable
	}
	d.historical = observed
	return root, nil
}

// observeInitialPreparationResult orders independent observations so a terminal
// original Pod cannot be paired with an earlier pre-activation SQL snapshot.
// The Pod never supplies SQL authority: the history reader still verifies the
// exact original scope and claim. Its read retains the Pod/request deadline.
func observeInitialPreparationResult(ctx context.Context, history fleetapp.InitialInstallationHistory, observePod func(context.Context) (kube.InitialPreparationPodDisposition, error), now func() time.Time) (fleetapp.InitialInstallationObservation, kube.InitialPreparationPodDisposition, error) {
	var zero fleetapp.InitialInstallationObservation
	var none kube.InitialPreparationPodDisposition
	pod, err := observePod(ctx)
	if err != nil {
		return zero, none, err
	}
	if ctx.Err() != nil || !now().Before(pod.ValidUntil) {
		return zero, none, mounts.ErrUnavailable
	}
	bounded, stop := context.WithDeadline(ctx, pod.ValidUntil)
	defer stop()
	observed, err := history.ObserveInitialInstallation(bounded)
	if err != nil {
		return zero, none, err
	}
	// Preserve the first Pod/request interval in the value handed to cleanup,
	// even if a history implementation returns a broader observation interval.
	deadline, _ := bounded.Deadline()
	if deadline.Before(observed.ValidUntil) {
		observed.ValidUntil = deadline
	}
	if bounded.Err() != nil || !now().Before(observed.ValidUntil) || !now().Before(pod.ValidUntil) {
		return zero, none, mounts.ErrUnavailable
	}
	return observed, pod, nil
}
