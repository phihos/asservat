package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// A pending journal read is only a notification hint. It neither opens optional
// credentials nor begins a native proof while another fixed actor owns admission.
func (d *CapacityHubWorkerDeployment) runProviderCapacity(ctx context.Context) error {
	if d == nil || d.admission == nil || d.activation == nil || d.mounts == nil || ctx == nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	var mountUntil time.Time
	// One closed waiting state per change, so a capacity child that never
	// starts is visible (ADR-197 CI continuation run 13).
	waiting := ""
	wait := func(state string) {
		if state != waiting {
			waiting = state
			fmt.Fprintln(os.Stderr, "capacity waiting: "+state)
		}
	}
	for ctx.Err() == nil {
		ready, err := d.activation.CapacityProjectionHint(ctx)
		if err != nil {
			return &fixedStepError{"hint", err}
		}
		if !ready {
			wait("projection hint pending")
		}
		if ready {
			if mountUntil.IsZero() {
				mountUntil = time.Now().Add(30 * time.Second)
			}
			if !time.Now().Before(mountUntil) {
				return &fixedStepError{"mount-wait", mounts.ErrUnavailable}
			}
			child, files, err := d.openProviderCapacity(ctx)
			if errors.Is(err, errCapacityProjectionMountPending) {
				wait("projection mount pending")
			}
			if !errors.Is(err, errCapacityProjectionMountPending) {
				if err != nil {
					return &fixedStepError{"open", err}
				}
				waiting = ""
				fmt.Fprintf(os.Stderr, "capacity started with %d regional clusters\n", len(child.regional))
				err = d.runProviderCapacityChild(ctx, child, files)
				// ADR-197 decision 6: a changed effective cluster set replaces
				// only this child; the process, its Lease and the configuration
				// reconciler keep running, so fleet trust stays current.
				if errors.Is(err, errCapacityClustersChanged) {
					fmt.Fprintln(os.Stderr, "capacity clusters changed; capacity restarts with the new set")
					mountUntil = time.Time{}
					continue
				}
				return err
			}
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ctx.Err()
}

func childInstalledCapacityClaim(d *CapacityWorkerDeployment) contracts.CapacityRuntimeProjectionClaim {
	if d == nil || d.installedClaim == nil {
		return contracts.CapacityRuntimeProjectionClaim{}
	}
	return *d.installedClaim
}

// The startup proof remains finite, but the child lifetime is the original
// Lease context. A failed final observation closes the constructed pools; no
// source or reconciliation loop has started at that point.
func (d *CapacityHubWorkerDeployment) openProviderCapacity(ctx context.Context) (*CapacityWorkerDeployment, *os.Root, error) {
	lease, err := d.admission.WaitCapacity(ctx)
	if err != nil {
		return nil, nil, &fixedStepError{"admission", err}
	}
	defer lease.Release()
	op, claim, err := d.activation.BeginCapacityProjectionOperation(lease.Context())
	if err != nil {
		return nil, nil, &fixedStepError{"operation", err}
	}
	defer op.Close()
	files, err := d.mounts.OpenRoot(contracts.CapacityWorkerProjectionDirectory)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && op.Context().Err() == nil {
			return nil, nil, errCapacityProjectionMountPending
		}
		return nil, nil, &fixedStepError{"mount", mounts.ErrUnavailable}
	}
	complete := false
	defer func() {
		if !complete {
			files.Close()
		}
	}()
	selected := &installedCapacityWorkerInputs{files: d.mounts, worker: d.input, expected: claim, until: op.FreshUntil(), startup: op.Context()}
	child, err := newCapacityWorkerDeployment(ctx, files, selected)
	if err != nil {
		return nil, nil, &fixedStepError{"deployment", err}
	}
	if err = op.Finish(op.Context()); err != nil || ctx.Err() != nil || !time.Now().Before(op.FreshUntil()) {
		child.Close()
		return nil, nil, &fixedStepError{"finish", errors.Join(mounts.ErrUnavailable, err)}
	}
	if err = d.acceptContextDeletion(ctx, child.input, child.reconciler.Work.Qualification, op.FreshUntil()); err != nil {
		child.Close()
		return nil, nil, &fixedStepError{"context-deletion", err}
	}
	complete = true
	return child, files, nil
}

// runProviderCapacityChild runs one opened child; its scoped pools and files
// stay owned until the child has joined.
func (d *CapacityHubWorkerDeployment) runProviderCapacityChild(ctx context.Context, child *CapacityWorkerDeployment, files *os.Root) error {
	defer files.Close()
	defer child.Close()
	source, err := newProviderCapacitySourceInvocation(child, d.activation, childInstalledCapacityClaim(child), d.input, d.admission)
	if err != nil {
		return &fixedStepError{"source", err}
	}
	err = child.run(ctx, func(call context.Context) error {
		return child.watchClusters(call, func(c context.Context) error { return child.reconciler.RunWithSourceInvocation(c, source) })
	})
	if errors.Is(err, errCapacityClustersChanged) {
		return err
	}
	if err != nil {
		return &fixedStepError{"run", err}
	}
	return nil
}
