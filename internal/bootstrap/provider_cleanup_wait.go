package bootstrap

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
)

type providerCleanupStartup struct {
	operation *kube.WorkerProjectionOperation
	admission *fleetapp.WorkerRuntimeAdmission
}

func (d *InstalledHubWorkerDeployment) runProviderCleanup(ctx context.Context) error {
	if d == nil || d.capacity == nil || d.capacity.admission == nil || d.capacity.activation == nil || d.capacity.mounts == nil || ctx == nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	b := d.capacity
	var mountUntil time.Time
	for ctx.Err() == nil {
		ready, err := b.activation.CleanupProjectionHint(ctx)
		if err != nil {
			return err
		}
		if ready {
			if mountUntil.IsZero() {
				mountUntil = time.Now().Add(projectionMountWait)
			}
			if !time.Now().Before(mountUntil) {
				return mounts.ErrUnavailable
			}
			child, files, err := d.openProviderCleanup(ctx)
			if !errors.Is(err, errCleanupProjectionMountPending) {
				if err != nil {
					return err
				}
				defer files.Close()
				defer child.Close()
				return child.Run(ctx)
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

func (d *InstalledHubWorkerDeployment) openProviderCleanup(ctx context.Context) (*CaptureCleanupWorkerDeployment, *os.Root, error) {
	b := d.capacity
	lease, err := b.admission.WaitCleanup(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer lease.Release()
	op, claim, err := b.activation.BeginCleanupProjectionOperation(lease.Context())
	if err != nil {
		return nil, nil, err
	}
	defer op.Close()
	files, err := b.mounts.OpenRoot(contracts.HubWorkerCleanupProjectionDirectory)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && op.Context().Err() == nil {
			return nil, nil, errCleanupProjectionMountPending
		}
		return nil, nil, mounts.ErrUnavailable
	}
	complete := false
	defer func() {
		if !complete {
			files.Close()
		}
	}()
	child, err := newCaptureCleanupWorkerDeployment(ctx, b.mounts, files, b.input, b.activation, claim, &providerCleanupStartup{op, b.admission})
	if err != nil {
		return nil, nil, err
	}
	if err = op.Finish(op.Context()); err != nil || ctx.Err() != nil || !time.Now().Before(op.FreshUntil()) {
		child.Close()
		return nil, nil, mounts.ErrUnavailable
	}
	complete = true
	return child, files, nil
}
