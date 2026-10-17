package bootstrap

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// InstalledHubWorkerDeployment owns the four fixed A-HWORK children. Only
// configuration starts with the initial projection. Capacity and cleanup wait
// independently for their original journal's positively completed receipts.
// The private hub-worker command selects this composition for the complete
// protected provider layout. Native startup and active-actor qualification
// remain pending; no Helm or public collection is enabled.
type InstalledHubWorkerDeployment struct{ capacity *CapacityHubWorkerDeployment }

func NewInstalledHubWorkerDeployment(ctx context.Context, files *os.Root) (*InstalledHubWorkerDeployment, error) {
	d, err := NewProvisionedCapacityHubWorkerDeployment(ctx, files)
	if err != nil {
		return nil, err
	}
	return &InstalledHubWorkerDeployment{capacity: d}, nil
}

func (d *InstalledHubWorkerDeployment) Run() error {
	if d == nil || d.capacity == nil {
		return mounts.ErrUnavailable
	}
	b := d.capacity
	if b.configuration == nil || b.activation == nil || b.configuration.leader == nil || b.configuration.reconciler == nil {
		return mounts.ErrUnavailable
	}
	b.mu.Lock()
	if b.closed || b.running || b.root == nil || b.root.Err() != nil {
		b.mu.Unlock()
		return mounts.ErrUnavailable
	}
	b.running = true
	b.owners.Add(1)
	b.mu.Unlock()
	defer func() { b.owners.Done(); b.Close() }()
	return b.configuration.leader.Run(b.root, func(lease context.Context) error {
		return runInstalledWorkerChildren(lease, b.configuration.runConfiguration, b.runCapacity, d.runCleanup, d.runPermission)
	})
}

// Every child receives the same original Lease deadline/cancellation. The
// first return closes all four; this callback cannot report joined until all
// children have actually returned, including failed or still-closing work.
func runInstalledWorkerChildren(ctx context.Context, configuration, capacity, cleanup, permission func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || configuration == nil || capacity == nil || cleanup == nil || permission == nil {
		return mounts.ErrUnavailable
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 4)
	go func() { done <- hubWorkerChildStop("configuration", configuration(call)) }()
	go func() { done <- hubWorkerChildStop("capacity", capacity(call)) }()
	go func() { done <- hubWorkerChildStop("cleanup", cleanup(call)) }()
	go func() { done <- hubWorkerChildStop("permission", permission(call)) }()
	err := <-done
	cancel()
	<-done
	<-done
	<-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return mounts.ErrUnavailable
	}
	return err
}

var errCleanupProjectionMountPending = errors.New("cleanup projection mount pending")

func (d *InstalledHubWorkerDeployment) runCleanup(ctx context.Context) error {
	if d != nil && d.capacity != nil && d.capacity.input.Activation != nil && d.capacity.input.Activation.WorkerLayout == contracts.HubWorkerProviderInstalledLayout {
		return d.runProviderCleanup(ctx)
	}
	b := d.capacity
	var mountUntil time.Time
	for {
		claim, ready, until, err := b.activation.ReadCleanup(ctx)
		if err != nil {
			return err
		}
		if ready {
			if mountUntil.IsZero() {
				mountUntil = time.Now().Add(30 * time.Second)
			}
			if !time.Now().Before(mountUntil) {
				return mounts.ErrUnavailable
			}
			err = d.openCleanup(ctx, claim, until)
			if !errors.Is(err, errCleanupProjectionMountPending) {
				return err
			}
		}
		if ctx.Err() != nil || !time.Now().Before(until) {
			return mounts.ErrUnavailable
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (d *InstalledHubWorkerDeployment) openCleanup(ctx context.Context, claim contracts.CaptureCleanupProjectionClaim, until time.Time) error {
	if d == nil || d.capacity == nil || d.capacity.mounts == nil || d.capacity.activation == nil || ctx == nil || ctx.Err() != nil || claim.Receipt == nil || !time.Now().Before(until) {
		return mounts.ErrUnavailable
	}
	b := d.capacity
	files, err := b.mounts.OpenRoot(contracts.HubWorkerCleanupProjectionDirectory)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && ctx.Err() == nil && time.Now().Before(until) {
			return errCleanupProjectionMountPending
		}
		return mounts.ErrUnavailable
	}
	defer files.Close()
	// The constructor freshly rechecks this exact receipt and workload before
	// any credential opens, then bounds all startup work by that observation.
	// The earlier read only selects the fixed mount; it confers no SQL effect.
	child, err := NewCaptureCleanupWorkerDeployment(ctx, files, b.input, b.activation, claim)
	if err != nil {
		return err
	}
	defer child.Close()
	return child.Run(ctx)
}

func (d *InstalledHubWorkerDeployment) Close() {
	if d != nil && d.capacity != nil {
		d.capacity.Close()
	}
}

// hubWorkerChildStop names the child that returned first, so the process's
// stop message carries a fixed child and stage name and the error class.
func hubWorkerChildStop(child string, err error) error {
	if err == nil {
		// Children run until cancelled; an early nil return is a stop too.
		return &fixedStepError{child + "/returned", mounts.ErrUnavailable}
	}
	return &fixedStepError{child, err}
}

// HubWorkerDiagnostic is the hub-worker's stop message: fixed child and stage
// names and the error class only, never provider, SQL or Kubernetes text.
func HubWorkerDiagnostic(err error) string {
	step := "startup"
	var inner interface{ FixedStep() string }
	if errors.As(err, &inner) {
		step = inner.FixedStep()
	}
	return "service stopped at " + step + " (" + errorClass(err) + "): protected configuration, credentials or original deadline unavailable"
}
