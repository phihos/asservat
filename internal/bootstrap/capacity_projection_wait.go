package bootstrap

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

var errCapacityProjectionMountPending = errors.New("capacity projection mount pending")

// projectionMountWait bounds how long a Lease-owned child waits for the
// kubelet to add an acknowledged projection to its already-mounted volume.
// Kubelet refreshes mounted ConfigMap/Secret volumes only on a Pod resync:
// syncFrequency (default 1m) jittered by up to 1.5x, i.e. up to 90s, plus
// watch/cache propagation ("kubelet sync period + cache propagation delay",
// kubernetes.io/docs/concepts/configuration/configmap/#mounted-configmaps-are-updated-automatically).
// The former 30s bound was shorter than that and exited healthy processes
// (measured 2026-10-26: mount pending 30s, exit, restart, 17s Lease wait).
// Original setup/operation deadlines still apply inside each attempt.
const projectionMountWait = 2 * time.Minute

func capacityProjectionMatches(c contracts.CapacityDeployment, m contracts.CapacityCredentialManifest, p contracts.CapacityRuntimeProjectionClaim, worker contracts.HubWorkerDeployment) bool {
	a := worker.Activation
	w := m.Input.Worker
	return a != nil && p.Receipt != nil && p.Receipt.Secret.Name == contracts.CapacityRuntimeProjectionName(worker.InstallationID) &&
		c.InstallationID == worker.InstallationID && c.Control.ClusterID == worker.ClusterID && c.Control.Namespace == worker.Namespace &&
		m.Input.ClusterID == worker.ClusterID && m.Input.Namespace == worker.Namespace && m.Input.OwnerConfigurationUID == worker.OwnerSource.UID &&
		w.Resources == a.Resources && w.ResourceSetupID == a.SetupID && w.ResourceBinding == a.BindingDigest && w.WorkerLayout == a.WorkerLayout &&
		w.Deployment.Reference == a.Deployment && w.Account.Reference == a.ServiceAccount && w.Lease.Reference == worker.LeaderLease &&
		reflect.DeepEqual(m.Capacity, p.Setup) && kube.CapacityRuntimePublicDigest(c, m) == p.PublicDigest
}

// One Lease-owned child waits on positive public provenance. Missing files are
// never inspected while pending and cannot select an alternate constructor.
// The original setup expiry remains enforced by the concrete reader; ordinary
// completed restart uses current protection and the exact historical receipt.
func (d *CapacityHubWorkerDeployment) runCapacity(ctx context.Context) error {
	if d != nil && d.input.Activation != nil && d.input.Activation.WorkerLayout == contracts.HubWorkerProviderInstalledLayout {
		return d.runProviderCapacity(ctx)
	}
	var mountUntil time.Time
	for {
		claim, ready, until, err := d.activation.ReadCapacity(ctx)
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
			err = d.openCapacity(ctx, claim, until)
			if !errors.Is(err, errCapacityProjectionMountPending) {
				return err
			}
		}
		if !time.Now().Before(until) {
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

func (d *CapacityHubWorkerDeployment) openCapacity(ctx context.Context, claim contracts.CapacityRuntimeProjectionClaim, until time.Time) error {
	if d == nil || d.mounts == nil || d.activation == nil || ctx == nil || ctx.Err() != nil || claim.Receipt == nil || !time.Now().Before(until) {
		return mounts.ErrUnavailable
	}
	// The finite current receipt read authorizes selecting only this exact
	// mounted public bundle. It is not carried as SQL/operation authority.
	read, end := context.WithDeadline(ctx, until)
	files, err := d.mounts.OpenRoot(contracts.CapacityWorkerProjectionDirectory)
	if err != nil {
		end()
		if errors.Is(err, fs.ErrNotExist) && ctx.Err() == nil && time.Now().Before(until) {
			return errCapacityProjectionMountPending
		}
		return mounts.ErrUnavailable
	}
	defer files.Close()
	c, m, q, err := readCapacityWorkerInputs(read, files)
	end()
	if err != nil || !capacityProjectionMatches(c, m, claim, d.input) || ctx.Err() != nil || !time.Now().Before(until) {
		return mounts.ErrUnavailable
	}
	capacity, err := NewInstalledCapacityWorkerDeployment(ctx, files, d.mounts, d.input, d.activation, claim)
	if err != nil {
		return err
	}
	defer capacity.Close()
	current, ready, after, err := d.activation.ReadCapacity(ctx)
	if err != nil || !ready || !reflect.DeepEqual(current, claim) || !capacityProjectionMatches(capacity.input, capacity.manifest, current, d.input) || ctx.Err() != nil || !time.Now().Before(after) {
		return mounts.ErrUnavailable
	}
	if after.Before(until) {
		until = after
	}
	if err = d.acceptContextDeletion(ctx, c, q, until); err != nil {
		return err
	}
	capacity.reconciler.Source.Protection = &installedCapacitySourceProtection{reader: d.activation, claim: claim, worker: d.input, input: capacity.input, manifest: capacity.manifest, source: capacity.reconciler.Source.Protection}
	// No Run call can occur before both actual SQL scope verifications and the
	// final exact native receipt/workload observation. Cancellation joins the
	// concrete child before its scoped pools or mounted root are closed.
	defer d.guards.share(capacity.reconciler.Clusters)()
	return capacity.Run(ctx)
}
