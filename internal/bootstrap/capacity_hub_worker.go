package bootstrap

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"sync"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	cfg "asservat.local/asservat/internal/domain/configuration"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// CapacityHubWorkerDeployment is the fixed configuration/capacity composition
// inside A-HWORK. It reuses the existing exact scheduling Lease. The installed
// command selects this only after its producer emits the complete projection.
type CapacityHubWorkerDeployment struct {
	root            context.Context
	cancel          context.CancelFunc
	configuration   *HubWorkerDeployment
	activation      *kube.InstalledWorkerProjectionReader
	admission       *fleetapp.WorkerRuntimeAdmission
	input           contracts.HubWorkerDeployment
	mounts          *os.Root
	closeObserver   func()
	mu              sync.Mutex
	closed, running bool
	// contextDeletion and evidenceStoreID are the verified capacity
	// projection's deletion section and its qualification's single backend's
	// evidence store ID, once the capacity projection has opened; the context
	// deletion child purges only that store's attempts (ADR-205).
	contextDeletion *contracts.ContextDeletionDeployment
	evidenceStoreID string
	owners          sync.WaitGroup
	once            sync.Once
}

func NewProvisionedCapacityHubWorkerDeployment(ctx context.Context, files *os.Root) (*CapacityHubWorkerDeployment, error) {
	if ctx == nil || ctx.Err() != nil || files == nil {
		return nil, mounts.ErrUnavailable
	}
	root, cancel := context.WithCancel(ctx)
	d := &CapacityHubWorkerDeployment{root: root, cancel: cancel}
	complete := false
	defer func() {
		if !complete {
			d.Close()
		}
	}()
	var err error
	d.configuration, err = NewProvisionedHubWorkerDeployment(root, files)
	if err != nil {
		return nil, err
	}
	in, worker, err := readHubWorkerInputs(root, files)
	if err != nil || !kube.HubWorkerActivationBound(worker) {
		return nil, mounts.ErrUnavailable
	}
	d.closeObserver = in.closeHTTP
	ns := cfg.NamespaceRef{Name: worker.Namespace.Name, UID: worker.Namespace.UID}
	observer, err := kube.NewPermissionClient(in.kubernetes("kube-observer.token"), worker.ClusterID, ns, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	probe, err := kube.NewPermissionClient(in.kubernetes("kube-probe.token"), worker.ClusterID, ns, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.activation, err = kube.NewInstalledWorkerProjectionReader(observer, probe, worker)
	if err != nil {
		return nil, err
	}
	d.mounts, d.input = files, worker
	complete = true
	return d, nil
}

// One callback owns exactly these two concrete children. It propagates the
// original Lease context unchanged, cancels on the first completion, and joins
// both before returning to the leader. This is not a dispatch/task registry.
func runCapacityWorkerChildren(ctx context.Context, configuration, capacity func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || configuration == nil || capacity == nil {
		return mounts.ErrUnavailable
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- configuration(call) }()
	go func() { done <- capacity(call) }()
	err := <-done
	cancel()
	<-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return mounts.ErrUnavailable
	}
	return err
}

func (d *CapacityHubWorkerDeployment) Run() error {
	if d == nil || d.configuration == nil || d.activation == nil || d.configuration.leader == nil || d.configuration.reconciler == nil {
		return mounts.ErrUnavailable
	}
	d.mu.Lock()
	if d.closed || d.running || d.root == nil || d.root.Err() != nil {
		d.mu.Unlock()
		return mounts.ErrUnavailable
	}
	d.running = true
	d.owners.Add(1)
	d.mu.Unlock()
	defer func() { d.owners.Done(); d.Close() }()
	return d.configuration.leader.Run(d.root, func(lease context.Context) error {
		return runCapacityWorkerChildren(lease, d.configuration.runConfiguration, d.runCapacity)
	})
}

func (d *CapacityHubWorkerDeployment) Close() {
	if d == nil {
		return
	}
	d.once.Do(func() {
		d.mu.Lock()
		d.closed = true
		if d.cancel != nil {
			d.cancel()
		}
		d.mu.Unlock()
		// The composed root reaches every started child before waiting. Neither
		// child pool nor the projection handle closes while a callback owns it.
		d.owners.Wait()
		if d.configuration != nil {
			d.configuration.Close()
		}
		if d.closeObserver != nil {
			d.closeObserver()
		}
	})
}

// ContextDeletion returns the verified capacity projection's deletion
// section and evidence store ID, or false before the capacity projection
// has opened or without a section.
func (d *CapacityHubWorkerDeployment) ContextDeletion() (contracts.ContextDeletionDeployment, string, bool) {
	if d == nil {
		return contracts.ContextDeletionDeployment{}, "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.root == nil || d.root.Err() != nil || d.contextDeletion == nil || d.evidenceStoreID == "" {
		return contracts.ContextDeletionDeployment{}, "", false
	}
	return cloneContextDeletion(*d.contextDeletion), d.evidenceStoreID, true
}

// Both installed layouts call this only after their final current projection
// check succeeds. The pins identify the immutable backend; they do not renew
// any cleanup authority. SQL still authorizes every deletion transition.
func (d *CapacityHubWorkerDeployment) acceptContextDeletion(ctx context.Context, c contracts.CapacityDeployment, q capacityapp.CapacityQualification, until time.Time) error {
	if d == nil || ctx == nil || ctx.Err() != nil || !time.Now().Before(until) || !kube.ContextDeletionSectionValid(c.ContextDeletion, time.Now()) {
		return mounts.ErrUnavailable
	}
	if c.ContextDeletion == nil {
		return nil
	}
	if !q.Valid() || len(q.Backends) != 1 || q.RootBacking.RootID != c.PermissionRootID || q.RootBacking.InstallationID != c.InstallationID || c.InstallationID != d.input.InstallationID {
		return mounts.ErrUnavailable
	}
	section := cloneContextDeletion(*c.ContextDeletion)
	store := q.Backends[0].EvidenceStoreID
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || ctx.Err() != nil || !time.Now().Before(until) || d.contextDeletion != nil && (!reflect.DeepEqual(*d.contextDeletion, section) || d.evidenceStoreID != store) {
		return mounts.ErrUnavailable
	}
	d.contextDeletion, d.evidenceStoreID = &section, store
	return nil
}

func cloneContextDeletion(v contracts.ContextDeletionDeployment) contracts.ContextDeletionDeployment {
	roots := make([][]byte, len(v.EvidenceStore.Roots))
	for i, root := range v.EvidenceStore.Roots {
		roots[i] = bytes.Clone(root)
	}
	v.EvidenceStore.Roots = roots
	keys := make(map[string][]byte, len(v.Signing.PublicKeys))
	for id, key := range v.Signing.PublicKeys {
		keys[id] = bytes.Clone(key)
	}
	v.Signing.PublicKeys = keys
	return v
}
