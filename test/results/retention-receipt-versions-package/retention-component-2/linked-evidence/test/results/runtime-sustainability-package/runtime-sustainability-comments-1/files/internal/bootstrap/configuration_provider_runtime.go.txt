package bootstrap

import (
	"context"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// NewProviderInstalledHubWorkerDeployment composes only the fresh joint v2
// profile selected by RunHubWorker from the complete protected provider layout.
// Native startup and active-actor qualification remain pending; this does not
// enable Helm or public collection.
func NewProviderInstalledHubWorkerDeployment(ctx context.Context, files *os.Root, podUID string) (*InstalledHubWorkerDeployment, error) {
	if ctx == nil || ctx.Err() != nil || files == nil {
		return nil, mounts.ErrUnavailable
	}
	root, cancel := context.WithCancel(ctx)
	worker := &HubWorkerDeployment{root: root, cancel: cancel}
	complete := false
	defer func() {
		if !complete {
			worker.Close()
		}
	}()
	loaded, err := newConfigurationProviderInputs(root, files, podUID)
	if err != nil {
		return nil, err
	}
	worker.input = loaded.deployment
	worker.closers = append(worker.closers, loaded.close)
	admission, err := app.NewWorkerRuntimeAdmission(root)
	if err != nil {
		return nil, err
	}
	worker.closers = append(worker.closers, admission.Close)
	worker.runtimeAdmission = admission
	startup, end := context.WithTimeout(root, 30*time.Second)
	defer end()
	in := loaded.deployment
	control := cfg.NamespaceRef{Name: in.Namespace.Name, UID: in.Namespace.UID}
	fleetSource, ownerSource, err := kube.NewConfigurationWorkerSourceReaders(loaded.provider)
	if err != nil {
		return nil, err
	}
	fleetStore, err := postgres.NewFleetObservation(startup, loaded.pools[0], in.InstallationID)
	if err != nil {
		return nil, err
	}
	ownerStore, err := postgres.NewOwnerConfigurations(startup, loaded.pools[1], in.InstallationID, in.ClusterID, in.Namespace.UID, in.OwnerSource.UID)
	if err != nil {
		return nil, err
	}
	ack, err := postgres.NewCurrentOwnerConfigurationAcknowledgements(startup, loaded.pools[2], in.InstallationID, in.ClusterID, in.Namespace.UID, in.OwnerSource.UID)
	if err != nil {
		return nil, err
	}
	provider, err := kms.NewInstalledConfigurationProviderEffects(root, in, files, loaded.provider, loaded.recovery, admission)
	if err != nil {
		return nil, err
	}
	worker.providers = provider
	audit, err := newInstalledConfigurationAudit(in, provider)
	if err != nil {
		return nil, err
	}
	worker.closers = append(worker.closers, audit.Close)
	worker.reconciler = &app.ConfigurationReconciler{
		Fleet: &app.TrustObserver{Settings: fleetSource, Projection: &configurationRuntimeFleetProjection{actual: fleetStore, admission: admission}, Now: time.Now},
		Owner: &app.OwnerConfigurationObserver{Reader: ownerSource, Ledger: ownerStore,
			Audit: audit, Acknowledgements: ack, Now: time.Now},
	}
	leaderClient, err := kube.NewPermissionClient(loaded.input.kubernetes("kube-leader.token"), in.ClusterID, control, time.Now)
	if err != nil {
		return nil, err
	}
	worker.leader, err = kube.NewReconciliationLeader(leaderClient, in.LeaderLease.Name, in.LeaderLease.UID, ownerRandomID())
	if err != nil || startup.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	capacity := &CapacityHubWorkerDeployment{root: root, cancel: cancel, configuration: worker,
		activation: loaded.activation, input: in, mounts: files, admission: admission}
	complete = true
	return &InstalledHubWorkerDeployment{capacity: capacity}, nil
}

// The provider loop and the original independently scheduled fleet/owner loops
// receive the same Lease cancellation. Missing provider/recovery authority does
// not prevent the fleet observer from maintaining its own accepted source.
func (d *HubWorkerDeployment) runConfiguration(ctx context.Context) error {
	if d == nil || d.reconciler == nil {
		return mounts.ErrUnavailable
	}
	if d.providers == nil {
		return d.reconciler.Run(ctx)
	}
	if d.runtimeAdmission == nil {
		return mounts.ErrUnavailable
	}
	return runConfigurationProviderChildren(ctx, func(call context.Context) error {
		return d.reconciler.RunWithIndependentOwnerAudit(call, d.runtimeAdmission)
	}, d.providers.Run)
}

func runConfigurationProviderChildren(ctx context.Context, configuration, provider func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || configuration == nil || provider == nil {
		return mounts.ErrUnavailable
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- configuration(call) }()
	go func() { done <- provider(call) }()
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
