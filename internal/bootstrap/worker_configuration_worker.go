package bootstrap

import (
	"context"
	"fmt"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

// workerConfigurationObserver is the one call the child repeats.
type workerConfigurationObserver interface {
	Observe(context.Context) error
}

// workerConfigurationWorker is the ADR-204 decision 7 hub-worker child: the
// ADR-070 observer of the guarded worker profile source in the hub cluster's
// worker namespace. It stages each accepted revision in SQL, writes its
// encrypted snapshot under the section's own Transit key and acknowledges it
// with the separate audit login. It exists only with the projection's worker
// configuration section and runs beside the permission stream, like the
// retention source, because its section, logins and mount arrive with the
// permission projection after the Lease starts.
type workerConfigurationWorker struct {
	observer workerConfigurationObserver
	// read is the fixed outcome of the last failed source read: the observer
	// reports every read failure as unavailable.
	read    string
	closers []func()
}

func (w *workerConfigurationWorker) Close() {
	for i := len(w.closers) - 1; i >= 0; i-- {
		w.closers[i]()
	}
	w.closers = nil
}

// openWorkerConfiguration composes the child only with its section: without
// it there is no child, no login and no worker namespace client.
func openWorkerConfiguration(ctx context.Context, c contracts.PermissionDeployment, pools map[string]*pgxpool.Pool, local *providerInputs, writer *installedConfigurationAudit, admission *fleetapp.WorkerRuntimeAdmission) (*workerConfigurationWorker, error) {
	if c.WorkerConfiguration == nil {
		return nil, nil
	}
	return newWorkerConfigurationWorker(ctx, c, pools, local, writer, admission)
}

// newWorkerConfigurationWorker composes the observer from the permission
// projection's two worker configuration logins, the hub-worker's own observer
// and probe accounts bound to the worker namespace, and the shared audit
// principal with the section's Transit key.
func newWorkerConfigurationWorker(ctx context.Context, c contracts.PermissionDeployment, pools map[string]*pgxpool.Pool, local *providerInputs, writer *installedConfigurationAudit, admission *fleetapp.WorkerRuntimeAdmission) (_ *workerConfigurationWorker, err error) {
	v := c.WorkerConfiguration
	if v == nil || !kube.WorkerConfigurationSectionValid(c) || local == nil || writer == nil || writer.providers == nil || admission == nil || ctx == nil || ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	w := &workerConfigurationWorker{}
	defer func() {
		if err != nil {
			w.Close()
		}
	}()
	namespace := cfg.NamespaceRef{Name: v.Namespace.Name, UID: v.Namespace.UID}
	observer, err := kube.NewPermissionClient(local.kubernetes("kube-observer.token"), c.Control.ClusterID, namespace, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	probe, err := kube.NewPermissionClient(local.kubernetes("kube-probe.token"), c.Control.ClusterID, namespace, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	admins, pin := capacityWorkerGuard(v.Guard)
	guard, err := kube.NewWorkerConfigurationProtection(observer, probe, cfg.WorkerAdministration{Name: v.Guard.Name, SourceName: v.Source.Name, ControlNamespace: namespace, Administrators: admins}, pin)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	source, err := kube.NewWorkerConfigurationSource(observer, guard, v.Source.Name, v.Source.UID, c.InstallationID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	ledger, err := postgres.NewWorkerConfigurations(ctx, pools["worker-config-observe"], c.InstallationID, c.Control.ClusterID, v.Namespace.UID, v.Source.UID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	acknowledgements, err := postgres.NewWorkerConfigurations(ctx, pools["worker-config-audit"], c.InstallationID, c.Control.ClusterID, v.Namespace.UID, v.Source.UID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	seal, open, err := writer.providers.AuditKeys(v.AuditTransit.Mount, v.AuditTransit.Key)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	w.closers = append(w.closers, seal.Close, open.Close)
	objects := &installedWorkerConfigurationAudit{installation: c.InstallationID, admission: admission, audit: writer, seal: seal, open: open}
	w.observer = &evidence.WorkerConfigurationObserver{Reader: stagedWorkerConfigurationSource{source, &w.read}, Ledger: ledger, Audit: objects, Acknowledgements: acknowledgements, Now: time.Now}
	return w, nil
}

// run observes the source once a second until the Lease ends, so an accepted
// revision stays within its five-second freshness. A failed read fences the
// SQL head inside the observer; nothing here extends a deadline. It never
// returns early, because a returning child tears down its siblings.
func (w *workerConfigurationWorker) run(ctx context.Context) {
	last := "ok"
	for ctx.Err() == nil {
		w.read = ""
		outcome := regionalOutcome(w.observer.Observe(ctx))
		if outcome != "ok" && w.read != "" {
			outcome = w.read
		}
		if outcome != last && ctx.Err() == nil {
			last = outcome
			fmt.Fprintln(os.Stderr, "hub-worker worker configuration: "+outcome)
		}
		if !sleepContext(ctx, time.Second) {
			return
		}
	}
}

// stagedWorkerConfigurationSource records the fixed class of a failed read
// for the diagnostic above; it changes no behavior.
type stagedWorkerConfigurationSource struct {
	*kube.WorkerConfigurationSource
	read *string
}

func (s stagedWorkerConfigurationSource) ReadWorkerConfiguration(ctx context.Context) (authorization.DownloadWorkerObservation, error) {
	out, err := s.WorkerConfigurationSource.ReadWorkerConfiguration(ctx)
	if err != nil {
		*s.read = regionalOutcome(&fixedStepError{"source", err})
	}
	return out, err
}

// installedWorkerConfigurationAudit writes one revision's encrypted snapshot
// under one provider audit operation. Revisions are rare, so it shares the
// authority audit admission and audit-only storage principal, as retention
// acceptance does (ADR-195), but seals with the section's own Transit key.
// A busy admission slot fails this attempt; the next observation retries and
// reuses an object already written for the same revision.
type installedWorkerConfigurationAudit struct {
	installation string
	admission    *fleetapp.WorkerRuntimeAdmission
	audit        *installedConfigurationAudit
	seal         *kms.Sealer
	open         *kms.Opener
}

func (s *installedWorkerConfigurationAudit) WriteWorkerConfiguration(ctx context.Context, c authorization.DownloadWorkerConfiguration) (audit.Receipt, error) {
	if s == nil || s.admission == nil || s.audit == nil || s.audit.providers == nil || s.seal == nil || s.open == nil || ctx == nil || ctx.Err() != nil || !c.Valid() || c.Profile.InstallationID != s.installation {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	lease, err := s.admission.WaitAuthorityAudit(ctx)
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.admission", mounts.ErrUnavailable}
	}
	defer lease.Release()
	if err = lease.AwaitFleetObservation(); err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.fleet", mounts.ErrUnavailable}
	}
	operation, err := s.audit.providers.BeginAuthorityAudit(lease.Context())
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.begin", mounts.ErrUnavailable}
	}
	defer operation.Close()
	call := operation.Context()
	material, err := operation.Credentials()
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.credentials", mounts.ErrUnavailable}
	}
	store, err := s.audit.storage(material)
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.storage", err}
	}
	defer store.Close()
	writer := &objectstore.WorkerConfigurationAuditObjects{Store: store, Seal: s.seal, Open: s.open}
	receipt, err := writer.WriteWorkerConfiguration(call, c)
	if err != nil || call.Err() != nil {
		return audit.Receipt{}, &fixedStepError{"audit.write", mounts.ErrUnavailable}
	}
	if err = operation.Finish(); err != nil || call.Err() != nil {
		return audit.Receipt{}, &fixedStepError{"audit.finish", mounts.ErrUnavailable}
	}
	return receipt, nil
}
