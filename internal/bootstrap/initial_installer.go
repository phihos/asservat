package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/apimachinery/pkg/util/validation"
)

type initialInputs struct {
	*providerInputs
	config   contracts.InitialInstaller
	scope    value.InstallationWitnessScope
	workload cfg.InitialWorkloadAdministration
	plan     artifact.Digest
}

func initialGuard(g contracts.OwnerDeploymentGuard, source string, ns cfg.NamespaceRef) (cfg.ConfigMapAdministration, kube.GuardPin) {
	p := cfg.ConfigMapAdministration{Name: g.Name, SourceName: source, ControlNamespace: ns}
	for _, a := range g.Administrators {
		p.Administrators = append(p.Administrators, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
	}
	return p, kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}
}

func readInitialInputs(ctx context.Context, files *os.Root) (*initialInputs, error) {
	b, err := mounts.Read(ctx, files, "deployment.json", contracts.OwnerDeploymentMaxBytes)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeInitialInstaller(bytes.NewReader(b))
	if err != nil || (c.Handover != "" && c.Handover != contracts.InitialPreparationHandoverProtocol) || !contracts.InitialInstallerFormatSupported(c.Format) {
		return nil, mounts.ErrUnavailable
	}
	if c.SchemaInitialization != "" || c.Schema != nil {
		if c.SchemaInitialization != contracts.InitialSchemaProtocol || c.Schema == nil || c.Handover != contracts.InitialPreparationHandoverProtocol {
			return nil, mounts.ErrUnavailable
		}
		if _, err := postgres.InitialSchemaIncarnation(*c.Schema); err != nil {
			return nil, mounts.ErrUnavailable
		}
	}
	for _, id := range []string{c.InstallationID, c.IssuerEpoch, c.ClusterID} {
		if !authorization.UUID(id) {
			return nil, mounts.ErrUnavailable
		}
	}
	for _, r := range []contracts.WorkerObjectReference{c.Namespace, c.Witness, c.WriterAccount, c.ProbeAccount, c.Pod, c.FleetSource} {
		if !authorization.UUID(r.UID) || len(validation.IsDNS1123Subdomain(r.Name)) != 0 {
			return nil, mounts.ErrUnavailable
		}
	}
	if len(validation.IsDNS1123Label(c.Namespace.Name)) != 0 || len(validation.IsDNS1123Subdomain(c.Configuration)) != 0 {
		return nil, mounts.ErrUnavailable
	}
	ns := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	seen := map[string]bool{}
	for _, g := range []contracts.OwnerDeploymentGuard{c.WitnessGuard, c.FleetGuard, c.WorkloadGuard} {
		if seen[g.Name] || len(validation.IsDNS1123Subdomain(g.Name)) != 0 || !authorization.UUID(g.PolicyUID) || !authorization.UUID(g.BindingUID) || !identity.Text(g.BindingResourceVersion, 128) || g.PolicyGeneration < 1 || g.PolicyGeneration >= 1<<53 {
			return nil, mounts.ErrUnavailable
		}
		seen[g.Name] = true
		p, _ := initialGuard(g, c.Configuration, ns)
		if !p.Valid() {
			return nil, mounts.ErrUnavailable
		}
	}
	// Reuse the checked, provider-neutral connection fields. No synthetic role
	// or authority value is introduced; this performs only input validation.
	providers := contracts.HubWorkerDeployment{Format: contracts.HubWorkerDeploymentFormat, InstallationID: c.InstallationID, ClusterID: c.ClusterID, Namespace: c.Namespace, FleetSource: c.FleetSource, OwnerSource: c.Witness, FleetGuard: c.FleetGuard, OwnerGuard: c.WitnessGuard, LeaderLease: c.Pod, Kubernetes: c.Kubernetes, Postgres: c.Postgres, AuditStore: c.AuditStore, KeyService: c.KeyService}
	if validateHubWorkerInputs(providers) != nil {
		return nil, mounts.ErrUnavailable
	}
	scope := value.InstallationWitnessScope{InstallationID: c.InstallationID, IssuerEpoch: c.IssuerEpoch, ClusterID: c.ClusterID, Namespace: c.Namespace.Name, NamespaceUID: c.Namespace.UID, Name: c.Witness.Name, UID: c.Witness.UID, WriterAccount: c.WriterAccount.Name, WriterAccountUID: c.WriterAccount.UID}
	wp, _ := initialGuard(c.WorkloadGuard, c.Configuration, ns)
	workload := cfg.InitialWorkloadAdministration{Handover: c.Handover == contracts.InitialPreparationHandoverProtocol, Name: wp.Name, Configuration: c.Configuration, Witness: c.Witness.Name, FleetSource: c.FleetSource.Name, ControlNamespace: ns, PodName: c.Pod.Name, PodUID: c.Pod.UID, WriterAccount: c.WriterAccount.Name, WriterAccountUID: c.WriterAccount.UID, ProbeAccount: c.ProbeAccount.Name, ProbeAccountUID: c.ProbeAccount.UID, Administrators: wp.Administrators}
	digest, err := hex.DecodeString(c.PodSpecDigest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != c.PodSpecDigest {
		return nil, mounts.ErrUnavailable
	}
	copy(workload.PodSpecDigest[:], digest)
	if !scope.Valid() || !workload.Valid() {
		return nil, mounts.ErrUnavailable
	}
	canonical, err := json.Marshal(c)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	return &initialInputs{&providerInputs{oneShot: true, files: files, kubernetesEndpoint: c.Kubernetes, postgresEndpoint: c.Postgres}, c, scope, workload, artifact.Digest(sha256.Sum256(canonical))}, nil
}

type protectedInitialWitness struct {
	reader     *kube.InstallationWitnessReader
	consumer   *kube.InstallationWitnessConsumer
	protection *kube.InitialWorkloadProtection
}

func (w protectedInitialWitness) ReadInstallationWitness(ctx context.Context) (value.InstallationWitness, error) {
	until, err := w.protection.Current(ctx)
	if err != nil {
		return value.InstallationWitness{}, err
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	r, err := w.reader.ReadInstallationWitness(ctx)
	r.FreshUntil = identity.Earlier(r.FreshUntil, until)
	if err != nil || ctx.Err() != nil || !r.Valid(time.Now()) {
		return value.InstallationWitness{}, value.ErrUnavailable
	}
	return r, nil
}
func (w protectedInitialWitness) ConsumeInstallationWitness(ctx context.Context, c value.InitialActivationClaim) (value.InstallationWitness, error) {
	until, err := w.protection.Current(ctx)
	if err != nil {
		return value.InstallationWitness{}, err
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	r, err := w.consumer.ConsumeInstallationWitness(ctx, c)
	r.FreshUntil = identity.Earlier(r.FreshUntil, until)
	if err != nil || ctx.Err() != nil || !r.Valid(time.Now()) {
		return value.InstallationWitness{}, value.ErrUnavailable
	}
	return r, nil
}

type InitialInstallerDeployment struct {
	root        context.Context
	cancel      context.CancelFunc
	closers     []func()
	once        sync.Once
	running     atomic.Bool
	coordinator app.InitialInstaller
}

func NewInitialInstallerDeployment(ctx context.Context, files *os.Root) (*InitialInstallerDeployment, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	root, cancel := context.WithTimeout(ctx, time.Minute)
	d := &InitialInstallerDeployment{root: root, cancel: cancel}
	complete := false
	defer func() {
		if !complete {
			d.Close()
		}
	}()
	in, err := readInitialInputs(root, files)
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, in.closeHTTP)
	c, ns := in.config, in.workload.ControlNamespace
	writer, err := kube.NewPermissionClient(in.kubernetes("kube-writer.token"), c.ClusterID, ns, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	probe, err := kube.NewPermissionClient(in.kubernetes("kube-probe.token"), c.ClusterID, ns, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	_, pin := initialGuard(c.WorkloadGuard, c.Configuration, ns)
	protection, err := kube.NewInitialWorkloadProtection(writer, probe, in.workload, pin)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if _, err = protection.Current(root); err != nil {
		return nil, mounts.ErrUnavailable
	}
	wp, wg := initialGuard(c.WitnessGuard, c.Witness.Name, ns)
	witness, err := kube.NewInstallationWitnessReader(writer, probe, wp, wg, in.scope)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	consume, err := kube.NewInstallationWitnessConsumer(witness, writer)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	fp, fg := initialGuard(c.FleetGuard, c.FleetSource.Name, ns)
	fleetGuard, err := kube.NewFleetConfigurationProtection(writer, probe, fp, fg)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	source, err := kube.NewProtectedFleetSettings(writer, fleetGuard, c.FleetSource.Name, c.FleetSource.UID, c.InstallationID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	stores := map[string]*postgres.InitialInstallations{}
	users := map[string]bool{}
	for _, role := range []string{"prepare", "audit", "activate"} {
		pc, err := in.sqlConfig(root, "sql-"+role+".json")
		expected, scopeErr := postgres.InitialSQLRoleName(c.InstallationID, role)
		if err != nil || scopeErr != nil || pc == nil || pc.ConnConfig.User != expected || users[pc.ConnConfig.User] {
			return nil, mounts.ErrUnavailable
		}
		// Password validity is meaningful only when the server actually verifies
		// it. Never accept an HBA trust, cleartext-password or MD5 fallback.
		pc.ConnConfig.RequireAuth = "scram-sha-256"
		users[pc.ConnConfig.User] = true
		pool, err := pgxpool.NewWithConfig(root, pc)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		d.closers = append(d.closers, pool.Close)
		if c.Schema != nil {
			stores[role], err = postgres.NewInitialInstallationsForSchema(root, pool, in.scope, in.plan, *c.Schema)
		} else {
			stores[role], err = postgres.NewInitialInstallations(root, pool, in.scope, in.plan)
		}
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
	}
	h, err := ownerHTTP(c.KeyService.Endpoint, c.KeyService.Roots)
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, h.CloseIdleConnections)
	seal, err := kms.NewSealerWithTokenSource(c.KeyService.Endpoint, c.KeyService.AuditMount, c.KeyService.AuditKey, in.token("audit-wrap.token"), h)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, seal.Close)
	open, err := kms.NewOpenerWithTokenSource(c.KeyService.Endpoint, c.KeyService.AuditMount, c.KeyService.AuditKey, in.token("audit-unwrap.token"), h)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, open.Close)
	sh, err := ownerHTTP(c.AuditStore.Endpoint, c.AuditStore.Roots)
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, sh.CloseIdleConnections)
	store, err := in.auditStore(sh)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, store.Close)
	w := protectedInitialWitness{witness, consume, protection}
	d.coordinator = app.InitialInstaller{Witness: w, Consume: w, Administration: source, Preparation: stores["prepare"], Objects: &objectstore.InitialInstallationObjects{Store: store, Seal: seal, Open: open}, Acknowledgements: stores["audit"], Activation: stores["activate"], Now: time.Now}
	if root.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	complete = true
	return d, nil
}

func (d *InitialInstallerDeployment) Run() error {
	if d == nil || !d.running.CompareAndSwap(false, true) {
		return mounts.ErrUnavailable
	}
	defer d.Close()
	_, err := d.coordinator.Activate(d.root)
	if err == nil && d.root.Err() != nil {
		return mounts.ErrUnavailable
	}
	return err
}
func (d *InitialInstallerDeployment) Close() {
	if d == nil {
		return
	}
	d.once.Do(func() {
		d.cancel()
		for i := len(d.closers) - 1; i >= 0; i-- {
			d.closers[i]()
		}
	})
}
func RunInitialInstaller(ctx context.Context) error {
	files, err := os.OpenRoot(contracts.InitialInstallerRoot)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer files.Close()
	d, err := NewInitialInstallerDeployment(ctx, files)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Run()
}
