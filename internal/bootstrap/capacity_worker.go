package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This subsystem belongs to the existing protected A-HWORK process. Its Run
// context is the original Lease-owned child; no new leader or authority root
// is created here. Close joins started work before releasing scoped pools.
type CapacityWorkerDeployment struct {
	input           contracts.CapacityDeployment
	manifest        contracts.CapacityCredentialManifest
	installedClaim  *contracts.CapacityRuntimeProjectionClaim
	root            context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	closed, running bool
	owners          sync.WaitGroup
	once            sync.Once
	closers         []func()
	reconciler      *app.CapacityReconciler
	// ADR-197 decision 6: the regional pins read at start and their source.
	regional       []app.CapacityNamespaceQualification
	qualifications *postgres.CapacityClusterQualifications
}

// errCapacityClustersChanged stops the child when the effective cluster set
// changes; the restart reads the new set.
var errCapacityClustersChanged = errors.New("capacity clusters changed")

// watchClusters runs work and rereads the regional qualifications every
// fifteen seconds. A failed read is not a change.
func (d *CapacityWorkerDeployment) watchClusters(ctx context.Context, work func(context.Context) error) error {
	if d.qualifications == nil {
		return work(ctx)
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- work(call) }()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	failed := ""
	for {
		select {
		case err := <-done:
			return err
		case <-tick.C:
			current, err := d.qualifications.ReadCapacityClusterQualifications(call)
			// One line per change: a read that keeps failing never sees a
			// new cluster (ADR-197 CI continuation run 17a).
			outcome := ""
			if err != nil {
				outcome = regionalOutcome(err)
			}
			if outcome != failed {
				failed = outcome
				fmt.Fprintln(os.Stderr, "capacity clusters read: "+regionalOutcome(err))
			}
			if err == nil && !slices.EqualFunc(current, d.regional, func(a, b app.CapacityNamespaceQualification) bool {
				return a.ClusterID == b.ClusterID && a.Digest == b.Digest && slices.Equal(a.Keys, b.Keys)
			}) {
				cancel()
				<-done
				return errCapacityClustersChanged
			}
		}
	}
}

func capacityWorkerGuard(g contracts.OwnerDeploymentGuard) ([]cfg.KubernetesActor, kube.GuardPin) {
	a := make([]cfg.KubernetesActor, len(g.Administrators))
	for i, v := range g.Administrators {
		a[i] = cfg.KubernetesActor{Kind: v.Kind, Name: v.Name}
	}
	return a, kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}
}
func capacityWorkerRef(r contracts.WorkerObjectReference) cfg.NamespaceRef {
	return cfg.NamespaceRef{Name: r.Name, UID: r.UID}
}

func NewCapacityWorkerDeployment(ctx context.Context, files *os.Root) (*CapacityWorkerDeployment, error) {
	return newCapacityWorkerDeployment(ctx, files, nil)
}

func newCapacityWorkerDeployment(ctx context.Context, files *os.Root, installed *installedCapacityWorkerInputs) (_ *CapacityWorkerDeployment, err error) {
	// Fixed stage names for the hub-worker's stop message.
	at := "start"
	defer func() {
		if err != nil {
			err = &fixedStepError{at, err}
		}
	}()
	if ctx == nil || ctx.Err() != nil || files == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	readParent := ctx
	if installed != nil && installed.startup != nil {
		readParent = installed.startup
	}
	read, stopRead := context.WithCancel(readParent)
	if installed != nil {
		stopRead()
		read, stopRead = context.WithDeadline(readParent, installed.until)
	}
	at = "inputs"
	c, m, q, err := readCapacityWorkerInputs(read, files)
	stopRead()
	if err != nil {
		return nil, err
	}
	if installed == nil && c.LocalOwner != nil {
		return nil, mounts.ErrUnavailable
	}
	at = "matches"
	if installed != nil && !installed.matches(c, m) {
		return nil, mounts.ErrUnavailable
	}
	root, cancel := context.WithCancel(ctx)
	d := &CapacityWorkerDeployment{input: c, manifest: m, root: root, cancel: cancel}
	if installed != nil {
		var original contracts.CapacityRuntimeProjectionClaim
		raw, e := json.Marshal(installed.expected)
		if e != nil || json.Unmarshal(raw, &original) != nil {
			cancel()
			return nil, mounts.ErrUnavailable
		}
		d.installedClaim = &original
	}
	complete := false
	defer func() {
		if !complete {
			d.Close()
		}
	}()
	startupUntil := time.Now().Add(30 * time.Second)
	if installed != nil && installed.until.Before(startupUntil) {
		startupUntil = installed.until
	}
	startupParent := root
	if installed != nil && installed.startup != nil {
		startupParent = installed.startup
	}
	startup, end := context.WithDeadline(startupParent, startupUntil)
	defer end()
	controlInputs := &providerInputs{files: files, kubernetesEndpoint: c.Control.Kubernetes, postgresEndpoint: c.Postgres}
	d.closers = append(d.closers, controlInputs.closeHTTP)
	localInputs := controlInputs
	observerToken, probeToken, processingToken := "kube-capacity-observer.token", "kube-capacity-probe.token", "kube-capacity-processing-probe.token"
	at = "local-inputs"
	if installed != nil {
		localInputs, err = installed.localInputs(startup, c, m)
		if err != nil {
			return nil, err
		}
		d.closers = append(d.closers, localInputs.closeHTTP)
		observerToken, probeToken, processingToken = "kube-observer.token", "kube-probe.token", "kube-probe.token"
	}
	pools := map[string]*pgxpool.Pool{}
	for _, purpose := range contracts.CapacityRuntimePurposes() {
		at = "sql/" + purpose
		p, e := controlInputs.sqlConfig(startup, "sql-"+purpose+".json")
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		p.MaxConns, p.MinConns = 1, 0
		p.ConnConfig.RequireAuth = "scram-sha-256"
		p.ConnConfig.RuntimeParams["application_name"] = "asservat-capacity"
		pool, e := pgxpool.NewWithConfig(startup, p)
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		d.closers = append(d.closers, pool.Close)
		if postgres.VerifyCapacityRuntimeCredential(startup, pool, m, purpose, q) != nil {
			return nil, mounts.ErrUnavailable
		}
		pools[purpose] = pool
	}
	at = "accounts"
	accounts, err := ReadProjectedCaptureAccounts(startup, files, c.InstallationID, c.RoleRootUID, c.RoleSetupID, c.AccountVersion)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, accounts.Close)

	at = "control"
	control := capacityWorkerRef(c.Control.Namespace)
	observer, err := kube.NewPermissionClient(localInputs.kubernetes(observerToken), c.Control.ClusterID, control, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	probe, err := kube.NewPermissionClient(localInputs.kubernetes(probeToken), c.Control.ClusterID, control, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	admins, pin := capacityWorkerGuard(c.Control.Guard)
	guard, err := kube.NewCapacityGuard(observer, probe, cfg.CapacityAdministration{Name: c.Control.Guard.Name, ControlNamespace: control, Administrators: admins, StatusUsers: c.Control.StatusUsers, ProbeAccount: capacityWorkerRef(c.Control.ProbeAccount)}, pin)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	source, err := kube.NewCapacitySource(observer)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	at = "processing"
	processingProbe, err := kube.NewPermissionClient(localInputs.kubernetes(processingToken), c.Control.ClusterID, control, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	pa, pp := capacityWorkerGuard(c.Processing.Guard)
	processingGuard, err := kube.NewDownloadEnvironmentProtection(observer, processingProbe, cfg.ConfigMapAdministration{Name: c.Processing.Guard.Name, SourceName: c.Processing.Source.Name, ControlNamespace: control, Administrators: pa}, pp)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	paths, err := capacityRuntimeProcessingPaths(c.Processing.Paths)
	if err != nil {
		return nil, err
	}
	processing, err := kube.NewDownloadEnvironmentSource(observer, processingGuard, c.Processing.Source.Name, c.Processing.Source.UID, c.PermissionRootID, c.InstallationID, paths)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	at = "clusters"
	clusters := make([]app.CapacityClusterReaders, 0, len(c.Clusters))
	var regional []app.CapacityNamespaceQualification
	if installed != nil {
		clusters, regional, err = d.installedClusterReaders(startup, installed, observer, probe, localInputs, pools["capacity"], observerToken, probeToken)
		if err != nil {
			return nil, err
		}
	} else {
		for _, v := range c.Clusters {
			in := &providerInputs{files: files, kubernetesEndpoint: v.Kubernetes}
			d.closers = append(d.closers, in.closeHTTP)
			namespace := capacityWorkerRef(v.ProbeNamespace)
			prefix := "kube-capacity-" + v.ClusterID
			read, e := kube.NewPermissionClient(in.kubernetes(prefix+"-observer.token"), v.ClusterID, namespace, time.Now)
			if e != nil {
				return nil, mounts.ErrUnavailable
			}
			deny, e := kube.NewPermissionClient(in.kubernetes(prefix+"-probe.token"), v.ClusterID, namespace, time.Now)
			if e != nil {
				return nil, mounts.ErrUnavailable
			}
			a, p := capacityWorkerGuard(v.Guard)
			g, e := kube.NewCapacityNamespaceGuard(read, deny, cfg.CapacityNamespaceAdministration{Name: v.Guard.Name, Administrators: a, Keys: v.Keys, ProbeNamespace: namespace, ProbeAccount: capacityWorkerRef(v.ProbeAccount)}, p)
			if e != nil {
				return nil, mounts.ErrUnavailable
			}
			clusters = append(clusters, app.CapacityClusterReaders{ClusterID: v.ClusterID, Workloads: read, Guard: g})
		}
	}
	at = "sql-adapters"
	journal, err := postgres.NewCapacitySourceJournal(startup, pools["capacity"], c.PermissionRootID, c.InstallationID, q.ID, q.Digest)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	permissions, err := postgres.NewCapacityPermissions(startup, pools["capacity"], c.PermissionRootID, c.InstallationID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	general, err := postgres.NewCapacityRootBacking(startup, pools["capacity"], c.PermissionRootID, c.InstallationID, q.ID, q.Digest)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	capture, err := postgres.NewCapacityRootCaptureBacking(startup, pools["capacity-capture"], c.PermissionRootID, c.InstallationID, q.ID, q.Digest)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	enroll, err := postgres.NewCapacityEnrollments(startup, pools["capacity"], c.PermissionRootID, c.InstallationID, accounts)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	captureEnroll, err := postgres.NewCapacityCaptureEnrollments(startup, pools["capacity-capture"], c.PermissionRootID, c.InstallationID, accounts)
	if err != nil || startup.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	d.reconciler = &app.CapacityReconciler{Source: &app.CapacitySourceObserver{RootID: c.PermissionRootID, InstallationID: c.InstallationID, QualificationID: q.ID, QualificationDigest: q.Digest, Source: source, Protection: guard, Recovery: journal, Journal: journal, Now: time.Now},
		Work: &app.CapacityWorkReconciler{Qualification: q, Recovery: journal, Permissions: permissions, Processing: processing, Root: &app.RootBackingCoordinator{Store: general, Capture: capture, Now: time.Now}, Enrollment: &app.EnrollmentCoordinator{Store: enroll, Capture: captureEnroll, Accounts: accounts, Now: time.Now}, Bindings: enroll, Now: time.Now, Regional: regional}, Clusters: clusters,
		SourceReport: capacitySourceReporter(),
		Stalled: func(cluster, stage string) {
			fmt.Fprintf(os.Stderr, "capacity workload loop stalled: cluster %s in %s for over %s\n", cluster, stage, 2*app.CapacitySourceInterval)
		}}
	d.regional = regional
	complete = true
	return d, nil
}

func (d *CapacityWorkerDeployment) Run(ctx context.Context) error {
	if d == nil || d.reconciler == nil {
		return mounts.ErrUnavailable
	}
	return d.run(ctx, d.reconciler.Run)
}

func (d *CapacityWorkerDeployment) run(ctx context.Context, work func(context.Context) error) error {
	if d == nil || ctx == nil || ctx.Err() != nil || work == nil {
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
	call, end := context.WithCancel(d.root)
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { end(); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
		end()
	}()
	return work(call)
}
func (d *CapacityWorkerDeployment) Close() {
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
		d.owners.Wait()
		for i := len(d.closers) - 1; i >= 0; i-- {
			d.closers[i]()
		}
	})
}

// capacitySourceReporter logs one line per change of the source loop's
// outcome (ADR-197 CI continuation run 18b). The loop is serial, so the
// closure needs no lock.
func capacitySourceReporter() func(error) {
	last := "ok"
	return func(err error) {
		if outcome := regionalOutcome(err); outcome != last {
			last = outcome
			fmt.Fprintln(os.Stderr, "capacity source: "+outcome)
		}
	}
}
