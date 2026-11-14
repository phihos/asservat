package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

// errHubWorkerCapacityConfig stops the capacity child (and so the process):
// the capacity section cannot produce a valid qualification.
var errHubWorkerCapacityConfig = errors.New("invalid hub-worker capacity section")

// capacityRetry is the pause between capacity attempts; a transient failure
// never returns from the child.
const capacityRetry = 5 * time.Second

// capacityInitializedAt is the setup time of a stored qualification: the
// builder starts the capture lane's ValidUntil there (the reserve phase later
// sets the planned date in SQL; the stored qualification keeps the original).
// A restart rebuilds with it, so SQL finds the identical qualification.
func capacityInitializedAt(q app.CapacityQualification) time.Time {
	return q.RootBacking.Capture.Policy.ValidUntil
}

// capacityAccountVersion is the capture account MAC version, derived from
// the generated role setup ID as the installer did.
func capacityAccountVersion(ids contracts.InstallationIDs) string {
	return ids.RoleSetupID + "-account/v1"
}

// validateHubWorkerCapacity checks the section's names and that its values
// derive a valid pool and qualification.
func validateHubWorkerCapacity(c *contracts.HubWorkerCapacity, ids contracts.InstallationIDs, namespace string) error {
	if c == nil || len(validation.IsDNS1123Subdomain(c.ProcessingSource)) != 0 || c.Revision < 1 {
		return errHubWorkerCapacityConfig
	}
	if _, err := capacityRuntimeProcessingPaths(capacityPaths(c)); err != nil {
		return errHubWorkerCapacityConfig
	}
	v, err := capacityValues(c.CapacityValues)
	if err != nil {
		return errHubWorkerCapacityConfig
	}
	if _, _, err = app.DeriveBudget(v, capacityClusters(c, ids)); err != nil {
		return errHubWorkerCapacityConfig
	}
	// The processing source UID is a placeholder here; only the settings decide.
	if _, err := buildHubWorkerQualification(c, ids, namespace, ids.ClusterID, time.Now()); err != nil {
		return errHubWorkerCapacityConfig
	}
	return nil
}

// capacityValues converts the Helm quantities and percentages to bytes.
func capacityValues(c contracts.CapacityValues) (app.CapacityValues, error) {
	total, err := resource.ParseQuantity(c.EvidenceStorage)
	if err != nil || total.Value() <= 0 {
		return app.CapacityValues{}, errHubWorkerCapacityConfig
	}
	out := app.CapacityValues{EvidenceBytes: total.Value(), Assurance: c.StorageAssurance}
	bytes := func(v string) (int64, error) {
		if v == "" {
			return 0, nil
		}
		if p, ok := strings.CutSuffix(v, "%"); ok {
			f, err := strconv.ParseFloat(p, 64)
			if err != nil || f <= 0 || f > 100 {
				return 0, errHubWorkerCapacityConfig
			}
			return int64(float64(out.EvidenceBytes) * f / 100), nil
		}
		q, err := resource.ParseQuantity(v)
		if err != nil || q.Value() <= 0 {
			return 0, errHubWorkerCapacityConfig
		}
		return q.Value(), nil
	}
	if out.ShareBytes, err = bytes(c.Workload.Share); err != nil {
		return out, err
	}
	if out.LimitBytes, err = bytes(c.Workload.Limit); err != nil {
		return out, err
	}
	out.NamespaceLimitBytes, err = bytes(c.NamespaceLimit)
	return out, err
}

// capacityClusters lists the hub cluster and the joined clusters.
func capacityClusters(c *contracts.HubWorkerCapacity, ids contracts.InstallationIDs) []string {
	out := []string{ids.ClusterID}
	for _, r := range c.RemoteClusters {
		out = append(out, r.ClusterID)
	}
	return out
}

func capacityPaths(c *contracts.HubWorkerCapacity) []contracts.DownloadEnvironmentPath {
	if c.Paths == nil {
		return []contracts.DownloadEnvironmentPath{}
	}
	return c.Paths
}

// capacitySettings are the internal capacity bookkeeping settings: audit
// lanes, history footprints and the backup profile (ADR-335 D2: internal
// estimates, not values). The backend's usable size only bounds the pool,
// which carries the evidenceStorage value and follows every helm upgrade.
func capacitySettings() contracts.InstallerCapacitySettings {
	f := func(row, wal int64) contracts.InstallerCapacityFootprint {
		return contracts.InstallerCapacityFootprint{RowBytes: row, TransitionWALBytes: wal}
	}
	lane := func(accounts, records int64) contracts.InstallerCapacityLane {
		return contracts.InstallerCapacityLane{Accounts: accounts, Records: records, RetainedSeconds: 10000}
	}
	return contracts.InstallerCapacitySettings{Accounts: 2, Records: 8, AdmissionSeconds: 86400,
		Lanes:               contracts.InstallerCapacityLanes{CaptureRetainedSeconds: 10000, Normal: lane(4, 128), Resolution: lane(4, 8), Processing: lane(2, 16)},
		StopRetainedSeconds: 10000, Backup: contracts.CapacityBackup(),
		Footprints: contracts.InstallerCapacityFootprints{Capture: f(128<<10, 256<<10), Operation: f(128<<10, 256<<10), Processing: f(128<<10, 256<<10),
			Native: f(64<<10, 128<<10), Stop: f(128<<10, 256<<10), ProcessingState: f(16<<10, 64<<10)},
		PurgeLeases: 4, Processing: contracts.InstallerCapacityProcessing{MaxRules: 2, MaxRootTransitions: 512},
		Metadata: contracts.InstallerCapacityMetadata{FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20,
			RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, ConfigurationTransitions: 4096},
		Envelope: contracts.InstallerCapacityEnvelope{SystemObjects: contracts.InstallerCapacityAmount{Bytes: 1 << 30, Objects: 4096},
			SQLBytes: 512 << 20, BackupBytes: 1 << 30, WALBytes: 32 << 30, KeyAttempts: 16384},
		Backends: []contracts.InstallerCapacityBackend{{StorageProfile: "evidence", Usable: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1000000000}}}}
}

// buildHubWorkerQualification is the capacity qualification with
// Helm-native inputs: S values from ids, the processing source UID read by
// name, deterministic source digests and identities derived from
// RoleSetupID and the first initialization time, so a retry builds the same
// qualification.
func buildHubWorkerQualification(c *contracts.HubWorkerCapacity, ids contracts.InstallationIDs, namespace, processingUID string, initialized time.Time) (app.CapacityQualification, error) {
	return buildCapacityQualification(capacitySettings(), capacityDerived{SharedQueries: c.SharedQueries, Root: ids.PermissionRootID, Installation: ids.InstallationID,
		AccountVersion: capacityAccountVersion(ids), SystemPoolUID: app.SystemPoolUID(ids.InstallationID), ProcessingSourceUID: processingUID,
		ProcessingProtection: contracts.ConfigMapSourceDigest(ids.ClusterID, namespace, c.ProcessingSource),
		NamespaceGuards:      []app.CapacityNamespaceQualification{{ClusterID: ids.ClusterID, Digest: contracts.NamespaceSourceDigest(ids.ClusterID, namespace), Keys: contracts.CapacityNamespaceKeys()}},
		Now:                  initialized}, capacityIDs(ids.RoleSetupID))
}

// capacityRootStore is the SQL root initialization port.
type capacityRootStore interface {
	InitializeCapacity(context.Context, postgres.CapacityInitialization) (postgres.CapacityInitialized, error)
}

type sqlCapacityRootStore struct{ pool *pgxpool.Pool }

func (s sqlCapacityRootStore) InitializeCapacity(ctx context.Context, in postgres.CapacityInitialization) (postgres.CapacityInitialized, error) {
	return postgres.InitializeCapacity(ctx, s.pool, in)
}

// initializeCapacityRoot inserts the capacity root once (decision 6) and
// retries until SQL created it or finds it present. SQL refuses until the
// permission child's first acceptance has made the permission stream current.
// A root with other inputs stays in effect and is reported once.
func initializeCapacityRoot(ctx context.Context, store capacityRootStore, in postgres.CapacityInitialization, pause time.Duration) error {
	last := ""
	for {
		outcome, err := store.InitializeCapacity(ctx, in)
		if err == nil {
			if outcome == postgres.CapacityDifferent {
				fmt.Fprintln(os.Stderr, "capacity root exists with other settings; the stored qualification stays in effect")
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s := capacityInitializationOutcome(err); s != last {
			last = s
			fmt.Fprintln(os.Stderr, "capacity initialization: "+s)
		}
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func capacityInitializationOutcome(err error) string {
	if errors.Is(err, postgres.ErrCapacityPermissionPending) {
		return "waiting for the permission stream and setup roles"
	}
	return regionalOutcome(err)
}

// platformCapacityProtection is the Helm-native source and namespace
// protection: Kubernetes RBAC protects the release namespace, the capacity
// CRs and the processing source; the digest names the protected namespace
// deterministically (contracts.NamespaceSourceDigest), as the qualification
// and the SQL capacity root persist it.
type platformCapacityProtection struct {
	clusterID, namespaceUID string
	digest                  artifact.Digest
	keys                    []string
}

func (p platformCapacityProtection) window(ctx context.Context) (time.Time, time.Time) {
	now := time.Now()
	until := now.Add(app.CapacitySourceInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	return now, until
}

func (p platformCapacityProtection) CapacityProtection(ctx context.Context) (app.CapacitySourceProtection, error) {
	if ctx == nil || ctx.Err() != nil {
		return app.CapacitySourceProtection{}, mounts.ErrUnavailable
	}
	at, until := p.window(ctx)
	return app.CapacitySourceProtection{ClusterID: p.clusterID, ControlNamespaceUID: p.namespaceUID, Digest: p.digest, ObservedAt: at, FreshUntil: until}, nil
}

func (p platformCapacityProtection) CapacityNamespaceProtection(ctx context.Context) (app.CapacityNamespaceProtection, error) {
	if ctx == nil || ctx.Err() != nil {
		return app.CapacityNamespaceProtection{}, mounts.ErrUnavailable
	}
	at, until := p.window(ctx)
	return app.CapacityNamespaceProtection{ClusterID: p.clusterID, Digest: p.digest, Keys: slices.Clone(p.keys), ObservedAt: at, FreshUntil: until}, nil
}

// runCapacity initializes the capacity root and then runs the capacity
// reconciler; every transient failure retries inside.
func (w *hubWorker) runCapacity(ctx context.Context) error {
	if w == nil || ctx == nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	if err := validateHubWorkerCapacity(w.config.Capacity, w.ids, w.namespace.Name); err != nil {
		return &fixedStepError{"config", err}
	}
	last := ""
	for ctx.Err() == nil {
		err := w.runCapacityOnce(ctx)
		if ctx.Err() != nil {
			break
		}
		if errors.Is(err, errHubWorkerCapacityConfig) {
			return err
		}
		if s := regionalOutcome(err); s != last {
			last = s
			fmt.Fprintln(os.Stderr, "capacity stopped, retrying: "+s)
		}
		t := time.NewTimer(capacityRetry)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
	}
	return ctx.Err()
}

func (w *hubWorker) runCapacityOnce(ctx context.Context) (err error) {
	c := w.config.Capacity
	at := "start"
	defer func() {
		if err != nil && !errors.Is(err, errHubWorkerCapacityConfig) {
			err = &fixedStepError{at, err}
		}
	}()
	var closers []func()
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}()
	startup, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	pools := map[string]*pgxpool.Pool{}
	for purpose, file := range map[string]string{"capacity": contracts.HubWorkerCapacitySQLFile, "capacity-capture": contracts.HubWorkerCapacityCaptureSQLFile} {
		at = "sql/" + purpose
		role, known := postgres.PublicRuntimeRoleName(w.ids.InstallationID, purpose)
		if !known {
			return errHubWorkerCapacityConfig
		}
		pool, err := w.pool(startup, file, role, "asservat-capacity")
		if err != nil {
			return err
		}
		closers = append(closers, pool.Close)
		pools[purpose] = pool
	}
	at = "observer"
	observer, err := w.kubeClient()
	if err != nil {
		return err
	}
	at = "names"
	processingUID, err := observer.ConfigMapUID(startup, c.ProcessingSource)
	if err != nil {
		return err
	}
	// The first initialization's time is persisted in the stored
	// qualification; a retry or restart rebuilds with it.
	at = "initialized-at"
	initialized := time.Now()
	switch stored, err := postgres.ReadCapacityQualification(startup, pools["capacity"], w.ids.PermissionRootID); {
	case err == nil:
		initialized = capacityInitializedAt(stored)
	case !errors.Is(err, postgres.ErrCapacityQualificationAbsent):
		return err
	}
	q, err := buildHubWorkerQualification(c, w.ids, w.namespace.Name, processingUID, initialized)
	if err != nil {
		return errHubWorkerCapacityConfig
	}
	end()

	at = "initialize"
	digest := contracts.NamespaceSourceDigest(w.ids.ClusterID, w.namespace.Name)
	in := postgres.CapacityInitialization{ClusterID: w.ids.ClusterID, NamespaceUID: w.namespace.UID, SourceDigest: digest, AccountVersion: capacityAccountVersion(w.ids), Qualification: q}
	if err = initializeCapacityRoot(ctx, sqlCapacityRootStore{pools["capacity"]}, in, capacityRetry); err != nil {
		return err
	}
	// The stored qualification is the one in effect (J), also after a
	// settings change.
	startup, end = context.WithTimeout(ctx, 30*time.Second)
	defer end()
	at = "qualification"
	if q, err = postgres.ReadCapacityQualification(startup, pools["capacity"], w.ids.PermissionRootID); err != nil {
		return err
	}
	if q.RootBacking.InstallationID != w.ids.InstallationID || q.RootBacking.AccountVersion != capacityAccountVersion(w.ids) {
		return errHubWorkerCapacityConfig
	}
	// Context deletion purges the one evidence store this qualification
	// names (the hub-worker qualifies exactly one backend).
	at = "evidence-store-id"
	if len(q.Backends) != 1 {
		return errHubWorkerCapacityConfig
	}
	if err = w.publishEvidenceStoreID(q.Backends[0].EvidenceStoreID); err != nil {
		return err
	}
	at = "accounts"
	key, err := w.inputs.read(startup, contracts.HubWorkerCaptureAccountKeyFile, 64)
	if err != nil {
		return err
	}
	accounts, err := auditapp.NewCaptureAccounts(w.ids.InstallationID, capacityAccountVersion(w.ids), key)
	clear(key)
	if err != nil {
		return err
	}
	closers = append(closers, accounts.Close)
	reconciler, err := w.capacityReconciler(startup, ctx, q, pools, observer, accounts, digest)
	if err != nil {
		return err
	}
	end()
	at = "run"
	fmt.Fprintln(os.Stderr, "capacity started")
	defer w.guards.share(reconciler.Clusters)()
	return reconciler.Run(ctx)
}

// run bounds background readers (the joined clusters' observation watch).
func (w *hubWorker) capacityReconciler(ctx, run context.Context, q app.CapacityQualification, pools map[string]*pgxpool.Pool, observer *kube.PermissionClient, accounts *auditapp.CaptureAccounts, digest artifact.Digest) (*app.CapacityReconciler, error) {
	c := w.config.Capacity
	root, installation, cluster := w.ids.PermissionRootID, w.ids.InstallationID, w.ids.ClusterID
	values, err := capacityValues(c.CapacityValues)
	if err != nil {
		return nil, errHubWorkerCapacityConfig
	}
	source := &app.ValuesSource{Installation: installation, Cluster: cluster, Control: cfg.NamespaceRef{Name: w.namespace.Name, UID: w.namespace.UID},
		Revision: c.Revision, Values: values, Clusters: capacityClusters(c, w.ids), Now: time.Now}
	paths, err := capacityRuntimeProcessingPaths(capacityPaths(c))
	if err != nil {
		return nil, errHubWorkerCapacityConfig
	}
	processing, err := kube.NewPlainDownloadEnvironmentReader(observer, c.ProcessingSource, q.RootBacking.ProcessingSourceUID, root, installation, w.ids.IssuerEpoch, paths)
	if err != nil {
		return nil, err
	}
	// Only the hub cluster is observed directly with the worker's account;
	// joined mode=cluster clusters from their connectors' deliveries
	// (ADR-331).
	protection := platformCapacityProtection{clusterID: cluster, namespaceUID: w.namespace.UID, digest: digest}
	regionalStore, err := postgres.NewRemoteCapacity(pools["capacity"], root)
	if err != nil {
		return nil, err
	}
	if len(c.RemoteClusters) != 0 {
		// The delivered observations stay in memory, reloaded on the table's
		// change notification (ADR-331); the reconciler's reads never poll SQL.
		go regionalStore.Watch(run, eventLog(os.Stderr, "capacity remote observations"))
	}
	clusters := make([]app.CapacityClusterReaders, 0, len(q.NamespaceGuards))
	for _, pin := range q.NamespaceGuards {
		if pin.ClusterID != cluster {
			return nil, errHubWorkerCapacityConfig
		}
		workloads, err := w.kubeClient()
		if err != nil {
			return nil, err
		}
		guard := protection
		guard.digest, guard.keys = pin.Digest, slices.Clone(pin.Keys)
		clusters = append(clusters, app.CapacityClusterReaders{ClusterID: cluster, ReleaseNamespace: w.namespace.Name, Workloads: workloads, Guard: guard})
	}
	regional, err := w.remoteCapacityClusters(ctx, c, pools["capacity"])
	if err != nil {
		return nil, err
	}
	for _, pin := range regional {
		reader := app.RemoteCapacityReader{Store: regionalStore, Pin: pin, Now: time.Now}
		release := w.namespace.Name
		for _, r := range c.RemoteClusters {
			if r.ClusterID == pin.ClusterID && r.Namespace != "" {
				release = r.Namespace
			}
		}
		clusters = append(clusters, app.CapacityClusterReaders{ClusterID: pin.ClusterID, ReleaseNamespace: release, Workloads: reader, Guard: reader, Guarded: reader, Pace: regionalCapacityPace})
	}
	general, capture := pools["capacity"], pools["capacity-capture"]
	journal, err := postgres.NewCapacitySourceJournal(ctx, general, root, installation, q.ID, q.Digest)
	if err != nil {
		return nil, err
	}
	permissions, err := postgres.NewCapacityPermissions(ctx, general, root, installation)
	if err != nil {
		return nil, err
	}
	rootStore, err := postgres.NewCapacityRootBacking(ctx, general, root, installation, q.ID, q.Digest)
	if err != nil {
		return nil, err
	}
	rootCapture, err := postgres.NewCapacityRootCaptureBacking(ctx, capture, root, installation, q.ID, q.Digest)
	if err != nil {
		return nil, err
	}
	enroll, err := postgres.NewCapacityEnrollments(ctx, general, root, installation, accounts)
	if err != nil {
		return nil, err
	}
	captureEnroll, err := postgres.NewCapacityCaptureEnrollments(ctx, capture, root, installation, accounts)
	if err != nil {
		return nil, err
	}
	demands, err := postgres.NewCapacityRefreshDemands(ctx, general, root)
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(mounts.ErrUnavailable, err)
	}
	return &app.CapacityReconciler{
		Source: &app.CapacitySourceObserver{RootID: root, InstallationID: installation, QualificationID: q.ID, QualificationDigest: q.Digest, Source: source, Protection: protection, Recovery: journal, Journal: journal, Now: time.Now},
		Work: &app.CapacityWorkReconciler{Qualification: q, Recovery: journal, Permissions: permissions, Processing: processing, Root: &app.RootBackingCoordinator{Store: rootStore, Capture: rootCapture, Now: time.Now},
			Enrollment: &app.EnrollmentCoordinator{Store: enroll, Capture: captureEnroll, Accounts: accounts, Now: time.Now}, Bindings: enroll, Now: time.Now, Regional: regional},
		Clusters:     clusters,
		SourceReport: capacitySourceReporter("capacity source: "), RootReport: capacitySourceReporter("capacity root: "),
		Demands: demands, DemandReport: capacityDemandReporter(),
		DemandContext: func(ctx context.Context) (context.Context, func() string) {
			ctx, marks := auditapp.WithStepTimes(ctx)
			return ctx, marks.String
		},
		Stalled: func(cluster, stage string) {
			fmt.Fprintf(os.Stderr, "capacity workload loop stalled: cluster %s in %s for over %s\n", cluster, stage, 2*app.CapacitySourceInterval)
		}}, nil
}

// capacitySourceReporter logs one line per change of a serial loop's outcome
// (ADR-197 CI continuation run 18b). Each loop is serial, so the closure
// needs no lock.
func capacitySourceReporter(prefix string) func(error) {
	last := "ok"
	return func(err error) {
		if outcome := regionalOutcome(err); outcome != last {
			last = outcome
			fmt.Fprintln(os.Stderr, prefix+outcome)
		}
	}
}

// capacityDemandReporter logs ADR-200 demand-lane outcomes. Candidate outcomes
// retain numeric freshness left; pre-candidate failures have no proof budget.
func capacityDemandReporter() func(error, time.Duration, time.Duration, string) {
	return func(err error, elapsed, left time.Duration, stages string) {
		readLeft := "not-applicable"
		switch stages {
		case "read", "read-deadline", "cluster-unmatched":
		default:
			readLeft = left.Round(10 * time.Millisecond).String()
		}
		fmt.Fprintf(os.Stderr, "capacity demand refresh: %s after %s, read left %s [%s]\n", regionalOutcome(err), elapsed.Round(10*time.Millisecond), readLeft, stages)
	}
}

// regionalCapacityPace spaces a joined cluster's reconcile loop iterations:
// its observation changes only with a delivery (every two seconds).
const regionalCapacityPace = 2 * time.Second

// remoteCapacityClusters qualifies each joined mode=cluster cluster once
// (write-once SQL rows; a replay is unchanged) with its namespace digest and
// the hub's capacity keys, and returns the stored regional pins (ADR-331).
func (w *hubWorker) remoteCapacityClusters(ctx context.Context, c *contracts.HubWorkerCapacity, pool *pgxpool.Pool) ([]app.CapacityNamespaceQualification, error) {
	if len(c.RemoteClusters) == 0 {
		return nil, nil
	}
	q, err := postgres.NewCapacityClusterQualifications(ctx, pool, w.ids.PermissionRootID)
	if err != nil {
		return nil, err
	}
	keys := contracts.CapacityNamespaceKeys()
	for _, r := range c.RemoteClusters {
		peer, ok := contracts.RemotePeerID(w.ids.InstallationID, r.ClusterID)
		if !ok || r.ClusterID == w.ids.ClusterID {
			return nil, errHubWorkerCapacityConfig
		}
		if err = q.QualifyCapacityCluster(ctx, r.ClusterID, peer, w.ids.IssuerEpoch, contracts.NamespaceSourceDigest(r.ClusterID, r.Namespace), keys); err != nil {
			return nil, err
		}
	}
	pins, err := q.ReadCapacityClusterQualifications(ctx)
	if err != nil {
		return nil, err
	}
	var out []app.CapacityNamespaceQualification
	for _, p := range pins {
		if slices.ContainsFunc(c.RemoteClusters, func(r contracts.RemoteCluster) bool { return r.ClusterID == p.ClusterID }) {
			out = append(out, p)
		}
	}
	return out, nil
}
