package bootstrap

import (
	identities "asservat.local/asservat/internal/application/identity"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/configuration"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errPermissionProjectionMountPending = errors.New("permission projection mount pending")

// permissionWorker is the ADR-189 hub-worker child: the supervised permission
// reconciler and the authority audit publisher for one stream root.
type permissionWorker struct {
	reconciler app.BindingReconciler
	publisher  auditapp.AuthorityPublisher
	admission  *fleetapp.WorkerRuntimeAdmission
	// retention is the hub retention source (ADR-195); nil without it.
	retention *retentionWorker
	// workerConfiguration is the download worker configuration acceptance
	// (ADR-204 decision 7); nil without its section.
	workerConfiguration *workerConfigurationWorker
	// contextDeletion deletes expired context evidence (ADR-205); nil
	// without its section.
	contextDeletion *contextDeletionWorker
	// browser projects the browser settings into SQL (ADR-210); nil without
	// its section.
	browser *identities.BrowserSettingsObserver
	closers []func()
}

func (p *permissionWorker) Close() {
	for i := len(p.closers) - 1; i >= 0; i-- {
		p.closers[i]()
	}
	p.closers = nil
}

// runPermission waits for the journal's acknowledged permission projection,
// opens it once, then runs the stream until the Lease ends. Reconciler
// failures restart a new epoch inside this child; it never returns early,
// because a returning child tears down its siblings.
func (d *InstalledHubWorkerDeployment) runPermission(ctx context.Context) error {
	b := d.capacity
	if b == nil || b.activation == nil || b.admission == nil || b.mounts == nil || b.configuration == nil || b.configuration.providers == nil || ctx == nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	var mountUntil time.Time
	for ctx.Err() == nil {
		ready, err := b.activation.PermissionProjectionHint(ctx)
		if err != nil {
			return err
		}
		if ready {
			// Kubelet adds a late optional Secret to the projected volume on a
			// later Pod sync, which can take more than a minute.
			if mountUntil.IsZero() {
				mountUntil = time.Now().Add(3 * time.Minute)
			}
			if !time.Now().Before(mountUntil) {
				return mounts.ErrUnavailable
			}
			worker, err := d.openPermission(ctx)
			if !errors.Is(err, errPermissionProjectionMountPending) {
				if err != nil {
					return err
				}
				defer worker.Close()
				return worker.run(ctx)
			}
		}
		if !sleepContext(ctx, time.Second) {
			break
		}
	}
	return ctx.Err()
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// openPermission binds the mounted files to the journal claim's public digest
// under one current native projection operation, then verifies both SQL
// logins against their projected role provenance.
func (d *InstalledHubWorkerDeployment) openPermission(ctx context.Context) (*permissionWorker, error) {
	b := d.capacity
	// The mount check is local and cheap; the native operation follows only
	// once the projection is present, so waiting spends no API budget.
	files, err := b.mounts.OpenRoot(contracts.PermissionWorkerProjectionDirectory)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && ctx.Err() == nil {
			return nil, errPermissionProjectionMountPending
		}
		return nil, mounts.ErrUnavailable
	}
	w := &permissionWorker{closers: []func(){func() { files.Close() }}}
	complete := false
	defer func() {
		if !complete {
			w.Close()
		}
	}()
	op, claim, err := b.activation.BeginPermissionProjectionOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer op.Close()
	startup := op.Context()
	c, m, err := readPermissionWorkerInputs(startup, files)
	if err != nil || kube.PermissionRuntimePublicDigest(c, m) != claim.PublicDigest || c.RootID != claim.RootID ||
		c.InstallationID != b.input.InstallationID || c.Control.ClusterID != b.input.ClusterID || c.Control.Namespace != b.input.Namespace {
		return nil, mounts.ErrUnavailable
	}
	// Long-lived pools re-read their logins through the stable mount root:
	// files pins today's projected data directory, which the kubelet deletes
	// on its next refresh.
	sql := &providerInputs{files: b.mounts, dir: contracts.PermissionWorkerProjectionDirectory, postgresEndpoint: c.Postgres}
	w.closers = append(w.closers, sql.closeHTTP)
	pools := map[string]*pgxpool.Pool{}
	for _, purpose := range contracts.PermissionProjectionPurposes(c.Retention != nil, c.WorkerConfiguration != nil, c.ContextDeletion, c.Browser != nil) {
		p, e := sql.sqlConfig(startup, "sql-"+purpose+".json")
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		p.MaxConns, p.MinConns = 1, 0
		p.ConnConfig.RequireAuth = "scram-sha-256"
		p.ConnConfig.RuntimeParams["application_name"] = "asservat-permission"
		pool, e := pgxpool.NewWithConfig(startup, p)
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		w.closers = append(w.closers, pool.Close)
		if postgres.VerifyPermissionRuntimeCredential(startup, pool, m, purpose) != nil {
			return nil, mounts.ErrUnavailable
		}
		pools[purpose] = pool
	}
	local, _, err := readHubWorkerInputs(startup, b.mounts)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	w.closers = append(w.closers, local.closeHTTP)
	control := cfg.NamespaceRef{Name: c.Control.Namespace.Name, UID: c.Control.Namespace.UID}
	observer, err := kube.NewPermissionClient(local.kubernetes("kube-observer.token"), c.Control.ClusterID, control, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	probe, err := kube.NewPermissionClient(local.kubernetes("kube-probe.token"), c.Control.ClusterID, control, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	g := c.Control.Guard
	guard, err := kube.NewPermissionGuard(observer, probe, kube.PermissionAdministrationOf(c.Control), kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion})
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	store, err := postgres.NewPermissions(startup, pools["permission-accept"], c.RootID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	ledger, err := postgres.NewPermissions(startup, pools["permission-audit"], c.RootID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if b := c.Browser; b != nil {
		browserObserver, e := kube.NewPermissionClient(kube.WithOpeningBurst(local.kubernetes("kube-observer.token")), c.Control.ClusterID, control, time.Now)
		if e != nil {
			return nil, &fixedStepError{"browser/client", e}
		}
		source, e := kube.NewBrowserSettingsClient(browserObserver, b.Settings.Name, b.Settings.UID, b.RootID)
		if e != nil {
			return nil, &fixedStepError{"browser/source", e}
		}
		projection, e := postgres.NewBrowserSettingsProjection(startup, pools["browser-settings"], b.RootID)
		if e != nil {
			return nil, &fixedStepError{"browser/projection", e}
		}
		w.browser = &identities.BrowserSettingsObserver{Source: source, Projection: projection, Now: time.Now}
	}
	// ADR-242: namespace inheritance observes the hub cluster's namespaces
	// with its own client, so a large namespace LIST never spends the
	// binding reconciler's request budget.
	namespaces, err := kube.NewPermissionClient(local.kubernetes("kube-observer.token"), c.Control.ClusterID, control, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	w.reconciler = app.BindingReconciler{RootID: c.RootID, Reader: observer, Watcher: observer, Trust: guard, Store: store, Namespaces: namespaces, NamespaceClusterID: c.Control.ClusterID, Now: time.Now, NewID: uuid.NewString}
	if r := c.Review; r != nil {
		review, e := kube.NewBootstrapReviewClient(observer, r.Name, r.UID)
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		w.reconciler.Review = review
	}
	writer, err := newInstalledConfigurationAudit(b.input, b.configuration.providers)
	if err != nil {
		return nil, err
	}
	w.closers = append(w.closers, writer.Close)
	w.publisher = auditapp.AuthorityPublisher{Ledger: oneAuthorityAudit{ledger}, Objects: &installedAuthorityAudit{root: c.RootID, audit: writer}}
	w.admission = b.admission
	if c.Retention != nil {
		// ADR-208: the retention source follower gets its own clients with the
		// opening limiter. Behind the permission reconciler on the shared 20/20
		// clients it wrote each observation with 2-3 s of its five seconds left
		// and the next one 3-6 s later, so the hub source was current about half
		// the time and previews refused at retention (installed native 68).
		retentionObserver, e := kube.NewPermissionClient(kube.WithOpeningBurst(local.kubernetes("kube-observer.token")), c.Control.ClusterID, control, time.Now)
		if e != nil {
			return nil, &fixedStepError{"retention/clients", e}
		}
		retentionProbe, e := kube.NewPermissionClient(kube.WithOpeningBurst(local.kubernetes("kube-probe.token")), c.Control.ClusterID, control, time.Now)
		if e != nil {
			return nil, &fixedStepError{"retention/clients", e}
		}
		if w.retention, err = newRetentionWorker(startup, c, pools, retentionObserver, retentionProbe, writer); err != nil {
			return nil, &fixedStepError{"retention/open", err}
		}
	}
	if w.workerConfiguration, err = openWorkerConfiguration(startup, c, pools, local, writer, b.admission); err != nil {
		return nil, &fixedStepError{"worker-configuration/open", err}
	}
	if w.workerConfiguration != nil {
		w.closers = append(w.closers, w.workerConfiguration.Close)
	}
	if w.contextDeletion, err = openContextDeletion(startup, c, pools, b.mounts, writer, b.admission, b.ContextDeletion); err != nil {
		return nil, &fixedStepError{"context-deletion/open", err}
	}
	if w.contextDeletion != nil {
		w.closers = append(w.closers, w.contextDeletion.Close)
	}
	if err = op.Finish(op.Context()); err != nil || ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	complete = true
	return w, nil
}

func readPermissionWorkerInputs(ctx context.Context, files *os.Root) (contracts.PermissionDeployment, contracts.PermissionCredentialManifest, error) {
	var c contracts.PermissionDeployment
	var m contracts.PermissionCredentialManifest
	b, err := mounts.Read(ctx, files, contracts.PermissionDeploymentFile, contracts.PermissionDeploymentMaxBytes)
	if err != nil {
		return c, m, mounts.ErrUnavailable
	}
	c, err = contracts.DecodePermissionDeployment(bytes.NewReader(b))
	clear(b)
	if err != nil || c.Format != contracts.PermissionDeploymentFormat || !authorization.UUID(c.InstallationID) || !authorization.UUID(c.RootID) ||
		!authorization.UUID(c.RoleRootUID) || !authorization.UUID(c.RoleSetupID) || c.Control.Guard.Name != contracts.PermissionGuardName(c.InstallationID) ||
		c.Retention != nil && c.Retention.Guard.Name != contracts.RetentionGuardName(c.InstallationID) || !kube.WorkerConfigurationSectionValid(c) {
		return c, m, mounts.ErrUnavailable
	}
	b, err = mounts.Read(ctx, files, contracts.PermissionCredentialManifestFile, contracts.PermissionCredentialManifestMaxBytes)
	if err != nil {
		return c, m, mounts.ErrUnavailable
	}
	m, err = contracts.DecodePermissionCredentialManifest(bytes.NewReader(b))
	clear(b)
	if err != nil || m.RootUID != c.RoleRootUID || m.SetupID != c.RoleSetupID || m.Input.InstallationID != c.InstallationID {
		return c, m, mounts.ErrUnavailable
	}
	return c, m, nil
}

// run supervises the reconciler and the publisher, and with their sections the
// retention source and the worker configuration child, until the Lease ends.
func (p *permissionWorker) run(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.publish(ctx)
	}()
	// ADR-210: one projection per second keeps the five-second settings
	// observation current for console logins; a failed read fences it.
	if p.browser != nil {
		browser := make(chan struct{})
		go func() {
			defer close(browser)
			report := capacitySourceReporter("hub-worker browser settings: ")
			for ctx.Err() == nil {
				report(p.browser.Reconcile(ctx))
				if !sleepContext(ctx, time.Second) {
					return
				}
			}
		}()
		defer func() { <-browser }()
	}
	if p.retention != nil {
		retention := make(chan struct{})
		go func() {
			defer close(retention)
			p.retention.run(ctx)
		}()
		defer func() { <-retention }()
	}
	// ADR-204: absent without its section; joined like retention.
	if p.workerConfiguration != nil {
		worker := make(chan struct{})
		go func() {
			defer close(worker)
			p.workerConfiguration.run(ctx)
		}()
		defer func() { <-worker }()
	}
	// ADR-205: absent without its section; joined like retention.
	if p.contextDeletion != nil {
		deletion := make(chan struct{})
		go func() {
			defer close(deletion)
			p.contextDeletion.run(ctx)
		}()
		defer func() { <-deletion }()
	}
	// A failed epoch retries after the 30-second SQL controller lease, so a
	// new epoch is not refused while the old lease is still live.
	for ctx.Err() == nil {
		// A stopped epoch leaves capacity scopes stale for 31 s; say why
		// (ADR-197 CI continuation run 19b).
		if err := p.reconciler.Run(ctx); ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "permission reconciler stopped: "+regionalOutcome(err))
		}
		if !sleepContext(ctx, 31*time.Second) {
			break
		}
	}
	<-done
	return ctx.Err()
}

// publish writes one pending authority record per admitted lease: a lease
// admits exactly one provider audit invocation.
func (p *permissionWorker) publish(ctx context.Context) {
	// A lease admits one provider audit invocation. With retention the
	// leases alternate between authority and checkpoint acceptance records.
	turn := 0
	// One line per change of the authority publisher's outcome: an
	// unacknowledged activation audit hides its scope from capacity.
	last := "ok"
	for ctx.Err() == nil {
		if lease, err := p.admission.WaitAuthorityAudit(ctx); err == nil {
			if lease.AwaitFleetObservation() == nil {
				if p.retention != nil && turn%2 == 1 {
					_ = p.retention.acceptance.Publish(lease.Context(), 1)
				} else if outcome := regionalOutcome(p.publisher.PublishAuthority(lease.Context())); outcome != last && ctx.Err() == nil {
					last = outcome
					fmt.Fprintln(os.Stderr, "authority audit publish: "+outcome)
				}
				turn++
			}
			lease.Release()
		}
		if !sleepContext(ctx, time.Second) {
			return
		}
	}
}

// oneAuthorityAudit limits a publisher pass to one pending record.
type oneAuthorityAudit struct{ auditapp.AuthorityLedger }

func (o oneAuthorityAudit) PendingAuthorityAudits(ctx context.Context) ([]audit.AuthorityRecord, error) {
	rows, err := o.AuthorityLedger.PendingAuthorityAudits(ctx)
	if len(rows) > 1 {
		rows = rows[:1]
	}
	return rows, err
}

// installedAuthorityAudit writes one authority record under one provider
// audit operation, scoped to its own stream root (ADR-189).
type installedAuthorityAudit struct {
	root  string
	audit *installedConfigurationAudit
}

func (s *installedAuthorityAudit) WriteAuthorityAudit(ctx context.Context, r audit.AuthorityRecord) (audit.Receipt, error) {
	if s == nil || s.audit == nil || ctx == nil || ctx.Err() != nil || !r.Valid() || r.RootID != s.root {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	operation, err := s.audit.providers.BeginAuthorityAudit(ctx)
	if err != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	defer operation.Close()
	call := operation.Context()
	material, err := operation.Credentials()
	if err != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	store, err := s.audit.storage(material)
	if err != nil {
		return audit.Receipt{}, err
	}
	defer store.Close()
	writer := &objectstore.AuthorityObjects{Store: store, Seal: s.audit.providers.Sealer(), Open: s.audit.providers.Opener()}
	receipt, err := writer.WriteAuthorityAudit(call, r)
	if err != nil || call.Err() != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	if err = operation.Finish(); err != nil || call.Err() != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return receipt, nil
}
