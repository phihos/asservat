package bootstrap

import (
	"bytes"
	"context"
	"errors"
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
	closers   []func()
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
	sql := &providerInputs{files: files, postgresEndpoint: c.Postgres}
	w.closers = append(w.closers, sql.closeHTTP)
	pools := map[string]*pgxpool.Pool{}
	for _, purpose := range contracts.PermissionProjectionPurposes(c.Retention != nil) {
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
	w.reconciler = app.BindingReconciler{RootID: c.RootID, Reader: observer, Watcher: observer, Trust: guard, Store: store, Now: time.Now, NewID: uuid.NewString}
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
		if w.retention, err = newRetentionWorker(startup, c, pools, observer, probe, writer); err != nil {
			return nil, &fixedStepError{"retention/open", err}
		}
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
		c.Retention != nil && c.Retention.Guard.Name != contracts.RetentionGuardName(c.InstallationID) {
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

// run supervises the reconciler and the publisher until the Lease ends.
func (p *permissionWorker) run(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.publish(ctx)
	}()
	if p.retention != nil {
		retention := make(chan struct{})
		go func() {
			defer close(retention)
			p.retention.run(ctx)
		}()
		defer func() { <-retention }()
	}
	// A failed epoch retries after the 30-second SQL controller lease, so a
	// new epoch is not refused while the old lease is still live.
	for ctx.Err() == nil {
		_ = p.reconciler.Run(ctx)
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
	for ctx.Err() == nil {
		if lease, err := p.admission.WaitAuthorityAudit(ctx); err == nil {
			if lease.AwaitFleetObservation() == nil {
				if p.retention != nil && turn%2 == 1 {
					_ = p.retention.acceptance.Publish(lease.Context(), 1)
				} else {
					_ = p.publisher.PublishAuthority(lease.Context())
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
