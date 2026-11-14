package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/configuration"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/apimachinery/pkg/util/validation"
)

// permissionAdministrators is the administrator set of the permission plan.
// Kubernetes RBAC decides who writes PermissionSources in the release
// namespace and AccessBindings in application namespaces (ADR-329), so the
// plan names the cluster administrators. It only enters the deterministic
// trust digest and the plan validation; no admission policy is derived from it.
var permissionAdministrators = []cfg.KubernetesActor{{Kind: "Group", Name: "system:masters"}}

// permissionPlan is the installed permission configuration of the release
// namespace: the status users from Helm.
func permissionPlan(c contracts.HubWorkerPermission, control cfg.NamespaceRef) cfg.PermissionAdministration {
	return cfg.PermissionAdministration{Name: "asservat-permission", ControlNamespace: control, Administrators: slices.Clone(permissionAdministrators), StatusUsers: slices.Clone(c.StatusUsers)}
}

// permissionTrustDigest is the stream's deterministic trust digest: the
// cluster and the installed plan. A changed status user is a new trust
// revision; the SQL stream starts a new epoch under it.
func permissionTrustDigest(cluster string, plan cfg.PermissionAdministration) (artifact.Digest, error) {
	b, err := json.Marshal(struct {
		Format  string
		Cluster string
		Plan    cfg.PermissionAdministration
	}{"asservat-permission-trust/v3", cluster, plan})
	if err != nil {
		return artifact.Digest{}, mounts.ErrUnavailable
	}
	return artifact.Digest(sha256.Sum256(b)), nil
}

// validateHubWorkerPermission checks the Helm section once the namespace is
// known. A failure is a configuration error that stops the hub-worker.
func validateHubWorkerPermission(c contracts.HubWorkerConfig, control cfg.NamespaceRef) error {
	p := c.Permission
	if p == nil || !permissionPlan(*p, control).Valid() || p.Review != "" && len(validation.IsDNS1123Subdomain(p.Review)) != 0 {
		return &fixedStepError{"permission/config", mounts.ErrUnavailable}
	}
	if v := p.WorkerConfiguration; v != nil && (len(validation.IsDNS1123Label(v.Namespace)) != 0 || v.Namespace == control.Name || len(validation.IsDNS1123Subdomain(v.Source)) != 0 ||
		!ownerProviderName.MatchString(c.Provider.WorkerConfigurationAudit.Mount) || !ownerProviderName.MatchString(c.Provider.WorkerConfigurationAudit.Key)) {
		return &fixedStepError{"permission/config/worker-configuration", mounts.ErrUnavailable}
	}
	if d := p.ContextDeletion; d != nil && (!ownerEndpoint(d.EvidenceStore.Endpoint) || !identity.Text(d.EvidenceStore.Region, 128) || !identity.Text(d.EvidenceStore.Bucket, 63) ||
		c.Provider.ContextDeletionSigning.Mount != c.KeyService.AuditMount || !ownerProviderName.MatchString(c.Provider.ContextDeletionSigning.Key) || c.Provider.ContextDeletionSigning.Key == c.KeyService.AuditKey) {
		return &fixedStepError{"permission/config/context-deletion", mounts.ErrUnavailable}
	}
	if b := p.Browser; b != nil && len(validation.IsDNS1123Subdomain(b.Settings)) != 0 {
		return &fixedStepError{"permission/config/browser", mounts.ErrUnavailable}
	}
	if i := p.Identity; i != nil && (len(validation.IsDNS1123Subdomain(i.Settings)) != 0 || !identity.Text(i.Issuer, 2048)) {
		return &fixedStepError{"permission/config/identity", mounts.ErrUnavailable}
	}
	return nil
}

// permissionWorker is the ADR-189 hub-worker child: the supervised permission
// reconciler and the authority audit publisher for the permission root, with
// the retention source, worker configuration acceptance, context deletion and
// browser/identity settings projections of present subsections.
type permissionWorker struct {
	reconciler          app.BindingReconciler
	publisher           auditapp.AuthorityPublisher
	authority           *authorityAuditTurn
	retention           *retentionWorker
	workerConfiguration *workerConfigurationWorker
	contextDeletion     *contextDeletionWorker
	browser             *identities.BrowserSettingsObserver
	policyGrantSettings *app.PolicyGrantSettingsObserver
	// Startup ordering (scheduling only, never authority): audit writers
	// start after the provider's first login, and the retention and context
	// deletion loops after the capacity child, which exists only once the
	// permission stream they lock is current. Nil means ready.
	auditReady    func() bool
	capacityReady func(context.Context) bool
	closers       []func()
}

// startupReadyPoll spaces readiness checks of an in-process prerequisite.
const startupReadyPoll = 250 * time.Millisecond

// awaitReady polls ready until it reports true or ctx ends.
func awaitReady(ctx context.Context, ready func() bool) bool {
	for ready != nil && !ready() {
		if !sleepContext(ctx, startupReadyPoll) {
			return false
		}
	}
	return ctx.Err() == nil
}

func (p *permissionWorker) awaitCapacity(ctx context.Context) bool {
	if p.capacityReady == nil {
		return ctx.Err() == nil
	}
	return p.capacityReady(ctx)
}

func (p *permissionWorker) Close() {
	for i := len(p.closers) - 1; i >= 0; i-- {
		p.closers[i]()
	}
	p.closers = nil
}

// permissionOpenRetry spaces startup attempts while SQL, OpenBao or source
// ConfigMaps are not yet available. It is scheduling, never authority.
const permissionOpenRetry = 5 * time.Second

// runPermission opens the child, retrying transient startup failures, then
// runs it until the Lease ends. It never returns early on a transient
// failure, because a returning child tears down its siblings.
func (w *hubWorker) runPermission(ctx context.Context) error {
	if w == nil || w.config.Permission == nil || w.audit == nil || w.authority == nil || w.providers == nil || ctx == nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	if err := validateHubWorkerPermission(w.config, w.namespace); err != nil {
		return err
	}
	last := ""
	for ctx.Err() == nil {
		p, err := w.openPermission(ctx)
		if err == nil {
			defer p.Close()
			return p.run(ctx)
		}
		if outcome := regionalOutcome(err); outcome != last && ctx.Err() == nil {
			last = outcome
			fmt.Fprintln(os.Stderr, "hub-worker permission open: "+outcome)
		}
		if !sleepContext(ctx, permissionOpenRetry) {
			break
		}
	}
	return ctx.Err()
}

// permissionPools opens one single-connection pool per present purpose from
// `sql-<purpose>.json`, each checked against its derived role name.
func (w *hubWorker) permissionPools(ctx context.Context, p *permissionWorker, c contracts.HubWorkerPermission) (map[string]*pgxpool.Pool, error) {
	pools := map[string]*pgxpool.Pool{}
	for _, purpose := range contracts.PermissionProjectionPurposes(c.Retention, c.WorkerConfiguration != nil, c.ContextDeletion != nil, c.Browser != nil) {
		role, known := postgres.PublicRuntimeRoleName(w.ids.InstallationID, purpose)
		if !known {
			return nil, mounts.ErrUnavailable
		}
		pool, err := w.pool(ctx, "sql-"+purpose+".json", role, "asservat-permission")
		if err != nil {
			return nil, err
		}
		p.closers = append(p.closers, pool.Close)
		pools[purpose] = pool
	}
	return pools, nil
}

func (w *hubWorker) openPermission(ctx context.Context) (_ *permissionWorker, err error) {
	c := *w.config.Permission
	p := &permissionWorker{authority: w.authority, auditReady: w.providers.AuditAvailable, capacityReady: w.awaitCapacity}
	defer func() {
		if err != nil {
			p.Close()
		}
	}()
	startup, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	pools, err := w.permissionPools(startup, p, c)
	if err != nil {
		return nil, err
	}
	root, installation, cluster := w.ids.PermissionRootID, w.ids.InstallationID, w.ids.ClusterID
	observer, err := w.kubeClient()
	if err != nil {
		return nil, err
	}
	digest, err := permissionTrustDigest(cluster, permissionPlan(c, w.namespace))
	if err != nil {
		return nil, err
	}
	trust, err := kube.NewPlainPermissionTrust(observer, digest)
	if err != nil {
		return nil, &fixedStepError{"permission/trust", err}
	}
	store, err := postgres.NewPermissions(startup, pools["permission-accept"], root)
	if err != nil {
		return nil, &fixedStepError{"permission/store", err}
	}
	ledger, err := postgres.NewPermissions(startup, pools["permission-audit"], root)
	if err != nil {
		return nil, &fixedStepError{"permission/ledger", err}
	}
	// ADR-242: namespace inheritance observes the hub cluster's namespaces
	// with its own client, so a large namespace LIST never spends the
	// binding reconciler's request budget.
	namespaces, err := w.kubeClient()
	if err != nil {
		return nil, err
	}
	p.reconciler = app.BindingReconciler{RootID: root, Reader: observer, Watcher: observer, Trust: trust, Store: store, Namespaces: namespaces, NamespaceClusterID: cluster,
		Guards: &w.guards, Remote: &w.guards, Workloads: &w.guards, WorkloadGuards: &w.guards, Now: time.Now, NewID: uuid.NewString}
	if b := c.Browser; b != nil {
		browserObserver, e := w.kubeOpeningClient()
		if e != nil {
			return nil, &fixedStepError{"browser/client", e}
		}
		uid, e := browserObserver.ConfigMapUID(startup, b.Settings)
		if e != nil {
			return nil, &fixedStepError{"browser/uid", e}
		}
		source, e := kube.NewBrowserSettingsReader(browserObserver, b.Settings, uid, w.ids.BrowserRootID, w.ids.SessionEpoch)
		if e != nil {
			return nil, &fixedStepError{"browser/source", e}
		}
		projection, e := postgres.NewBrowserSettingsProjection(startup, pools["browser-settings"], w.ids.BrowserRootID)
		if e != nil {
			return nil, &fixedStepError{"browser/projection", e}
		}
		p.browser = &identities.BrowserSettingsObserver{Source: source, Projection: projection, Now: time.Now}
	}
	if id := c.Identity; id != nil {
		uid, e := observer.ConfigMapUID(startup, id.Settings)
		if e != nil {
			return nil, &fixedStepError{"identity/uid", e}
		}
		settings, e := kube.NewIdentityPolicyClient(observer, id.Settings, uid, id.Issuer)
		if e != nil {
			return nil, &fixedStepError{"identity/directory", e}
		}
		p.reconciler.Directory = identityDirectory{settings}
		grants, e := postgres.NewPolicies(startup, pools["permission-accept"], root, installation)
		if e != nil {
			return nil, &fixedStepError{"identity/policy-grant-settings", e}
		}
		p.policyGrantSettings = &app.PolicyGrantSettingsObserver{Issuer: id.Issuer, Source: settings, Projection: grants, Now: time.Now}
	}
	if c.Review != "" {
		uid, e := observer.ConfigMapUID(startup, c.Review)
		if e != nil {
			return nil, &fixedStepError{"review/uid", e}
		}
		review, e := kube.NewBootstrapReviewClient(observer, c.Review, uid)
		if e != nil {
			return nil, &fixedStepError{"review/source", e}
		}
		p.reconciler.Review = review
	}
	p.publisher = auditapp.AuthorityPublisher{Ledger: oneAuthorityAudit{ledger}, Objects: &installedAuthorityAudit{root: root, audit: w.audit}}
	var signing *permissionDeletionSigning
	if c.ContextDeletion != nil {
		signing = &permissionDeletionSigning{w: w}
	}
	if c.Retention {
		// ADR-208: the retention source follower gets its own client with the
		// opening limiter, so the hub source stays within its five seconds.
		retentionObserver, e := w.kubeOpeningClient()
		if e != nil {
			return nil, &fixedStepError{"retention/clients", e}
		}
		if p.retention, err = newRetentionWorker(startup, root, cluster, w.namespace, pools, retentionObserver, w.audit, signing); err != nil {
			return nil, &fixedStepError{"retention/open", err}
		}
	}
	if v := c.WorkerConfiguration; v != nil {
		if p.workerConfiguration, err = w.openWorkerConfiguration(startup, *v, pools); err != nil {
			return nil, &fixedStepError{"worker-configuration/open", err}
		}
		p.closers = append(p.closers, p.workerConfiguration.Close)
	}
	if d := c.ContextDeletion; d != nil {
		if p.contextDeletion, err = w.openContextDeletion(startup, *d, pools, signing); err != nil {
			return nil, &fixedStepError{"context-deletion/open", err}
		}
		p.closers = append(p.closers, p.contextDeletion.Close)
	}
	if startup.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	return p, nil
}

// permissionReporter logs a repeated loop's outcome when it changes.
func permissionReporter(prefix string) func(error) {
	last := "ok"
	return func(err error) {
		if outcome := regionalOutcome(err); outcome != last {
			last = outcome
			fmt.Fprintln(os.Stderr, prefix+outcome)
		}
	}
}

// goJoined runs f in a goroutine and returns a wait for it.
func goJoined(f func()) func() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	return func() { <-done }
}

// run supervises the reconciler and the publisher, and with their sections
// the projections and sub-children, until the Lease ends.
func (p *permissionWorker) run(ctx context.Context) error {
	var joins []func()
	defer func() {
		for i := len(joins) - 1; i >= 0; i-- {
			joins[i]()
		}
	}()
	joins = append(joins, goJoined(func() {
		if awaitReady(ctx, p.auditReady) {
			p.publish(ctx)
		}
	}))
	// ADR-210: one projection per second keeps the five-second settings
	// observation current for console logins; a failed read fences it.
	if p.policyGrantSettings != nil {
		joins = append(joins, goJoined(func() { p.policyGrantSettings.Run(ctx, permissionReporter("hub-worker policy grant settings: ")) }))
	}
	if p.browser != nil {
		joins = append(joins, goJoined(func() {
			report := permissionReporter("hub-worker browser settings: ")
			for ctx.Err() == nil {
				report(p.browser.Reconcile(ctx))
				if !sleepContext(ctx, time.Second) {
					return
				}
			}
		}))
	}
	if p.retention != nil {
		joins = append(joins, goJoined(func() {
			if p.awaitCapacity(ctx) {
				p.retention.run(ctx)
			}
		}))
	}
	if p.workerConfiguration != nil {
		joins = append(joins, goJoined(func() {
			if awaitReady(ctx, p.auditReady) {
				p.workerConfiguration.run(ctx)
			}
		}))
	}
	if p.contextDeletion != nil {
		joins = append(joins, goJoined(func() {
			if p.awaitCapacity(ctx) {
				p.contextDeletion.run(ctx)
			}
		}))
	}
	// Unknown suspension waits out the 30-second SQL controller lease. A
	// positively suspended, joined epoch can rebuild from current facts sooner.
	for ctx.Err() == nil {
		result := p.reconciler.RunEpoch(ctx)
		if ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "permission reconciler stopped: "+regionalOutcome(result.Err))
		}
		if !sleepContext(ctx, permissionEpochRestartDelay(result)) {
			break
		}
	}
	return ctx.Err()
}

// publish writes one pending authority record per admitted lease: a lease
// admits exactly one provider audit invocation. With retention the leases
// alternate between authority and retention records.
func (p *permissionWorker) publish(ctx context.Context) {
	turn := 0
	last := "ok"
	for ctx.Err() == nil {
		if lease, release, err := p.authority.wait(ctx); err == nil {
			if lease.AwaitFleetObservation() == nil {
				if p.retention != nil && turn%2 == 1 {
					p.retention.publish(lease.Context(), turn%4 == 3)
				} else if outcome := regionalOutcome(p.publisher.PublishAuthority(lease.Context())); outcome != last && ctx.Err() == nil {
					last = outcome
					fmt.Fprintln(os.Stderr, "authority audit publish: "+outcome)
				}
				turn++
			}
			release()
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
	return s.audit.writeAuthorityAudit(ctx, func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		writer := &objectstore.AuthorityObjects{Store: store, Seal: s.audit.providers.Sealer(), Open: s.audit.providers.Opener()}
		return writer.WriteAuthorityAudit(call, r)
	})
}

// writeAuthorityAudit runs one write under one authority audit provider
// operation: its audit-only storage material, versioned store and final
// provider proof. Every record type of this child shares it.
func (s *installedConfigurationAudit) writeAuthorityAudit(ctx context.Context, write func(context.Context, *objectstore.Store) (audit.Receipt, error)) (audit.Receipt, error) {
	if s == nil || s.providers == nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	operation, err := s.providers.BeginAuthorityAudit(ctx)
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.begin", err}
	}
	defer operation.Close()
	call := operation.Context()
	material, err := operation.Credentials()
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.credentials", err}
	}
	store, err := s.storage(material)
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.storage", err}
	}
	defer store.Close()
	receipt, err := write(call, store)
	if err != nil || call.Err() != nil {
		return audit.Receipt{}, &fixedStepError{"audit.write", mounts.ErrUnavailable}
	}
	if err = operation.Finish(); err != nil || call.Err() != nil {
		return audit.Receipt{}, &fixedStepError{"audit.finish", mounts.ErrUnavailable}
	}
	return receipt, nil
}

// The existing controller lease is 30s; only a completed exact suspension can
// make an earlier retry useful. This delay is scheduling, never authority.
func permissionEpochRestartDelay(result app.PermissionEpochResult) time.Duration {
	if result.Suspended {
		return time.Second
	}
	return 31 * time.Second
}

// permissionDeletionSigning reads the context deletion signing key's public
// keys from OpenBao once, on first use, and keeps the successful result for
// the process: the deletion cleaner and the retention lifecycle records sign
// with the latest version at that time.
type permissionDeletionSigning struct {
	w     *hubWorker
	mu    sync.Mutex
	value *contracts.ContextDeletionSigning
}

func (s *permissionDeletionSigning) get(ctx context.Context) (contracts.ContextDeletionSigning, error) {
	if s == nil || s.w == nil || s.w.providers == nil {
		return contracts.ContextDeletionSigning{}, mounts.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.value == nil {
		latest, keys, err := s.w.providers.ContextDeletionSigningPublicKeys(ctx)
		if err != nil {
			return contracts.ContextDeletionSigning{}, &fixedStepError{"signing.keys", err}
		}
		k := s.w.config.Provider.ContextDeletionSigning
		v := contracts.ContextDeletionSigning{Mount: k.Mount, Key: k.Key, Version: latest, KeyID: permissionDeletionKeyID(latest), PublicKeys: make(map[string][]byte, len(keys))}
		for version, key := range keys {
			v.PublicKeys[permissionDeletionKeyID(version)] = key
		}
		s.value = &v
	}
	return cloneContextDeletion(contracts.ContextDeletionDeployment{Signing: *s.value}).Signing, nil
}

// permissionDeletionKeyID names a Transit key version in a deletion or
// lifecycle record's JWS header.
func permissionDeletionKeyID(version int) string { return "v" + strconv.Itoa(version) }
