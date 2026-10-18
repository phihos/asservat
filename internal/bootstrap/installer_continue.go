package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	capacityapp "asservat.local/asservat/internal/application/capacity"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/rest"
)

// InstallerContinuation is one ADR-183 continuation process. It reopens the
// completed bootstrap under the chart's runner account and runs the existing
// post-activation producers. It holds no provider administration credential.
type InstallerContinuation struct {
	in       *providerInputs
	plan     contracts.InitialPreparer
	input    contracts.InstallerContinuation
	roots    [][]byte
	preparer *kube.InitialPreparer
	observer *kube.InitialBootstrapObserver
	history  *pgxpool.Pool
	record   audit.InitialInstallation
	receipt  audit.Receipt
	sql      *postgres.InitialRuntimeBridgeSQL
	admin    *pgxpool.Config
	closers  []func()
	// The bridge's control-namespace observer and owner workload guard, reused
	// by the public runtime role root (ADR-184).
	control    *kube.PermissionClient
	ownerGuard *kube.OwnerWorkloadProtection
	// The worker account's probe client, for the capacity guard proofs.
	workerProbe *kube.PermissionClient
	// capacity keeps the initialized capacity inputs for the projection
	// after the owner launch (ADR-190).
	capacity *installedCapacity
	// sources are the latest EnsurePublicSources references (ADR-185/194);
	// publicProjection the published public runtime projection (ADR-194).
	sources          *kube.PublicSources
	publicProjection contracts.WorkerObjectReference
	// federation is the ADR-193 federation input once its account and audit
	// Secret exist; the phase-3 artifact then carries its provider roles.
	federation *contracts.FederationDeployment
	publisher  *installerPublisher
	// The public role root and producer, kept open for the permission step.
	publicRoot  *kube.PublicRuntimeRoleRoot
	publicRoles *postgres.PublicRuntimeSQLRoles
	// step names the current fixed step for the operator's stop message.
	step    string
	started time.Time
}

func (k *InstallerContinuation) Close() {
	if k == nil {
		return
	}
	for i := len(k.closers) - 1; i >= 0; i-- {
		k.closers[i]()
	}
	k.closers = nil
}

// OpenInstallerContinuation reopens the activated installation: the original
// preparer and passive history under native protection, the acknowledged
// activation record, and the operator superuser for the runtime SQL bridge.
// preparer is the produce step's fresh projection; files holds the
// continuation input, the superuser and the kubelet-rotated runner token.
func OpenInstallerContinuation(ctx context.Context, files, preparer *os.Root, step *string) (*InstallerContinuation, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || preparer == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	k := &InstallerContinuation{}
	complete := false
	defer func() {
		if !complete {
			k.Close()
		}
	}()
	*step = "open/input"
	raw, err := mounts.Read(ctx, files, contracts.InstallerContinuationFile, contracts.InstallerContinuationMaxBytes)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	k.input, err = contracts.DecodeInstallerContinuation(bytes.NewReader(raw))
	clear(raw)
	if err != nil || k.input.Format != contracts.InstallerContinuationFormat {
		return nil, mounts.ErrUnavailable
	}
	// ADR-194 decision 1: promotion needs the capacity and federation steps.
	if p := k.input.Public; p != nil && p.Promotion != nil && (p.Capacity == nil || p.Federation == nil || len(p.ProcessingOperators) == 0) {
		return nil, mounts.ErrUnavailable
	}
	// ADR-202: promotion implies federation (checked above).
	if p := k.input.Public; p != nil && p.Promotion != nil && p.Promotion.Exposure != nil && !validPublicExposure(*p.Promotion.Exposure, *p.Federation) {
		return nil, mounts.ErrUnavailable
	}
	// ADR-198 decision 6: the key service's key clients are the promoted
	// owner's worker PKI.
	if p := k.input.Public; p != nil && p.Federation != nil && p.Federation.KeyServiceEndpoint != "" && p.Promotion == nil {
		return nil, mounts.ErrUnavailable
	}
	// ADR-196 decision 7: the offer names the whole executor section or none.
	if p := k.input.Public; p != nil && p.Federation != nil && (p.Federation.EvidenceStore != nil) != (p.Federation.KeyServiceEndpoint != "" && p.Federation.OwnerAddress != "") {
		return nil, mounts.ErrUnavailable
	}
	// ADR-197: regional capacity needs the executor section and hub capacity.
	if p := k.input.Public; p != nil && p.Federation != nil && p.Federation.OwnerOperationAddress != "" && (p.Federation.EvidenceStore == nil || p.Capacity == nil || !ownerDialAddress(p.Federation.OwnerOperationAddress)) {
		return nil, mounts.ErrUnavailable
	}
	*step = "open/owner-roots"
	if k.roots, err = providerconfig.TrustRootsPEM([]byte(k.input.OwnerIssuerRootsPEM), time.Now()); err != nil {
		return nil, mounts.ErrUnavailable
	}
	*step = "open/preparer"
	if k.preparer, k.plan, k.in, k.observer, err = initialBootstrapPreparerTokens(ctx, preparer, files); err != nil {
		return nil, err
	}
	if k.input.Namespace == "" || k.input.Namespace == k.plan.Plan.Workload.Namespace {
		k.in.closeHTTP()
		k.observer.Close()
		k.preparer.Close()
		return nil, mounts.ErrUnavailable
	}
	k.closers = append(k.closers, k.in.closeHTTP, k.observer.Close, k.preparer.Close)
	*step = "open/history"
	reader, pool, err := initialBootstrapHistory(ctx, preparer, k.preparer, k.plan)
	if err != nil {
		return nil, err
	}
	k.history = pool
	k.closers = append(k.closers, pool.Close)
	*step = "open/activation"
	observed, err := reader.ObserveInitialInstallation(ctx)
	if err != nil || observed.Disposition != app.InitialInstallationActivated || observed.Record == nil || observed.AuditReceipt == nil {
		return nil, errors.Join(mounts.ErrUnavailable, err)
	}
	k.record, k.receipt = *observed.Record, *observed.AuditReceipt
	*step = "open/superuser"
	if k.admin, err = k.in.sqlConfig(ctx, "postgres-administrator.json"); err != nil {
		return nil, mounts.ErrUnavailable
	}
	*step = "open/sql-bridge"
	if k.sql, err = postgres.NewInitialRuntimeBridgeSQL(ctx, k.admin.ConnConfig, k.record, k.receipt); err != nil {
		return nil, mounts.ErrUnavailable
	}
	k.closers = append(k.closers, k.sql.Close)
	complete = true
	return k, nil
}

// Resources creates or reopens the 19-resource journal of the fresh provider
// pair and advances every claim (ADR-149). The two empty audit Secrets exist
// before the first claim so their UIDs enter the original binding.
func (k *InstallerContinuation) Resources(ctx context.Context) (*kube.InitialRuntimeResources, contracts.InitialRuntimeResourceSnapshot, kube.InitialRuntimeResourceInventory, error) {
	var snapshot contracts.InitialRuntimeResourceSnapshot
	var inventory kube.InitialRuntimeResourceInventory
	admin := k.in.kubernetes("administrator-token")
	installation, namespace := k.plan.Plan.InstallationID, k.plan.Plan.Workload.Namespace
	k.at("resources/audit-secrets")
	worker, owner, err := kube.EnsureProviderAuditSecrets(ctx, admin, namespace, installation)
	// A rerun finds the Secrets already filled: reopen them, and require the
	// existing journal instead of creating one (ADR-187).
	reopen := errors.Is(err, cfg.ErrChanged)
	if reopen {
		worker, owner, err = kube.ReadProviderAuditSecrets(ctx, admin, namespace, installation)
	}
	if err != nil {
		return nil, snapshot, inventory, err
	}
	w, o := k.input.WorkerProvider, k.input.OwnerProvider
	k.at("resources/producer")
	resources, err := kube.NewProviderInstalledRuntimeResources(ctx, k.preparer, k.sql, k.roots,
		contracts.ConfigurationProviderSelection{AuthMount: w.AuthMount, AuthMountAccessor: w.AuthMountAccessor, AuditCredentials: worker},
		contracts.OwnerProviderSelection{AuthMount: o.AuthMount, AuthMountAccessor: o.AuthMountAccessor, AuditCredentials: owner})
	if err != nil {
		return nil, snapshot, inventory, err
	}
	fail := func(e error) (*kube.InitialRuntimeResources, contracts.InitialRuntimeResourceSnapshot, kube.InitialRuntimeResourceInventory, error) {
		resources.Close()
		return nil, snapshot, inventory, e
	}
	k.at("resources/journal")
	// An existing journal is reopened; its original claims and end are kept.
	if snapshot, err = resources.Read(ctx); err != nil {
		if reopen {
			return fail(err)
		}
		if snapshot, err = resources.Create(ctx); err != nil {
			return fail(err)
		}
	}
	k.at("resources/advance")
	for len(snapshot.State.Objects) < contracts.InitialRuntimeResourceCount || !initialRuntimeResourcesReceipted(snapshot) {
		if snapshot, err = resources.Advance(ctx); err != nil {
			return fail(err)
		}
	}
	k.at("resources/inventory")
	if inventory, err = resources.ReadInventory(ctx); err != nil {
		return fail(err)
	}
	return resources, snapshot, inventory, nil
}

func initialRuntimeResourcesReceipted(s contracts.InitialRuntimeResourceSnapshot) bool {
	for _, o := range s.State.Objects {
		if o.Receipt == nil {
			return false
		}
	}
	return true
}

// Bridge applies the guard bridge (probe, then retained) over the configuration
// role source built from the installer-minted owner and worker probe tokens.
func (k *InstallerContinuation) Bridge(ctx context.Context, inventory kube.InitialRuntimeResourceInventory) (*kube.InitialRuntimeBridge, *kube.ConfigurationRoleSource, error) {
	admin := k.in.kubernetes("administrator-token")
	control := cfg.NamespaceRef{Name: inventory.Namespace.Name, UID: inventory.Namespace.UID}
	cluster := k.record.Scope.ClusterID
	k.at("bridge/observer")
	observer, err := kube.NewPermissionClient(admin, cluster, control, time.Now)
	if err != nil {
		return nil, nil, err
	}
	probe := func(account contracts.WorkerObjectReference) (*kube.PermissionClient, error) {
		return kube.NewPermissionClient(k.in.kubernetesToken(accountTokens(admin, control.Name, account.Name, k.plan.Plan.ProbeAudience)), cluster, control, time.Now)
	}
	ownerProbe, err := probe(inventory.OwnerAccount)
	if err != nil {
		return nil, nil, err
	}
	workerProbe, err := probe(inventory.WorkerAccount)
	if err != nil {
		return nil, nil, err
	}
	pin := func(g contracts.OwnerDeploymentGuard) kube.GuardPin {
		return kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}
	}
	plan := func(g contracts.OwnerDeploymentGuard, name string) cfg.ConfigMapAdministration {
		return cfg.ConfigMapAdministration{Name: g.Name, SourceName: name, ControlNamespace: control, Administrators: inventory.BridgeAdministration.Owner.Administrators}
	}
	k.at("bridge/protection")
	owner, err := kube.NewOwnerWorkloadProtection(observer, ownerProbe, inventory.BridgeAdministration.Owner, pin(inventory.WorkloadGuard))
	if err != nil {
		return nil, nil, err
	}
	fleetGuard, err := kube.NewFleetConfigurationProtection(observer, workerProbe, plan(inventory.FleetGuard, inventory.FleetSource.Name), pin(inventory.FleetGuard))
	if err != nil {
		return nil, nil, err
	}
	fleet, err := kube.NewProtectedFleetSettings(observer, fleetGuard, inventory.FleetSource.Name, inventory.FleetSource.UID, k.record.Scope.InstallationID)
	if err != nil {
		return nil, nil, err
	}
	ownerGuard, err := kube.NewOwnerConfigurationProtection(observer, workerProbe, plan(inventory.OwnerSourceGuard, inventory.OwnerSource.Name), pin(inventory.OwnerSourceGuard))
	if err != nil {
		return nil, nil, err
	}
	ownerSource, err := kube.NewOwnerConfigurationSource(observer, ownerGuard, inventory.OwnerSource.Name, inventory.OwnerSource.UID, k.record.Scope.InstallationID)
	if err != nil {
		return nil, nil, err
	}
	in := contracts.ConfigurationRuntimeRoles{Format: contracts.ConfigurationRuntimeRolesFormat, InstallationID: k.record.Scope.InstallationID, InitialClaimID: k.record.Claim.ID, ClusterID: cluster, Namespace: inventory.Namespace, Deployment: inventory.WorkerDeployment, ServiceAccount: inventory.WorkerAccount, FleetSource: inventory.FleetSource, OwnerSource: inventory.OwnerSource, LayoutDigest: postgres.ConfigurationRuntimeRoleLayoutDigest()}
	k.control, k.ownerGuard, k.workerProbe = observer, owner, workerProbe
	k.at("bridge/source")
	source, err := kube.NewConfigurationRoleSource(observer, owner, fleet, ownerSource, in)
	if err != nil {
		return nil, nil, err
	}
	k.at("bridge/journal")
	bridge, err := kube.NewInitialRuntimeBridge(ctx, k.preparer, source, k.sql, inventory.BridgeAdministration)
	if err != nil {
		return nil, nil, err
	}
	current, err := bridge.ReadInitialRuntimeBridge(ctx)
	if err != nil {
		current, err = bridge.CreateInitialRuntimeBridge(ctx)
	}
	// Each guard step proves a policy the API applies asynchronously. A replay
	// is lookup-only for an unknown result, so waiting for convergence is safe.
	k.at("bridge/probe")
	if err == nil && (current.State.Probe == nil || current.State.Probe.Receipt == nil) {
		err = converge(ctx, 30*time.Second, func() (e error) { current, e = bridge.AdvanceInitialRuntimeProbe(ctx); return })
	}
	k.at("bridge/retained")
	if err == nil && (current.State.Retained == nil || current.State.Retained.Receipt == nil) {
		err = converge(ctx, 30*time.Second, func() (e error) { current, e = bridge.AdvanceInitialRuntimeRetained(ctx); return })
	}
	// The bridge releases the runtime Deployment controllers; their delayed
	// status writes must land before a role proof pins resource versions.
	k.at("bridge/settle")
	if err == nil {
		settle, end := context.WithTimeout(ctx, 2*time.Minute)
		err = kube.AwaitDeploymentsSettled(settle, admin, control.Name, inventory.WorkerDeployment.Name, inventory.OwnerDeployment.Name)
		end()
	}
	if err != nil {
		bridge.Close()
		return nil, nil, err
	}
	return bridge, source, nil
}

// at starts a named step and reports the previous one's duration. Progress
// lines carry only fixed step names and durations.
func (k *InstallerContinuation) at(step string) {
	now := time.Now()
	if k.step != "" && !k.started.IsZero() {
		fmt.Fprintf(os.Stdout, "installer continuation: %s done in %s\n", k.step, now.Sub(k.started).Round(time.Millisecond))
	}
	k.step, k.started = step, now
}

// accountTokens re-mints a runtime account's ten-minute probe token five
// minutes before expiry; the continuation can outlive a single token.
func accountTokens(admin *rest.Config, namespace, account, audience string) kms.TokenSource {
	var mu sync.Mutex
	var token []byte
	var until time.Time
	return func(ctx context.Context) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		if time.Until(until) < 5*time.Minute {
			next, err := kube.MintAccountToken(ctx, admin, namespace, account, audience)
			if err != nil {
				return nil, err
			}
			clear(token)
			token, until = next, time.Now().Add(10*time.Minute)
		}
		return bytes.Clone(token), nil
	}
}

// converge repeats one replay-safe step for at most limit inside the caller's
// original deadline: while Kubernetes applies a policy, or while a role
// operation that overran its own five-second window resumes by lookup.
func converge(ctx context.Context, limit time.Duration, step func() error) error {
	bound, end := context.WithTimeout(ctx, limit)
	defer end()
	var first error
	for attempts := 1; ; attempts++ {
		err := step()
		if err == nil || errors.Is(err, cfg.ErrChanged) && first == nil {
			return err
		}
		if first == nil {
			first = err
		}
		if errors.Is(err, cfg.ErrChanged) {
			return &convergeStop{first: first, last: err, attempts: attempts}
		}
		select {
		case <-bound.Done():
			return &convergeStop{first: first, last: err, attempts: attempts}
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// federationConcurrency is how many lifecycle conversations the installed
// federation admits at once; it answers 429 beyond that. Two served only
// the regional executor and renewal. ADR-197's two capacity standbys add a
// steady stream of short owner reads, which CI continuation run 9 saw
// refused as hub-channel while slower registration conversations held both
// slots. Each federation SQL pool stays at one connection.
const federationConcurrency = 4

// fixedStepError names a fixed continuation sub-step for the stop message.
type fixedStepError struct {
	step string
	err  error
}

func (e *fixedStepError) Error() string { return e.step }
func (e *fixedStepError) Unwrap() error { return e.err }

// FixedStep appends a nested fixed step, so labels compose across layers.
func (e *fixedStepError) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}

// convergeStop keeps the first attempt's fixed step: a replay after an
// overrun is lookup-only, so the last error alone hides the cause.
type convergeStop struct {
	first, last error
	attempts    int
}

func (e *convergeStop) Error() string { return e.last.Error() }
func (e *convergeStop) Unwrap() error { return e.last }
func (e *convergeStop) FixedStep() string {
	return fixedStep(e.last) + fmt.Sprintf(" after %d attempts; first %s (%s)", e.attempts, fixedStep(e.first), errorClass(e.first))
}

func fixedStep(err error) string {
	var inner interface{ FixedStep() string }
	if errors.As(err, &inner) {
		return inner.FixedStep()
	}
	return "-"
}

// WorkerRecipe derives the original configuration documents, as the qualified
// native chain does, and publishes the exact installed worker2 provider
// artifact to the outbox (phase 1 end). The worker inputs driver later adds
// the activation from the journal itself.
func (k *InstallerContinuation) WorkerRecipe(ctx context.Context, resources *kube.InitialRuntimeResources, snapshot contracts.InitialRuntimeResourceSnapshot, inventory kube.InitialRuntimeResourceInventory, worker contracts.WorkerObjectReference) (InitialConfigurationDocuments, error) {
	admin := k.in.kubernetes("administrator-token")
	original := resources.Initial()
	if original.InstallationID != k.record.Scope.InstallationID || original.Namespace != inventory.Namespace {
		return InitialConfigurationDocuments{}, mounts.ErrUnavailable
	}
	k.at("worker/configuration-documents")
	docs, err := BuildInitialConfigurationDocuments(original, inventory, k.record.Claim.ID)
	if err != nil {
		return docs, err
	}
	deployment, err := contracts.DecodeHubWorkerDeployment(bytes.NewReader(docs.Worker))
	if err != nil {
		return docs, err
	}
	w := k.input.WorkerProvider
	k.at("worker/outbox")
	artifact, err := providerconfig.ConfigurationProviderPairSetupArtifact(deployment, contracts.ConfigurationProviderSelection{AuthMount: w.AuthMount, AuthMountAccessor: w.AuthMountAccessor, AuditCredentials: worker}, inventory.WorkerAccount, snapshot.State.WorkerLayout, time.Now())
	if err != nil {
		return docs, err
	}
	return docs, kube.PublishInstallerRecipe(ctx, admin, k.input.Namespace, k.record.Scope.InstallationID, contracts.InstallerRecipeOutbox{Format: contracts.InstallerRecipeOutboxFormat, Phase: 1, Purpose: "worker-provider", Recipe: artifact})
}

// awaitInbox polls the operator inbox for phase until ctx ends; the caller's
// deadline is the original journal end.
func (k *InstallerContinuation) awaitInbox(ctx context.Context, phase int) (kube.InstallerInbox, error) {
	admin := k.in.kubernetes("administrator-token")
	for {
		inbox, err := kube.ReadInstallerInbox(ctx, admin, k.input.Namespace, k.record.Scope.InstallationID, phase)
		if err == nil {
			return inbox, nil
		}
		select {
		case <-ctx.Done():
			return inbox, errors.Join(mounts.ErrUnavailable, ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
}

// WorkerLaunch is phase 2: after the operator applied the worker recipe it
// inspects the provider, fills the original audit Secret, provisions the
// three configuration roles and completes the worker inputs and launch.
func (k *InstallerContinuation) WorkerLaunch(ctx context.Context, resources *kube.InitialRuntimeResources, snapshot contracts.InitialRuntimeResourceSnapshot, source *kube.ConfigurationRoleSource, bridge *kube.InitialRuntimeBridge, docs InitialConfigurationDocuments) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	var roles contracts.ConfigurationRuntimeRoleSnapshot
	worker := snapshot.State.WorkerProvider
	if worker == nil {
		return roles, mounts.ErrUnavailable
	}
	deployment, err := contracts.DecodeHubWorkerDeployment(bytes.NewReader(docs.Worker))
	if err != nil {
		return roles, err
	}
	installer, err := contracts.DecodeConfigurationRoleInstaller(bytes.NewReader(docs.Roles))
	if err != nil {
		return roles, err
	}
	k.at("worker/inbox")
	inbox, err := k.awaitInbox(ctx, 1)
	if err != nil {
		return roles, err
	}
	defer clear(inbox.InspectionToken)
	defer clear(inbox.AuditCredential)

	if c, e := contracts.DecodeOwnerStorageCredential(bytes.NewReader(inbox.AuditCredential)); e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return roles, mounts.ErrUnavailable
	}
	k.at("worker/inspection")
	inspector, err := providerconfig.NewSetupReader(contracts.OwnerProviderEndpoint{Endpoint: deployment.KeyService.Endpoint, Roots: deployment.KeyService.Roots}, inbox.InspectionToken)
	if err != nil {
		return roles, err
	}
	defer func() { _ = inspector.Close(context.Background()) }()
	admin := k.in.kubernetes("administrator-token")
	k.at("worker/audit-secret")
	if err = kube.FillProviderAuditSecret(ctx, admin, k.plan.Plan.Workload.Namespace, worker.AuditCredentials, contracts.ConfigurationProviderAuditCredentialFile, inbox.AuditCredential); err != nil {
		return roles, err
	}
	k.at("worker/roles-root")
	root, err := kube.NewConfigurationRuntimeRoleRoot(ctx, source, installer.Roles)
	if err != nil {
		return roles, err
	}
	defer root.Close()
	k.at("worker/roles-sql")
	producer, err := postgres.NewConfigurationRuntimeSQLRoles(ctx, k.admin.ConnConfig, root, installer.Roles)
	if err != nil {
		return roles, err
	}
	defer producer.Close()
	k.at("worker/roles-provision")
	// One role operation proves the guarded source three times inside its
	// original five seconds at 20 QPS. A role created before an overrun
	// completes on replay, which verifies and never recreates it.
	if err = converge(ctx, time.Minute, func() error { _, e := producer.Provision(ctx); return e }); err != nil {
		return roles, err
	}
	k.at("worker/roles-projection")
	if err = root.WithConfigurationRoleOperation(ctx, func(call context.Context) error {
		verified, e := producer.VerifyConfigurationRuntimeRoles(call)
		if e == nil {
			_, e = root.PublishConfigurationRuntimeProjection(call, verified)
		}
		return e
	}); err != nil {
		return roles, err
	}
	k.at("worker/inputs")
	inputs, err := kube.NewConfigurationWorkerInputs(ctx, bridge, resources, root, producer, inspector, snapshot)
	if err != nil {
		return roles, err
	}
	defer inputs.Close()
	k.at("worker/inputs-complete")
	if r, e := inputs.CompleteInputs(ctx); e != nil || r.Progress != kube.ConfigurationWorkerInputAcknowledged {
		return roles, errors.Join(mounts.ErrUnavailable, e)
	}
	k.at("worker/launch")
	launched, err := inputs.CompleteLaunch(ctx)
	if err != nil || launched.Progress != kube.ConfigurationWorkerLaunchAcknowledged {
		return roles, errors.Join(mounts.ErrUnavailable, err)
	}
	return launched.Snapshot, kube.DeleteInstallerInbox(ctx, admin, k.input.Namespace, k.record.Scope.InstallationID, inbox.UID)
}

// acceptedOwnerSource opens the running worker's audited accepted owner
// projection with the original configuration-source role (one connection of
// its LIMIT 3) and waits until the worker has accepted a current observation.
func (k *InstallerContinuation) acceptedOwnerSource(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, s contracts.ConfigurationRuntimeRoleSnapshot) (*pgxpool.Pool, *postgres.OwnerConfigurations, error) {
	m := contracts.ConfigurationRuntimeCredentialManifest{Format: contracts.ConfigurationRuntimeCredentialManifestFormat, Input: s.State.Input, RootUID: s.UID, SetupID: s.State.OperationID}
	var credential contracts.OwnerSQLCredential
	for _, r := range s.State.Roles {
		if r.Claim == nil || r.Receipt == nil {
			return nil, nil, mounts.ErrUnavailable
		}
		m.Roles = append(m.Roles, contracts.ConfigurationRuntimeCredentialProof{Purpose: r.Purpose, Claim: *r.Claim, Receipt: *r.Receipt})
		if r.Purpose == "configuration-source" {
			credential = contracts.OwnerSQLCredential{Username: r.Receipt.RoleName, Password: r.Password}
		}
	}
	if credential.Username == "" || credential.Password == "" {
		return nil, nil, mounts.ErrUnavailable
	}
	p, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	p.ConnConfig = k.admin.ConnConfig.Copy()
	p.ConnConfig.User, p.ConnConfig.Password = credential.Username, credential.Password
	p.ConnConfig.RuntimeParams = map[string]string{"application_name": "asservat-installer-owner-source", "statement_timeout": "5000ms", "lock_timeout": "1000ms", "idle_in_transaction_session_timeout": "5000ms"}
	p.MaxConns, p.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, p)
	if err != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	if err = postgres.VerifyConfigurationRuntimeCredential(call, pool, m, "configuration-source"); err != nil {
		pool.Close()
		return nil, nil, err
	}
	reader, err := postgres.NewOwnerConfigurations(call, pool, k.record.Scope.InstallationID, k.record.Scope.ClusterID, inventory.Namespace.UID, inventory.OwnerSource.UID)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	for {
		if v, e := reader.ReadOwnerConfiguration(ctx); e == nil && v.Valid(time.Now()) {
			return pool, reader, nil
		}
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, nil, errors.Join(mounts.ErrUnavailable, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// PublicSources creates or reopens the browser and identity settings and the
// empty guarded cluster catalog (ADR-185) before the owner phase. A promoted
// launch calls it again after capacity with the download environment
// (ADR-194), which also creates the owner's two download sources.
func (k *InstallerContinuation) PublicSources(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, environment *contracts.DownloadEnvironmentSettings) (*kube.PublicSources, error) {
	p := k.input.Public
	if p == nil {
		return nil, nil
	}
	k.at("public/sources")
	browser := contracts.BrowserSettings{SchemaVersion: "browser-settings/v1", Revision: 1, RootID: uuid.NewString(), SessionEpoch: uuid.NewString(),
		Issuer: p.Issuer, ClientID: p.ClientID, Origin: p.Origin, MaxLifetimeSeconds: p.MaxLifetimeSeconds, MaxLogins: p.MaxLogins, MaxSessions: p.MaxSessions, MaxLogoutEvents: p.MaxLogoutEvents}
	identity := contracts.IdentitySettings{SchemaVersion: "identity-settings/v1", Revision: 1, Issuer: p.Issuer, Clients: p.Clients,
		EligibleSubjects: p.EligibleSubjects, EligibleGroups: p.EligibleGroups, GroupsAtIssueQualified: true, GroupMaxAgeSeconds: p.GroupMaxAgeSeconds}
	if identity.EligibleSubjects == nil {
		identity.EligibleSubjects = []contracts.IdentitySubject{}
	}
	if identity.EligibleGroups == nil {
		identity.EligibleGroups = []string{}
	}
	control := cfg.NamespaceRef{Name: inventory.Namespace.Name, UID: inventory.Namespace.UID}
	sources, err := kube.EnsurePublicSources(ctx, k.in.kubernetes("administrator-token"), control, k.record.Scope.InstallationID, inventory.BridgeAdministration.Owner.Administrators, browser, identity, environment)
	if err != nil {
		return nil, err
	}
	k.sources = &sources
	return &sources, nil
}

// processingSettings is the first download environment document. ADR-192:
// the capacity processing source and the owner download environment carry
// the same settings.
func (k *InstallerContinuation) processingSettings(root string) contracts.DownloadEnvironmentSettings {
	return contracts.DownloadEnvironmentSettings{Format: contracts.DownloadEnvironmentFormat, RootID: root, InstallationID: k.record.Scope.InstallationID, RecoveryEpoch: k.record.Scope.IssuerEpoch, Revision: 1,
		PermittedRegions: []string{}, Paths: []contracts.DownloadEnvironmentPath{}, Clients: []contracts.DownloadEnvironmentClient{}, Operators: k.input.Public.ProcessingOperators}
}

// PublicRoles provisions the public runtime roles before the owner's one
// launch and publishes their immutable projection (ADR-184). The role root
// accepts the still-inert Recreate owner and the accepted owner source.
func (k *InstallerContinuation) PublicRoles(ctx context.Context, resources *kube.InitialRuntimeResources, bridge *kube.InitialRuntimeBridge, inventory kube.InitialRuntimeResourceInventory, roles contracts.ConfigurationRuntimeRoleSnapshot, accepted *postgres.OwnerConfigurations) error {
	k.at("public/roles-binding")
	// After the guard bridge only the bridge's retained reader can read the
	// original journal; a plain read sees the advanced guard as a change.
	snapshot, err := bridge.ReadRetainedResources(ctx, resources)
	if err != nil {
		return err
	}
	binding, err := kube.BuildPublicRuntimeWorkerBinding(snapshot, inventory, roles)
	if err != nil {
		return err
	}
	input := contracts.PublicRuntimeRoles{Format: contracts.PublicRuntimeRolesFormat, InstallationID: k.record.Scope.InstallationID, InitialClaimID: k.record.Claim.ID,
		OwnerConfigurationUID: inventory.OwnerSource.UID, ClusterID: k.record.Scope.ClusterID, Namespace: inventory.Namespace,
		LayoutDigest: postgres.PublicRuntimeRoleLayoutDigest(), Worker: binding}
	k.at("public/roles-root")
	root, err := kube.NewPublicRuntimeRoleRoot(ctx, k.control, k.ownerGuard, accepted, input)
	if err != nil {
		return err
	}
	k.at("public/roles-sql")
	producer, err := postgres.NewPublicRuntimeSQLRoles(ctx, k.admin.ConnConfig, root, input)
	if err != nil {
		root.Close()
		return err
	}
	// The permission step reuses this root after the owner selection (ADR-189).
	k.publicRoot, k.publicRoles = root, producer
	k.closers = append(k.closers, root.Close, producer.Close)
	k.at("public/roles-provision")
	if err = converge(ctx, 10*time.Minute, func() error { _, e := producer.Provision(ctx); return e }); err != nil {
		return err
	}
	// Verification and publication share one role operation, so the verified
	// candidate's original interval covers the projection (ADR-186). Only an
	// acknowledged first projection claim creates; replays are lookup-only.
	k.at("public/roles-projection")
	return converge(ctx, time.Minute, func() error {
		return root.WithPublicRoleOperation(ctx, func(op context.Context) error {
			verified, e := producer.Verify(op)
			if e == nil {
				k.publicProjection, e = root.PublishPublicRuntimeProjection(op, verified)
			}
			return e
		})
	})
}

// Owner is phases 3 and 4: the original owner selection and its recipe, then,
// after the operator applied it, the owner audit Secret, the four identity
// roles, the immutable projection and the one zero-to-one launch.
func (k *InstallerContinuation) Owner(ctx context.Context, resources *kube.InitialRuntimeResources, bridge *kube.InitialRuntimeBridge, inventory kube.InitialRuntimeResourceInventory, roles contracts.ConfigurationRuntimeRoleSnapshot) error {
	k.at("owner/accepted-source")
	pool, accepted, err := k.acceptedOwnerSource(ctx, inventory, roles)
	if err != nil {
		return err
	}
	defer pool.Close()
	if k.input.Public != nil {
		if err = k.PublicRoles(ctx, resources, bridge, inventory, roles, accepted); err != nil {
			return err
		}
	}
	k.at("owner/roles")
	root, err := kube.NewProviderOwnerIdentityRoleRoot(ctx, bridge, resources, accepted, postgres.OwnerIdentityRoleLayoutDigest())
	if err != nil {
		return err
	}
	defer root.Close()
	k.at("owner/roles-sql")
	sql, err := postgres.NewOwnerIdentityOperationSQL(ctx, k.admin.ConnConfig, root, root.Input())
	if err != nil {
		return err
	}
	defer sql.Close()
	plan := contracts.OwnerBootstrapPlan{Format: contracts.OwnerBootstrapPlanFormat, PKIMount: k.input.OwnerPKIMount, Connections: k.input.OwnerConnections, Concurrency: k.input.OwnerConcurrency, Peers: []contracts.OwnerBootstrapPeerPlan{{ClusterID: k.record.Scope.ClusterID, Roots: k.roots}}}
	k.at("owner/selection")
	selection, err := kube.NewOwnerBootstrapSelectionProducer(root, plan)
	if err != nil {
		return err
	}
	defer selection.Close()
	k.at("owner/selection-complete")
	bootstrap, err := selection.Complete(ctx)
	if err != nil || bootstrap.Status != kube.OwnerBootstrapComplete || bootstrap.Input.ProviderAuthentication == nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	input, profile := bootstrap.Input, *bootstrap.Input.ProviderAuthentication
	if k.input.Public != nil {
		if err = k.Permission(ctx, resources, bridge, inventory, input); err != nil {
			return err
		}
		if err = k.Capacity(ctx, inventory, input); err != nil {
			return err
		}
		if err = k.FederationProjection(ctx, input); err != nil {
			return err
		}
		if err = k.Federation(ctx, inventory, input); err != nil {
			return err
		}
		if err = k.PublisherIdentity(ctx, inventory, input); err != nil {
			return err
		}
		if k.input.Public.Promotion != nil {
			k.at("public/download-sources")
			settings := k.processingSettings(input.PermissionRootID)
			if _, err = k.PublicSources(ctx, inventory, &settings); err != nil {
				return err
			}
		}
		if k.capacity != nil {
			// ADR-190 decision 7: the owner serves the hub cluster's capacity
			// observation to this exact hub-worker caller.
			k.at("capacity/local-observation")
			caller, e := selection.ReadWorkerCaller(ctx)
			if e != nil {
				return e
			}
			c, s := caller.Pin, k.capacity.sources
			input.Observation.LocalCapacity = &contracts.OwnerLocalCapacityObservation{Guard: s.NamespaceGuard, Keys: slices.Sorted(slices.Values(k.input.Public.Capacity.NamespaceKeys)),
				ProbeNamespace: s.ProbeNamespace, ProbeAccount: s.ProbeAccount, ProbeAudience: k.plan.Plan.ProbeAudience,
				Caller: contracts.OwnerObservationCaller{Account: c.Account, AccountUID: c.AccountUID, Deployment: c.Deployment, DeploymentUID: c.DeploymentUID,
					TemplateDigest: hex.EncodeToString(c.TemplateDigest[:]), ImageDigest: hex.EncodeToString(c.ImageDigest[:]), ProtectionDigest: hex.EncodeToString(c.ProtectionDigest[:])}}
		}
	}
	observed, err := accepted.ReadOwnerConfiguration(ctx)
	if err != nil || !observed.Valid(time.Now()) || observed.Configuration.Revision.UID != input.ConfigurationUID {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	k.at("owner/outbox")
	// ADR-194: a promoted artifact also creates the derived public keys and
	// roles; only their names are known before the readback.
	var promotion *contracts.InstallerOwnerPromotion
	if k.input.Public != nil {
		promotion = k.input.Public.Promotion
	}
	named := input
	if promotion != nil {
		transit, signing, pki := promotedKeyNames(input.InstallationID, k.record.Scope.IssuerEpoch, *promotion)
		named.Public = &contracts.OwnerPublicDeployment{SessionTransit: transit, WorkSigning: signing, WorkerPKI: pki}
	}
	artifact, err := providerconfig.OwnerProviderSetupArtifact(named, profile, observed.Configuration.Pool, observed.Configuration.IssuerRoots, time.Now(), k.federation)
	if err != nil {
		return err
	}
	admin := k.in.kubernetes("administrator-token")
	if err = kube.PublishInstallerRecipe(ctx, admin, k.input.Namespace, k.record.Scope.InstallationID, contracts.InstallerRecipeOutbox{Format: contracts.InstallerRecipeOutboxFormat, Phase: 3, Purpose: "owner-provider", Recipe: artifact}); err != nil {
		return err
	}
	k.at("owner/inbox")
	inbox, err := k.awaitInbox(ctx, 3)
	if err != nil {
		return err
	}
	defer clear(inbox.InspectionToken)
	defer clear(inbox.AuditCredential)
	for _, b := range inbox.Public {
		defer clear(b)
	}
	if promotion != nil {
		if len(inbox.Public) != len(contracts.InstallerInboxPublicFiles()) {
			return mounts.ErrUnavailable
		}
		if _, e := tls.X509KeyPair(inbox.Public[contracts.OwnerPublicTLSCertificate], inbox.Public[contracts.OwnerPublicTLSKey]); e != nil {
			return mounts.ErrUnavailable
		}
	}
	if c, e := contracts.DecodeOwnerStorageCredential(bytes.NewReader(inbox.AuditCredential)); e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return mounts.ErrUnavailable
	}
	inspector, err := providerconfig.NewSetupReader(contracts.OwnerProviderEndpoint{Endpoint: input.KeyService.Endpoint, Roots: input.KeyService.Roots}, inbox.InspectionToken)
	if err != nil {
		return err
	}
	defer func() { _ = inspector.Close(context.Background()) }()
	k.at("owner/audit-secret")
	if err = kube.FillProviderAuditSecret(ctx, admin, inventory.Namespace.Name, profile.AuditCredentials, contracts.OwnerProviderAuditCredentialFile, inbox.AuditCredential); err != nil {
		return err
	}
	if f := k.federation; f != nil {
		// ADR-193: the federation's separate audit principal and its applied
		// provider roles, read back through the inspection token.
		defer clear(inbox.FederationAuditCredential)
		if c, e := contracts.DecodeOwnerStorageCredential(bytes.NewReader(inbox.FederationAuditCredential)); e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return mounts.ErrUnavailable
		}
		k.at("federation/audit-secret")
		if err = kube.FillProviderAuditSecret(ctx, admin, inventory.Namespace.Name, f.ProviderAuthentication.AuditCredentials, contracts.FederationProviderAuditCredentialFile, inbox.FederationAuditCredential); err != nil {
			return err
		}
		k.at("federation/verify")
		roots, e := providerconfig.TrustRootsPEM([]byte(k.input.Public.Federation.ConnectorIssuerRootsPEM), time.Now())
		if e != nil {
			return e
		}
		if _, err = inspector.VerifyFederation(ctx, *f, roots); err != nil {
			return err
		}
	}
	if err = k.PublisherCredentials(ctx, inventory, inbox, inspector); err != nil {
		return err
	}
	if promotion != nil {
		if input, err = k.promote(ctx, inventory, input, named, profile, inspector, inbox.Public); err != nil {
			return err
		}
	}
	k.at("owner/projection")
	projection, err := kube.NewProviderOwnerProjection(root, sql, input, inspector)
	if err != nil {
		return err
	}
	k.at("owner/installation")
	driver, err := kube.NewProviderOwnerInstallation(projection, sql)
	if err != nil {
		return err
	}
	defer driver.Close()
	if result, e := driver.Run(ctx); e != nil || !result.Complete {
		// The driver's fixed phase and stop name where it ended; provider
		// and SQL causes stay out of the message.
		return &fixedStepError{result.Phase + "/" + string(result.Stop), errors.Join(mounts.ErrUnavailable, e)}
	}
	if p := k.input.Public; p != nil && p.Promotion != nil && p.Promotion.Exposure != nil {
		// ADR-202: the public API's own L4 Service; TLS ends in the hub-api.
		k.at("public/exposure")
		e := p.Promotion.Exposure
		if err = kube.EnsureOwnerPublicService(ctx, k.in.kubernetes("administrator-token"), inventory.Namespace.Name, k.record.Scope.InstallationID, inventory.OwnerDeployment.Name, e.ServiceType, e.NodePort); err != nil {
			return err
		}
	}
	if err = k.CapacityProjection(ctx, resources, bridge, inventory, input); err != nil {
		return err
	}
	if err = k.FederationWorkload(ctx, inventory, input); err != nil {
		return err
	}
	if err = k.RetentionBaseline(ctx, inventory, input.PermissionRootID); err != nil {
		return err
	}
	return kube.DeleteInstallerInbox(ctx, admin, k.input.Namespace, k.record.Scope.InstallationID, inbox.UID)
}

// regionalWorkKeyValidity is the offered work key's fixed window, from the
// installation's activation; renewing it means a new trust and a rejoin.
const regionalWorkKeyValidity = 5 * 365 * 24 * time.Hour

// regionalExecutorOffer is the work-trust key (the ADR-194 signing key) and
// the hub's evidence store with the capacity qualification's store ID. Both
// derive from installation facts only, so a rerun publishes the same offer.
func (k *InstallerContinuation) regionalExecutorOffer(owner contracts.OwnerDeployment, e contracts.InstallerEvidenceStore) (*contracts.APIContextWorkPublicKey, *contracts.RegionalEvidenceStore, error) {
	if owner.Public == nil || k.capacity == nil || len(k.capacity.qualification.Backends) != 1 {
		return nil, nil, mounts.ErrUnavailable
	}
	s := owner.Public.WorkSigning
	if len(s.PublicKey) != 32 || s.KeyID == "" {
		return nil, nil, mounts.ErrUnavailable
	}
	from := k.record.Claim.NotBefore.UTC()
	work := &contracts.APIContextWorkPublicKey{ID: s.KeyID, PublicKey: base64.RawURLEncoding.EncodeToString(s.PublicKey), NotBefore: from.Format(time.RFC3339Nano), NotAfter: from.Add(regionalWorkKeyValidity).Format(time.RFC3339Nano)}
	roots, err := providerconfig.TrustRootsPEM([]byte(e.RootsPEM), time.Now())
	if err != nil || !ownerEndpoint(e.Endpoint) || !identity.Text(e.Region, 128) || !identity.Text(e.Bucket, 63) {
		return nil, nil, mounts.ErrUnavailable
	}
	return work, &contracts.RegionalEvidenceStore{Endpoint: e.Endpoint, Roots: roots, Region: e.Region, Bucket: e.Bucket, StoreID: k.capacity.qualification.Backends[0].EvidenceStoreID}, nil
}

// KeyService installs the ADR-198 key service: its SQL projection, the
// generated root key and guarded configuration, and its workload behind the
// operator's serving identity. It returns what the regional offer names.
func (k *InstallerContinuation) KeyService(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, owner contracts.OwnerDeployment, connectorRoots [][]byte) (*contracts.RegionalWrapService, error) {
	settings, f := k.input.Public.Federation, k.federation
	endpoint, err := url.Parse(settings.KeyServiceEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.Path != "" || owner.Public == nil || len(owner.Public.WorkerPKI.Roots) == 0 || k.publicRoot == nil || k.publicRoles == nil {
		return nil, mounts.ErrUnavailable
	}
	admin := k.in.kubernetes("administrator-token")
	installation, namespace := k.record.Scope.InstallationID, inventory.Namespace.Name
	k.at("key-service/projection")
	if err = converge(ctx, time.Minute, func() error {
		return k.publicRoot.WithPublicRoleOperation(ctx, func(op context.Context) error {
			verified, e := k.publicRoles.Verify(op)
			if e != nil {
				return e
			}
			_, e = k.publicRoot.PublishKeyServiceRuntimeProjection(op, verified)
			return e
		})
	}); err != nil {
		return nil, err
	}
	k.at("key-service/root")
	keyID := promotedArtifactKeyID(installation)
	key, err := kube.EnsureLocalArtifactKey(ctx, admin, cfg.NamespaceRef{Name: namespace, UID: inventory.Namespace.UID}, installation, keyID, k.record.Scope.IssuerEpoch, inventory.BridgeAdministration.Owner.Administrators)
	if err != nil {
		return nil, err
	}
	// The only copy of the artifact root: losing it makes stored artifacts
	// unreadable (ADR-198 decision 2).
	fmt.Fprintf(os.Stdout, "installer continuation: back up Secret %s/%s; stored artifacts are unreadable without it\n", namespace, contracts.LocalArtifactKeySecretName(installation))
	k.at("key-service/serving")
	servingRoots, err := kube.ReadKeyServiceServingRoots(ctx, admin, namespace, installation, endpoint.Hostname())
	if err != nil {
		return nil, err
	}
	k.at("key-service/workload")
	sql := f.Postgres
	sql.MaxConnections = 1
	d := contracts.KeyServiceDeployment{Format: contracts.KeyServiceDeploymentFormat, InstallationID: installation, ClusterID: k.record.Scope.ClusterID, PermissionRootID: f.PermissionRootID, Port: contracts.KeyServicePort,
		Namespace: inventory.Namespace, Kubernetes: owner.Kubernetes, KeySource: key.Configuration, KeyID: keyID, RecoveryEpoch: k.record.Scope.IssuerEpoch, Postgres: sql,
		KeyClientRoots: owner.Public.WorkerPKI.Roots, ConnectorClientRoots: connectorRoots, Concurrency: 8}
	if err = kube.EnsureKeyServiceAccount(ctx, admin, namespace, installation); err != nil {
		return nil, err
	}
	w, err := kube.BuildKeyServiceWorkload(namespace, k.plan.Plan.Workload.Image, d, contracts.LocalArtifactKeySecretName(installation), settings.ServiceType, settings.KeyServiceNodePort)
	if err != nil {
		return nil, err
	}
	if err = kube.EnsureFederationWorkload(ctx, admin, w); err != nil {
		return nil, err
	}
	k.at("key-service/settle")
	settle, end := context.WithTimeout(ctx, 3*time.Minute)
	defer end()
	if err = kube.AwaitDeploymentsSettled(settle, admin, namespace, w.Deployment.Name); err != nil {
		return nil, err
	}
	return &contracts.RegionalWrapService{Endpoint: settings.KeyServiceEndpoint, Roots: servingRoots, KeyID: keyID}, nil
}

// RetentionBaseline creates the operator's baseline retention policy once the
// hub source has accepted its first, empty policy set (ADR-195 D2), so that
// first acceptance needs no review. Without baseline values it does nothing.
func (k *InstallerContinuation) RetentionBaseline(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, root string) error {
	if k.input.Public == nil || k.input.Public.RetentionBaseline == nil {
		return nil
	}
	k.at("retention/first-acceptance")
	wait, end := context.WithTimeout(ctx, 3*time.Minute)
	defer end()
	c := k.admin.Copy()
	c.MaxConns, c.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(wait, c)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer pool.Close()
	for {
		var sequence int64
		e := pool.QueryRow(wait, `SELECT sequence FROM retention_source WHERE root_id=$1 AND cluster_id=$2 AND namespace_uid=$3 AND hub`, root, k.record.Scope.ClusterID, inventory.Namespace.UID).Scan(&sequence)
		if e == nil && sequence >= 1 {
			break
		}
		select {
		case <-wait.Done():
			return errors.Join(mounts.ErrUnavailable, wait.Err())
		case <-time.After(2 * time.Second):
		}
	}
	k.at("retention/baseline")
	return kube.EnsureRetentionBaseline(ctx, k.in.kubernetes("administrator-token"), inventory.Namespace.Name, k.record.Scope.InstallationID, *k.input.Public.RetentionBaseline)
}

// promote is ADR-194 order step 6: the public key and role readback, the
// derived promoted input, the empty worker-control catalog and the operator
// public Secret, all before the owner projection.
func (k *InstallerContinuation) promote(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, input, named contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, inspector *providerconfig.SetupReader, public map[string][]byte) (contracts.OwnerDeployment, error) {
	if k.sources == nil || k.capacity == nil || k.publicProjection.UID == "" || k.input.Public.Federation == nil {
		return input, mounts.ErrUnavailable
	}
	k.at("public/readback")
	readback, err := inspector.VerifyOwnerPublic(ctx, named, profile)
	if err != nil {
		return input, err
	}
	k.at("public/derive")
	connectorRoots, err := providerconfig.TrustRootsPEM([]byte(k.input.Public.Federation.ConnectorIssuerRootsPEM), time.Now())
	if err != nil {
		return input, err
	}
	promoted, err := derivePromotedOwner(input, promotedOwnerParts{Settings: *k.input.Public, Sources: *k.sources, Qualification: k.capacity.qualification, ConnectorRoots: connectorRoots,
		IssuerEpoch: k.record.Scope.IssuerEpoch, Signing: readback.Signing, WorkerRoots: readback.WorkerRoots, Projection: k.publicProjection}, time.Now())
	if err != nil {
		return input, err
	}
	admin := k.in.kubernetes("administrator-token")
	installation := k.record.Scope.InstallationID
	k.at("public/observation-projection")
	if err = kube.WriteOwnerObservationProjection(ctx, admin, inventory.Namespace.Name, installation, contracts.OwnerWorkerTrust{Format: contracts.OwnerWorkerTrustFormat, Controls: [][]byte{}}); err != nil {
		return input, err
	}
	k.at("public/operator-secret")
	if err = kube.WriteOwnerPublicSecret(ctx, admin, inventory.Namespace.Name, installation, public); err != nil {
		return input, err
	}
	return promoted, nil
}

// RunInstallerContinue runs the ADR-183 phases 1-4. Every wait and producer ends
// at the original resource journal end; a lapse ends the attempt.
func RunInstallerContinue(ctx context.Context) error {
	step := "start"
	err := runInstallerContinue(ctx, &step)
	if err != nil {
		return &InstallerContinuationStop{Step: step, Err: err}
	}
	return nil
}

// InstallerContinuationStop names the fixed step that stopped; its message
// carries the step and error class only, never provider or Kubernetes text.
type InstallerContinuationStop struct {
	Step string
	Err  error
}

func (e *InstallerContinuationStop) Unwrap() error { return e.Err }
func (e *InstallerContinuationStop) Error() string {
	class := errorClass(e.Err)
	step := e.Step
	var inner interface{ FixedStep() string }
	if errors.As(e.Err, &inner) {
		step += "/" + inner.FixedStep()
	}
	return "installer continuation stopped at " + step + " (" + class + ")"
}

func errorClass(err error) string {
	switch {
	case errors.Is(err, cfg.ErrChanged):
		return "changed"
	case errors.Is(err, cfg.ErrInvalid):
		return "invalid"
	case errors.Is(err, cfg.ErrDenied):
		return "denied"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	}
	return "unavailable"
}

func runInstallerContinue(ctx context.Context, step *string) error {
	files, err := os.OpenRoot(contracts.InstallerContinuationRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer files.Close()
	preparer, err := os.OpenRoot(contracts.InstallerContinuationPreparerRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer preparer.Close()
	open, end := context.WithTimeout(ctx, 30*time.Minute)
	defer end()
	k, err := OpenInstallerContinuation(open, files, preparer, step)
	if err != nil {
		return err
	}
	defer k.Close()
	k.step = *step
	defer func() { *step = k.step }()
	resources, snapshot, inventory, err := k.Resources(open)
	if err != nil {
		return err
	}
	defer resources.Close()
	// ADR-187: a rerun after the owner launch has nothing left to do. A phase-3
	// inbox still holding a credential is removed.
	if l := snapshot.State.OwnerLaunch; l != nil && l.Receipt != nil {
		admin := k.in.kubernetes("administrator-token")
		if inbox, e := kube.ReadInstallerInbox(open, admin, k.input.Namespace, k.record.Scope.InstallationID, 3); e == nil {
			clear(inbox.InspectionToken)
			clear(inbox.AuditCredential)
			if e = kube.DeleteInstallerInbox(open, admin, k.input.Namespace, k.record.Scope.InstallationID, inbox.UID); e != nil {
				return e
			}
		}
		fmt.Fprintln(os.Stdout, "installer continuation: already complete")
		return nil
	}
	phase, stop := context.WithDeadline(open, snapshot.State.Until)
	defer stop()
	bridge, source, err := k.Bridge(phase, inventory)
	if err != nil {
		return err
	}
	defer bridge.Close()
	worker := snapshot.State.WorkerProvider
	if worker == nil {
		return mounts.ErrUnavailable
	}
	docs, err := k.WorkerRecipe(phase, resources, snapshot, inventory, worker.AuditCredentials)
	if err != nil {
		return err
	}
	roles, err := k.WorkerLaunch(phase, resources, snapshot, source, bridge, docs)
	if err != nil {
		return err
	}
	// ADR-185 sources precede the owner projection; their references enter the
	// promoted owner input (ADR-194).
	if _, err = k.PublicSources(phase, inventory, nil); err != nil {
		return err
	}
	return k.Owner(phase, resources, bridge, inventory, roles)
}

// Permission is the ADR-189 step after the owner selection: it applies the
// permission guard and publishes the hub-worker's permission projection for
// the selection's PermissionRootID, verified and published in one role
// operation. Only an acknowledged first claim creates; replays look up.
func (k *InstallerContinuation) Permission(ctx context.Context, resources *kube.InitialRuntimeResources, bridge *kube.InitialRuntimeBridge, inventory kube.InitialRuntimeResourceInventory, owner contracts.OwnerDeployment) error {
	if k.publicRoot == nil || k.publicRoles == nil {
		return mounts.ErrUnavailable
	}
	k.at("permission/guard")
	admins := make([]contracts.OwnerDeploymentActor, 0, len(inventory.BridgeAdministration.Owner.Administrators))
	for _, a := range inventory.BridgeAdministration.Owner.Administrators {
		admins = append(admins, contracts.OwnerDeploymentActor{Kind: a.Kind, Name: a.Name})
	}
	control := contracts.PermissionControlDeployment{ClusterID: k.record.Scope.ClusterID, Namespace: inventory.Namespace, Kubernetes: owner.Kubernetes,
		Guard:        contracts.OwnerDeploymentGuard{Name: contracts.PermissionGuardName(k.record.Scope.InstallationID), Administrators: admins},
		StatusUsers:  []string{"system:serviceaccount:" + inventory.Namespace.Name + ":" + inventory.WorkerAccount.Name},
		Delegations:  append([]contracts.PermissionDelegation{}, k.input.Public.PermissionDelegations...),
		ProbeAccount: inventory.WorkerAccount}
	guard, err := kube.EnsurePermissionGuard(ctx, k.in.kubernetes("administrator-token"), kube.PermissionAdministrationOf(control))
	if err != nil {
		return err
	}
	control.Guard = guard
	// ADR-195: the hub retention source's guard, with the same administrators.
	k.at("retention/guard")
	retention, err := kube.EnsureRetentionGuard(ctx, k.in.kubernetes("administrator-token"), kube.RetentionAdministrationOf(control, contracts.RetentionGuardName(k.record.Scope.InstallationID)))
	if err != nil {
		return err
	}
	k.at("permission/projection")
	// One projection instance owns the one claim attempt across replays; an
	// uncertain claim is lookup-only afterwards.
	var projection *kube.PermissionRuntimeProjection
	return converge(ctx, time.Minute, func() error {
		return k.publicRoot.WithPublicRoleOperation(ctx, func(op context.Context) error {
			started := time.Now()
			verified, e := k.publicRoles.Verify(op)
			if e != nil {
				return &fixedStepError{"verify after " + time.Since(started).Round(time.Millisecond).String(), e}
			}
			if projection == nil {
				deployment := contracts.PermissionDeployment{Format: contracts.PermissionDeploymentFormat, InstallationID: k.record.Scope.InstallationID, RootID: owner.PermissionRootID,
					RoleRootUID: verified.UID, RoleSetupID: verified.State.OperationID, Postgres: owner.Postgres, Control: control,
					Retention: &contracts.RetentionDeployment{Guard: retention}}
				if projection, e = kube.NewPermissionRuntimeProjection(bridge, resources, k.publicRoot, deployment); e != nil {
					return e
				}
			}
			_, e = projection.Publish(op, verified)
			return e
		})
	})
}

// installedCapacity is what the capacity projection needs after the launch.
type installedCapacity struct {
	sources       kube.CapacitySources
	qualification capacityapp.CapacityQualification
	setup         contracts.CapacityRootSetup
}

// Capacity is the ADR-190 initialization before the owner launch: the
// capacity sources and their live proofs, the qualification from the
// operator profile, then InitializeCapacity once the ADR-189 permission
// stream is fresh. Without an operator capacity profile it does nothing.
func (k *InstallerContinuation) Capacity(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, owner contracts.OwnerDeployment) error {
	p := k.input.Public.Capacity
	if p == nil {
		return nil
	}
	if k.publicRoot == nil || k.publicRoles == nil || k.control == nil || k.workerProbe == nil || len(k.input.Public.ProcessingOperators) == 0 {
		return mounts.ErrUnavailable
	}
	admin := k.in.kubernetes("administrator-token")
	installation, cluster := k.record.Scope.InstallationID, k.record.Scope.ClusterID
	control := cfg.NamespaceRef{Name: inventory.Namespace.Name, UID: inventory.Namespace.UID}
	admins := inventory.BridgeAdministration.Owner.Administrators
	// One sorted key list for the guard, its proof, the qualification and the
	// runtime pins, which compare keys in order.
	keys := slices.Sorted(slices.Values(p.NamespaceKeys))
	k.at("capacity/sources")
	sources, err := kube.EnsureCapacitySources(ctx, admin, control, installation, admins, inventory.WorkerAccount, inventory.OwnerAccount, keys, k.processingSettings(owner.PermissionRootID))
	if err != nil {
		return err
	}
	k.at("capacity/proofs")
	selector, err := kube.NewPermissionClient(k.in.kubernetesToken(accountTokens(admin, sources.ProbeNamespace.Name, sources.ProbeAccount.Name, k.plan.Plan.ProbeAudience)), cluster, cfg.NamespaceRef{Name: sources.ProbeNamespace.Name, UID: sources.ProbeNamespace.UID}, time.Now)
	if err != nil {
		return err
	}
	var proofs kube.CapacityProofs
	// The new policies apply asynchronously; a failed proof has no effect.
	if err = converge(ctx, 30*time.Second, func() (e error) {
		proofs, e = kube.ProveCapacitySources(ctx, k.control, k.workerProbe, selector, sources, control, admins, inventory.WorkerAccount, keys)
		return
	}); err != nil {
		return err
	}
	k.at("capacity/qualification")
	pool, err := kube.ReadStoragePoolUID(ctx, admin, control.Name, p.Pool)
	if err != nil {
		return err
	}
	roles, err := k.publicRoot.ReadPublicRuntimeRoles(ctx)
	if err != nil {
		return err
	}
	// ADR-192: identities and the setup time derive from the role setup, so a
	// replay rebuilds the input its committed claim bound.
	q, err := buildCapacityQualification(*p, capacityDerived{Root: owner.PermissionRootID, Installation: installation, AccountVersion: roles.State.MAC.AccountVersion,
		SystemPoolUID: pool, ProcessingSourceUID: sources.ProcessingSource.UID, ProcessingProtection: proofs.Processing,
		NamespaceGuards: []capacityapp.CapacityNamespaceQualification{{ClusterID: cluster, Digest: proofs.NamespaceDigest, Keys: keys}}, Now: roles.State.CreatedAt}, capacityIDs(roles.State.OperationID))
	if err != nil {
		return err
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return mounts.ErrUnavailable
	}
	guard, err := proofs.Guard.CapacityProtection(ctx)
	if err != nil {
		return err
	}
	setup := contracts.CapacityRootSetup{Format: contracts.CapacityRootSetupFormat, InstallationID: installation, InitialClaimID: k.record.Claim.ID, PermissionRootID: owner.PermissionRootID,
		RoleRootUID: roles.UID, RoleSetupID: roles.State.OperationID, ControlClusterID: cluster, ControlNamespaceUID: control.UID,
		SourceGuardDigest: hex.EncodeToString(guard.Digest[:]), AccountVersion: roles.State.MAC.AccountVersion, Qualification: raw}
	k.at("capacity/initialize")
	// The setup checks the permission stream before its irreversible claim,
	// so replays wait for the hub-worker's fresh, acknowledged stream.
	// One role operation scopes the root proof (ADR-186); a replay after the
	// commit recovers the exact pair and completes in its next operation.
	if err = converge(ctx, 5*time.Minute, func() error {
		return k.publicRoot.WithPublicRoleOperation(ctx, func(op context.Context) error {
			_, e := k.publicRoles.InitializeCapacity(op, setup, proofs.Guard)
			return e
		})
	}); err != nil {
		return err
	}
	k.capacity = &installedCapacity{sources: sources, qualification: q, setup: setup}
	return nil
}

// CapacityProjection is ADR-190 step 7 after the owner launch: it reads the
// local owner carrier from the launched owner and publishes the hub-worker's
// capacity projection, verified and published in one role operation. The
// hub-worker then runs capacity to ReadyAt. Download paths are empty until
// regional provisioning adds one (ADR-192).
// ponytail: a failure here is not resumable, because the ADR-187 rerun
// short-circuits after the launch; resume when that path reopens the roles.
func (k *InstallerContinuation) CapacityProjection(ctx context.Context, resources *kube.InitialRuntimeResources, bridge *kube.InitialRuntimeBridge, inventory kube.InitialRuntimeResourceInventory, owner contracts.OwnerDeployment) error {
	c := k.capacity
	if c == nil {
		return nil
	}
	if k.publicRoot == nil || k.publicRoles == nil {
		return mounts.ErrUnavailable
	}
	k.at("capacity/projection")
	installation, cluster := k.record.Scope.InstallationID, k.record.Scope.ClusterID
	s := c.sources
	deployment := contracts.CapacityDeployment{Format: contracts.CapacityDeploymentFormat, InstallationID: installation, PermissionRootID: owner.PermissionRootID, Postgres: owner.Postgres,
		// StatusUsers must equal the installed guard's plan (EnsureCapacitySources
		// grants none); the hub-worker rebuilds that plan to match the pin.
		Control: contracts.CapacityControlDeployment{ClusterID: cluster, Namespace: inventory.Namespace, Kubernetes: owner.Kubernetes, Guard: s.Guard,
			StatusUsers: []string{}, ProbeAccount: inventory.WorkerAccount},
		Clusters: []contracts.CapacityClusterDeployment{{ClusterID: cluster, ProbeNamespace: s.ProbeNamespace, ProbeAccount: s.ProbeAccount, Guard: s.NamespaceGuard,
			Keys: slices.Sorted(slices.Values(k.input.Public.Capacity.NamespaceKeys))}},
		Processing:    contracts.CapacityProcessingDeployment{Source: s.ProcessingSource, Guard: s.ProcessingGuard, Paths: []contracts.DownloadEnvironmentPath{}},
		Qualification: c.setup.Qualification}
	// One projection instance owns the one claim attempt across replays; an
	// uncertain claim is lookup-only afterwards.
	var projection *kube.CapacityRuntimeProjection
	return converge(ctx, time.Minute, func() error {
		return k.publicRoot.WithPublicRoleOperation(ctx, func(op context.Context) error {
			started := time.Now()
			verified, e := k.publicRoles.Verify(op)
			if e != nil {
				return &fixedStepError{"verify after " + time.Since(started).Round(time.Millisecond).String(), e}
			}
			if projection == nil {
				if verified.State.CapacitySetup == nil || verified.State.CapacitySetup.Receipt == nil {
					return mounts.ErrUnavailable
				}
				d := deployment
				d.RoleRootUID, d.RoleSetupID, d.AccountVersion = verified.UID, verified.State.OperationID, verified.State.MAC.AccountVersion
				m := contracts.CapacityCredentialManifest{Format: contracts.CapacityCredentialManifestFormat, Input: verified.State.Input, RootUID: verified.UID,
					SetupID: verified.State.OperationID, Capacity: *verified.State.CapacitySetup.Receipt}
				carrier, _, e := bridge.ReadCapacityLocalOwner(op, resources, d, m)
				if e != nil {
					return &fixedStepError{"local-owner", e}
				}
				d.LocalOwner = &carrier
				if projection, e = kube.NewCapacityRuntimeProjection(bridge, resources, k.publicRoot, d); e != nil {
					return e
				}
			}
			_, e = projection.Publish(op, verified)
			return e
		})
	})
}

// FederationProjection publishes the federation's six SQL logins and audit
// keys for the permission root (ADR-193 step 2a), verified and published in
// one role operation. The federation workload follows in a later step.
func (k *InstallerContinuation) FederationProjection(ctx context.Context, owner contracts.OwnerDeployment) error {
	if k.publicRoot == nil || k.publicRoles == nil {
		return mounts.ErrUnavailable
	}
	k.at("federation/projection")
	return converge(ctx, time.Minute, func() error {
		return k.publicRoot.WithPublicRoleOperation(ctx, func(op context.Context) error {
			started := time.Now()
			verified, e := k.publicRoles.Verify(op)
			if e != nil {
				return &fixedStepError{"verify after " + time.Since(started).Round(time.Millisecond).String(), e}
			}
			_, e = k.publicRoot.PublishFederationRuntimeProjection(op, verified, owner.PermissionRootID)
			return e
		})
	})
}

// Federation prepares the ADR-193 federation before the phase-3 outbox: its
// account and audit Secret, the deployment input and its provider recipe, so
// the one owner provider artifact also carries the federation's roles.
func (k *InstallerContinuation) Federation(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, owner contracts.OwnerDeployment) error {
	f := k.input.Public.Federation
	if f == nil {
		return nil
	}
	k.at("federation/identity")
	installation := k.record.Scope.InstallationID
	identity, err := kube.EnsureFederationIdentity(ctx, k.in.kubernetes("administrator-token"), inventory.Namespace.Name, installation)
	if err != nil {
		return err
	}
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	guard := owner.Guard()
	deployment := contracts.FederationDeployment{Format: contracts.FederationDeploymentFormat, InstallationID: installation, ClusterID: k.record.Scope.ClusterID,
		PermissionRootID: owner.PermissionRootID, Port: contracts.FederationPort, Postgres: owner.Postgres, AuditStore: owner.AuditStore, Concurrency: federationConcurrency, Owner: &guard,
		KeyService: contracts.FederationKeyService{Endpoint: owner.KeyService.Endpoint, Roots: owner.KeyService.Roots, AuditMount: owner.KeyService.AuditMount,
			AuditKey: prefix + "-federation-audit", PKIMount: f.ConnectorPKIMount, ClientRole: prefix + "-connector-client", ServerRole: prefix + "-connector-server"}}
	recipe, err := providerconfig.FederationProviderRecipeFor(deployment, contracts.FederationProviderAuthentication{AuthMount: k.input.OwnerProvider.AuthMount,
		AuthMountAccessor: k.input.OwnerProvider.AuthMountAccessor, Namespace: inventory.Namespace, ServiceAccount: identity.Account, AuditCredentials: identity.AuditCredentials})
	if err != nil {
		return err
	}
	deployment.ProviderAuthentication = &recipe.Profile
	// ADR-193: the hub decides the connector root backing; its backup values
	// come from the capacity profile and its identities from the role setup.
	if k.input.Public.Capacity == nil {
		return mounts.ErrUnavailable
	}
	roles, err := k.publicRoot.ReadPublicRuntimeRoles(ctx)
	if err != nil {
		return err
	}
	backing, err := buildConnectorBacking(f.Connector, k.input.Public.Capacity.Backup, owner.PermissionRootID, installation, roles.State.MAC.AccountVersion, roles.State.OperationID, roles.State.CreatedAt)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(backing)
	if err != nil {
		return mounts.ErrUnavailable
	}
	deployment.Connector = &contracts.FederationConnector{Backing: raw}
	k.federation = &deployment
	return nil
}

// FederationWorkload launches the ADR-193 federation after the owner launch
// and publishes the regional offer: the operator's serving TLS Secret must
// name the configured server, the workload must settle, and the offer then
// carries its roots with the installation-wide connector values.
func (k *InstallerContinuation) FederationWorkload(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, owner contracts.OwnerDeployment) error {
	f := k.federation
	if f == nil {
		return nil
	}
	settings := k.input.Public.Federation
	admin := k.in.kubernetes("administrator-token")
	installation, namespace := k.record.Scope.InstallationID, inventory.Namespace.Name
	k.at("federation/serving")
	servingRoots, err := kube.ReadFederationServingRoots(ctx, admin, namespace, installation, settings.ServerName)
	if err != nil {
		return err
	}
	k.at("federation/workload")
	w, err := kube.BuildFederationWorkload(namespace, k.plan.Plan.Workload.Image, inventory.OwnerDeployment.Name, *f, settings.ServiceType, settings.NodePort)
	if err != nil {
		return err
	}
	if err = kube.EnsureFederationWorkload(ctx, admin, w); err != nil {
		return err
	}
	k.at("federation/settle")
	settle, end := context.WithTimeout(ctx, 3*time.Minute)
	defer end()
	if err = kube.AwaitDeploymentsSettled(settle, admin, namespace, w.Deployment.Name); err != nil {
		return err
	}
	k.at("federation/offer")
	connectorRoots, err := providerconfig.TrustRootsPEM([]byte(settings.ConnectorIssuerRootsPEM), time.Now())
	if err != nil {
		return err
	}
	var names [6]string
	for i, purpose := range []string{"connector-source", "connector-journal", "connector-ack", "connector-cleanup", "connector-verifier", "connector-finalizer"} {
		name, ok := postgres.PublicRuntimeRoleName(installation, purpose)
		if !ok {
			return mounts.ErrUnavailable
		}
		names[i] = name
	}
	var owners *contracts.RegionalContextOwners
	if settings.OwnerAddress != "" {
		// ADR-196 decision 5: the owner's native port for regional starts.
		k.at("federation/owner-exposure")
		if err = kube.EnsureOwnerNativeService(ctx, admin, namespace, installation, inventory.OwnerDeployment.Name, settings.ServiceType, settings.OwnerNodePort, settings.OwnerOperationNodePort); err != nil {
			return err
		}
		pool, err := kube.ReadOwnerSourceConfiguration(ctx, admin, namespace, inventory.OwnerSource)
		if err != nil {
			return err
		}
		owners = &contracts.RegionalContextOwners{Address: settings.OwnerAddress, Configuration: pool}
	}
	var keys *contracts.RegionalWrapService
	if settings.KeyServiceEndpoint != "" {
		if keys, err = k.KeyService(ctx, inventory, owner, connectorRoots); err != nil {
			return err
		}
	}
	if err = k.PublisherWorkload(ctx, inventory, owner, keys); err != nil {
		return err
	}
	var work *contracts.APIContextWorkPublicKey
	var evidence *contracts.RegionalEvidenceStore
	if e := settings.EvidenceStore; e != nil {
		// ADR-196 decision 7: the hub's work key and evidence store complete
		// the regional executor section.
		k.at("federation/executor-offer")
		if work, evidence, err = k.regionalExecutorOffer(owner, *e); err != nil {
			return err
		}
	}
	var capacity *contracts.RegionalCapacityOffer
	if settings.OwnerOperationAddress != "" {
		// ADR-197: the owner's v2 operation port, its observation pin and the
		// hub's selector keys, which the region's selector guard reuses.
		o := owner.Observation
		if o == nil || owners == nil {
			return mounts.ErrUnavailable
		}
		capacity = &contracts.RegionalCapacityOffer{OperationAddress: settings.OwnerOperationAddress, Keys: slices.Sorted(slices.Values(k.input.Public.Capacity.NamespaceKeys)),
			Owner: contracts.RegionalOwnerObservation{SourceUID: owner.ConfigurationUID, TemplateDigest: o.TemplateDigest, ImageDigest: o.ImageDigest, ProtectionDigest: o.ProtectionDigest}}
	}
	return kube.PublishRegionalOffer(ctx, admin, namespace, contracts.RegionalOffer{Format: contracts.RegionalOfferFormat, InstallationID: installation, HubClusterID: k.record.Scope.ClusterID, Owners: owners, KeyService: keys, WorkKey: work, EvidenceStore: evidence, Capacity: capacity,
		PermissionRootID: f.PermissionRootID, IssuerEpoch: k.record.Scope.IssuerEpoch,
		Federation:            contracts.RegionalHubEndpoint{Endpoint: settings.Endpoint, ServerName: settings.ServerName, Roots: servingRoots},
		ConnectorServerSuffix: contracts.ConnectorServerSuffix(installation), ConnectorIssuerRoots: connectorRoots,
		Roles:            contracts.ConnectorIdentityRoles{Source: names[0], Journal: names[1], Acknowledgement: names[2], Cleanup: names[3], Verifier: names[4], Finalizer: names[5]},
		ConnectorBacking: f.Connector.Backing, Image: k.plan.Plan.Workload.Image})
}

// validPublicExposure accepts NodePort, with an optional fixed port in the
// node-port range that no federation Service pins, or LoadBalancer (ADR-202).
// A duplicate port would otherwise fail only after the owner is installed.
func validPublicExposure(e contracts.InstallerPublicExposure, f contracts.InstallerFederationSettings) bool {
	switch {
	case e.ServiceType == "LoadBalancer":
		return e.NodePort == 0
	case e.ServiceType != "NodePort":
		return false
	case e.NodePort == 0:
		return true
	}
	return e.NodePort >= 30000 && e.NodePort <= 32767 && !slices.Contains([]int32{f.NodePort, f.KeyServiceNodePort, f.OwnerNodePort, f.OwnerOperationNodePort}, e.NodePort)
}
