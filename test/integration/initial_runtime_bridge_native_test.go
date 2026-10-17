package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
	auth "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// This opt-in continuation runs only after the actual four-command original
// bootstrap chain has activated, positively retired its manager and replayed
// without setup files. It uses a separately supplied fixture administrator;
// it neither adopts that retired manager nor synthesizes another activation.
// Owner issuer roots are explicit fixture inputs. Public/provider projections,
// owner execution and an installed public workflow are not qualified here.
func qualifyInitialRuntimeBridgeNative(t *testing.T, ctx context.Context, connection *rest.Config, api kubernetes.Interface, admin *pgxpool.Pool, f fixture, desired contracts.InitialBootstrap, original contracts.InitialPreparer) {
	t.Helper()
	qualifyInitialRuntimeBridgeLayoutNative(t, ctx, connection, api, admin, f, desired, original, false, false, false)
}

func qualifyInstalledOwnerRuntimeBridgeNative(t *testing.T, ctx context.Context, connection *rest.Config, api kubernetes.Interface, admin *pgxpool.Pool, f fixture, desired contracts.InitialBootstrap, original contracts.InitialPreparer) {
	t.Helper()
	qualifyInitialRuntimeBridgeLayoutNative(t, ctx, connection, api, admin, f, desired, original, true, false, false)
}

func qualifyProviderPairRuntimeBridgeNative(t *testing.T, ctx context.Context, connection *rest.Config, api kubernetes.Interface, admin *pgxpool.Pool, f fixture, desired contracts.InitialBootstrap, original contracts.InitialPreparer) {
	t.Helper()
	qualifyInitialRuntimeBridgeLayoutNative(t, ctx, connection, api, admin, f, desired, original, true, true, false)
}

func qualifyProviderWorkerRuntimeBridgeNative(t *testing.T, ctx context.Context, connection *rest.Config, api kubernetes.Interface, admin *pgxpool.Pool, f fixture, desired contracts.InitialBootstrap, original contracts.InitialPreparer) {
	t.Helper()
	qualifyInitialRuntimeBridgeLayoutNative(t, ctx, connection, api, admin, f, desired, original, true, true, true)
}

func qualifyInitialRuntimeBridgeLayoutNative(t *testing.T, ctx context.Context, connection *rest.Config, api kubernetes.Interface, admin *pgxpool.Pool, f fixture, desired contracts.InitialBootstrap, original contracts.InitialPreparer, installedOwner, providerPair, runtimeWorker bool) {
	t.Helper()
	seed, err := kube.OpenInitialBootstrap(ctx, connection, desired)
	if err != nil {
		t.Fatal("open actual completed bootstrap", err)
	}
	defer seed.Close()
	passive, err := seed.ReadPassiveHistory(ctx)
	if err != nil || passive == nil || !passive.ManagerRetired {
		t.Fatal("read actual retired-manager history", err)
	}
	observation, err := kube.NewInitialBootstrapObserver(ctx, connection, passive.Bundle.Observation, original)
	if err != nil {
		t.Fatal("original history observer", err)
	}
	defer observation.Close()
	bootstrap := cfg.NamespaceRef{Name: original.Plan.BootstrapNamespace.Name, UID: original.Plan.BootstrapNamespace.UID}
	trace := newInitialRuntimeNativeTrace(providerPair)
	defer trace.phase(t, "complete-native-provider-pair")()
	bootstrapAdmin, err := kube.NewPermissionClient(trace.config(connection, 1), original.Plan.ClusterID, bootstrap, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := kube.NewPermissionClient(trace.config(initialRuntimeNativeTokenConfig(connection, observation.ReadToken), 2), original.Plan.ClusterID, bootstrap, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var lose atomic.Int32 // 1: actual resource POST reply; 2: actual policy PUT reply.
	var resourcePosts, policyWrites atomic.Int32
	effect := trace.config(rest.CopyConfig(connection), 0)
	effect.Wrap(func(next http.RoundTripper) http.RoundTripper {
		return ownerProbeRoundTripper(func(r *http.Request) (*http.Response, error) {
			response, e := next.RoundTrip(r)
			if e != nil || response.StatusCode >= 300 || r.URL.Query().Get("dryRun") != "" {
				return response, e
			}
			lost := false
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/serviceaccounts") && strings.Contains(r.URL.Path, "/"+desired.TargetNamespace+"/") {
				resourcePosts.Add(1)
				lost = lose.CompareAndSwap(1, 0)
			}
			if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/") && strings.HasSuffix(r.URL.Path, "/"+original.Plan.Workload.WorkloadGuard) {
				policyWrites.Add(1)
				lost = lose.CompareAndSwap(2, 0)
			}
			if lost {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 256<<10))
				_ = response.Body.Close()
				return nil, errors.New("synthetic lost actual committed reply")
			}
			return response, nil
		})
	})
	preparer, err := kube.NewInitialPreparer(effect, bootstrapAdmin, probe, original)
	if err != nil {
		t.Fatal("reopen original preparer for separate continuation", err)
	}
	defer preparer.Close()
	var recordJSON, receiptJSON []byte
	if err = admin.QueryRow(ctx, "SELECT record_json,audit_receipt_json FROM fleet_initial_activation WHERE installation_id=$1", original.Plan.InstallationID).Scan(&recordJSON, &receiptJSON); err != nil {
		t.Fatal(err)
	}
	var record audit.InitialInstallation
	var receipt audit.Receipt
	if json.Unmarshal(recordJSON, &record) != nil || json.Unmarshal(receiptJSON, &receipt) != nil || !record.Valid() || !receipt.ValidInitialInstallation(record.Scope.InstallationID, record.Claim.ID) {
		t.Fatal("actual original acknowledged activation missing")
	}
	u, err := url.Parse(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, roots := pgTLSBridge(t, u.Host)
	config := publicRoleTLSConfig(t, admin, address, roots)
	sql, err := postgres.NewInitialRuntimeBridgeSQL(ctx, config, record, receipt)
	if err != nil {
		t.Fatal("actual post-activation SQL bridge gate", err)
	}
	defer sql.Close()
	// The selected layout is fixed before the first resource claim. A separate
	// original bootstrap run is required for the other layout; neither adopts
	// an existing journal or changes an acknowledged resource template.
	newResources := kube.NewInitialRuntimeResources
	if installedOwner {
		newResources = kube.NewInstalledOwnerRuntimeResources
	}
	var resources *kube.InitialRuntimeResources
	var providers *initialRuntimeNativeProviders
	if providerPair {
		providers = initialRuntimeProviderSelections(t, ctx, api, connection, f, desired, original, true)
		providers.trace = trace
		resources, err = kube.NewProviderInstalledRuntimeResources(ctx, preparer, sql, providers.issuerRoots, providers.worker, providers.owner)
	} else {
		resources, err = newResources(ctx, preparer, sql, [][]byte{f.NativeProviders.Root})
	}
	if err != nil {
		t.Fatal("protected inert resource producer", err)
	}
	defer resources.Close()
	prefix := "asservat-" + strings.ReplaceAll(original.Plan.InstallationID, "-", "")
	// Teardown owns only exact journal-marked cluster objects. Namespace objects
	// remain covered by the existing chain's original-UID teardown.
	t.Cleanup(func() {
		initialRuntimeNativeCleanup(t, api, desired.TargetNamespace, original.Plan.InstallationID, prefix)
	})
	created, err := resources.Create(ctx)
	if err != nil {
		t.Fatal("create original private resource journal", err)
	}
	lose.Store(1)
	if _, err = resources.Advance(ctx); err == nil {
		t.Fatal("lost original resource CREATE reported success")
	}
	pending, err := resources.Read(ctx)
	if err != nil || len(pending.State.Objects) != 1 || pending.State.Objects[0].Receipt != nil {
		t.Fatal("unknown CREATE did not retain exact claim", err)
	}
	originalClaim := pending.State.Objects[0]
	for i := 0; i < contracts.InitialRuntimeResourceCount; i++ {
		pending, err = resources.Advance(ctx)
		if err != nil {
			t.Fatalf("fixed resource %d unavailable: %v", i, err)
		}
	}
	if resourcePosts.Load() != 2 || pending.UID != created.UID || len(pending.State.Objects) != contracts.InitialRuntimeResourceCount || pending.State.Objects[0].OperationID != originalClaim.OperationID || !pending.State.Objects[0].Until.Equal(originalClaim.Until) {
		t.Fatal("resource replay repeated CREATE or replaced original claim")
	}
	inventory, err := resources.ReadInventory(ctx)
	if err != nil || inventory.Namespace.UID != record.Scope.NamespaceUID || inventory.FleetSource.UID != record.Claim.FleetSource.UID {
		t.Fatal("generated inventory replaced original namespace/source", err)
	}
	for _, ref := range []contracts.WorkerObjectReference{inventory.OwnerDeployment, inventory.WorkerDeployment} {
		deployment, e := api.AppsV1().Deployments(desired.TargetNamespace).Get(ctx, ref.Name, meta.GetOptions{})
		if e != nil || string(deployment.UID) != ref.UID || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0 {
			t.Fatal("producer launched or replaced a runtime Deployment", e)
		}
	}
	initialRuntimeNativePolicyReady(t, ctx, api, inventory.OwnerSourceGuard.Name, inventory.OwnerSourceGuard.PolicyUID, inventory.OwnerSourceGuard.PolicyGeneration)
	if installedOwner {
		ownerLayout, workerLayout := contracts.OwnerInstalledLayout, contracts.HubWorkerInstalledLayout
		if providerPair {
			ownerLayout, workerLayout = contracts.OwnerProviderInstalledLayout, contracts.HubWorkerProviderInstalledLayout
		}
		if created.State.OwnerLayout != ownerLayout || created.State.WorkerLayout != workerLayout || inventory.BridgeAdministration.Owner.CapacityProbe == nil || inventory.BridgeAdministration.Owner.CapacityProbe.ServiceAccount != inventory.WorkerAccount.Name || inventory.BridgeAdministration.Owner.CapacityProbe.ServiceAccountUID != inventory.WorkerAccount.UID || len(inventory.BridgeAdministration.SourceProbes) != 3 {
			t.Fatal("fresh installed bridge lost original layout or complete worker-bound guard")
		}
		actual, e := api.AppsV1().Deployments(inventory.Namespace.Name).Get(ctx, inventory.OwnerDeployment.Name, meta.GetOptions{})
		if e != nil || string(actual.UID) != inventory.OwnerDeployment.UID || actual.Spec.Replicas == nil || *actual.Spec.Replicas != 0 {
			t.Fatal("read exact original inert installed owner", e)
		}
		if _, e := kube.ConnectorAPITemplateDigest(actual.Spec.Template); e != nil {
			t.Fatal("actual installed template cannot supply native startup pin", e)
		}
	} else if created.State.OwnerLayout != "" || created.State.WorkerLayout != "" || inventory.BridgeAdministration.Owner.CapacityProbe != nil || len(inventory.BridgeAdministration.SourceProbes) != 2 {
		t.Fatal("legacy bridge gained installed-only layout or probes")
	}
	initialRuntimeNativePolicyReady(t, ctx, api, inventory.WorkloadGuard.Name, inventory.WorkloadGuard.PolicyUID, inventory.WorkloadGuard.PolicyGeneration)
	source := initialRuntimeNativeSource(t, ctx, api, connection, desired.ProbeAudience, record, inventory, trace)
	bridge, err := kube.NewInitialRuntimeBridge(ctx, preparer, source, sql, inventory.BridgeAdministration)
	if err != nil {
		t.Fatal("exact installed guard bridge constructor", err)
	}
	defer bridge.Close()
	if _, err = bridge.CreateInitialRuntimeBridge(ctx); err != nil {
		t.Fatal("original bridge journal", err)
	}
	if _, err = bridge.AdvanceInitialRuntimeRetained(ctx); err == nil {
		t.Fatal("retained guard applied before independently proven intermediate phase")
	}
	// Lost successful updates must be exact lookup/receipt only. No delay,
	// replacement claim or third policy generation is used to manufacture pass.
	for _, advance := range []func(context.Context) (contracts.InitialRuntimeBridgeSnapshot, error){bridge.AdvanceInitialRuntimeProbe, bridge.AdvanceInitialRuntimeRetained} {
		lose.Store(2)
		if _, err = advance(ctx); err == nil {
			t.Fatal("lost actual policy reply reported success")
		}
		// API policy status converges independently. Waiting here neither
		// retries the CAS nor changes its original persisted claim/deadline.
		actual, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, original.Plan.Workload.WorkloadGuard, meta.GetOptions{})
		if e != nil {
			t.Fatal("read actual applied bridge policy", e)
		}
		initialRuntimeNativePolicyReady(t, ctx, api, actual.Name, string(actual.UID), actual.Generation)
		before := policyWrites.Load()
		if _, err = advance(ctx); err != nil || policyWrites.Load() != before {
			t.Fatal("exact applied policy lookup failed or repeated PUT", err)
		}
	}
	complete, err := bridge.ReadInitialRuntimeBridge(ctx)
	if err != nil || complete.State.Probe == nil || complete.State.Probe.Receipt == nil || complete.State.Retained == nil || complete.State.Retained.Receipt == nil || policyWrites.Load() != 2 {
		t.Fatal("both independently proven bridge receipts missing", err)
	}
	// A fresh process owns no administrator SQL callback. Its distinct passive
	// reader recognizes only the exact retained policy and original history.
	history, err := kube.NewInitialRuntimeBridgeHistory(ctx, preparer, source, record, receipt, inventory.BridgeAdministration)
	if err != nil {
		t.Fatal("read-only native bridge history reopen", err)
	}
	defer history.Close()
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig, pc.MaxConns = config.Copy(), 1
	pc.ConnConfig.User, pc.ConnConfig.Password = passive.Bundle.History.Username, passive.Bundle.History.Password
	pc.ConnConfig.TLSConfig.MinVersion = tls.VersionTLS13
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	reader, err := postgres.NewInitialInstallationReader(ctx, pool, record.Scope, record.Claim.PlanDigest, history)
	if err != nil {
		t.Fatal(err)
	}
	if providerPair {
		qualifyProviderPairWorkerInputs(t, ctx, api, config, record, original, resources, pending, inventory, source, bridge, providers, runtimeWorker)
		if runtimeWorker {
			// This distinct case has its own source-loss/Lease-loss/normal-GC
			// checks. The input-only case retains the original recovery and
			// destructive owner tests below, unchanged.
			return
		}
	}
	for _, recovery := range []bool{false, true} {
		if recovery {
			if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", record.Scope.InstallationID); err != nil {
				t.Fatal(err)
			}
			if _, err = bridge.ReadInitialRuntimeBridge(ctx); err == nil {
				t.Fatal("historical bridge success bypassed current recovery for effects")
			}
		}
		got, e := reader.ObserveInitialInstallation(ctx)
		if e != nil || got.Disposition != app.InitialInstallationActivated || got.Record == nil || !got.Record.Claim.Same(record.Claim) || got.AuditReceipt == nil || *got.AuditReceipt != receipt {
			t.Fatal("original passive history unavailable after bridge", recovery, e)
		}
	}
	// Controller progress is qualified with zero replicas: no unprovisioned
	// executable is launched to manufacture a successful installed workflow.
	initialRuntimeNativeControllerCleanup(t, ctx, api, inventory.Namespace.Name, inventory.OwnerDeployment)
	if _, e := reader.ObserveInitialInstallation(ctx); e == nil {
		t.Fatal("missing original owner Deployment preserved bridged native history proof")
	}
	t.Logf("actual original bootstrap activation/retirement, 19 fixed inert resources (installed-owner=%t), lost CREATE lookup, two lost guard-CAS replies with exact receipts and SELECT-only history during recovery, actual zero-replica controller/GC and missing-owner denial; owner/runtime/provider projection remains unqualified", installedOwner)
}

func initialRuntimeNativeTokenConfig(original *rest.Config, token func(context.Context) ([]byte, error)) *rest.Config {
	// Never retain administrator client certificates alongside a probe bearer.
	out := &rest.Config{Host: original.Host, TLSClientConfig: rest.TLSClientConfig{CAData: bytes.Clone(original.CAData), CAFile: original.CAFile, ServerName: original.ServerName}}
	out.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return ownerProbeRoundTripper(func(r *http.Request) (*http.Response, error) {
			value, err := token(r.Context())
			defer clear(value)
			if err != nil {
				return nil, err
			}
			copy := r.Clone(r.Context())
			copy.Header.Set("Authorization", "Bearer "+string(value))
			return next.RoundTrip(copy)
		})
	}
	return out
}

func initialRuntimeNativeSource(t *testing.T, ctx context.Context, api kubernetes.Interface, connection *rest.Config, audience string, record audit.InitialInstallation, inventory kube.InitialRuntimeResourceInventory, trace *initialRuntimeNativeTrace) *kube.ConfigurationRoleSource {
	t.Helper()
	control := cfg.NamespaceRef{Name: inventory.Namespace.Name, UID: inventory.Namespace.UID}
	observer, err := kube.NewPermissionClient(trace.config(connection, 3), record.Scope.ClusterID, control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	probe := func(ref contracts.WorkerObjectReference, counter int) *kube.PermissionClient {
		t.Helper()
		result, e := api.CoreV1().ServiceAccounts(control.Name).CreateToken(ctx, ref.Name, &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		v, e := kube.NewPermissionClient(trace.config(initialRuntimeNativeTokenConfig(connection, func(context.Context) ([]byte, error) { return []byte(result.Status.Token), nil }), counter), record.Scope.ClusterID, control, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	ownerProbe, workerProbe := probe(inventory.OwnerAccount, 4), probe(inventory.WorkerAccount, 5)
	pin := func(g contracts.OwnerDeploymentGuard) kube.GuardPin {
		return kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}
	}
	owner, err := kube.NewOwnerWorkloadProtection(observer, ownerProbe, inventory.BridgeAdministration.Owner, pin(inventory.WorkloadGuard))
	if err != nil {
		t.Fatal(err)
	}
	plan := func(g contracts.OwnerDeploymentGuard, name string) cfg.ConfigMapAdministration {
		return cfg.ConfigMapAdministration{Name: g.Name, SourceName: name, ControlNamespace: control, Administrators: inventory.BridgeAdministration.Owner.Administrators}
	}
	fleetGuard, err := kube.NewFleetConfigurationProtection(observer, workerProbe, plan(inventory.FleetGuard, inventory.FleetSource.Name), pin(inventory.FleetGuard))
	if err != nil {
		t.Fatal(err)
	}
	fleetSource, err := kube.NewProtectedFleetSettings(observer, fleetGuard, inventory.FleetSource.Name, inventory.FleetSource.UID, record.Scope.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	ownerGuard, err := kube.NewOwnerConfigurationProtection(observer, workerProbe, plan(inventory.OwnerSourceGuard, inventory.OwnerSource.Name), pin(inventory.OwnerSourceGuard))
	if err != nil {
		t.Fatal(err)
	}
	ownerSource, err := kube.NewOwnerConfigurationSource(observer, ownerGuard, inventory.OwnerSource.Name, inventory.OwnerSource.UID, record.Scope.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	input := contracts.ConfigurationRuntimeRoles{Format: contracts.ConfigurationRuntimeRolesFormat, InstallationID: record.Scope.InstallationID, InitialClaimID: record.Claim.ID, ClusterID: record.Scope.ClusterID, Namespace: inventory.Namespace, Deployment: inventory.WorkerDeployment, ServiceAccount: inventory.WorkerAccount, FleetSource: inventory.FleetSource, OwnerSource: inventory.OwnerSource, LayoutDigest: postgres.ConfigurationRuntimeRoleLayoutDigest()}
	source, err := kube.NewConfigurationRoleSource(observer, owner, fleetSource, ownerSource, input)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

// keepFailedFixture leaves a failed native fixture's objects in place for
// inspection when the harness runs with --keep-on-failure; the harness's
// --cleanup-kept removes the owned clusters and containers afterwards.
func keepFailedFixture(t *testing.T) bool {
	return t.Failed() && os.Getenv("ASSERVAT_KEEP_ON_FAILURE") == "1"
}

func initialRuntimeNativeCleanup(t *testing.T, api kubernetes.Interface, namespace, installation, prefix string) {
	if keepFailedFixture(t) {
		return
	}
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 15*time.Second)
	defer end()
	secret, err := api.CoreV1().Secrets(namespace).Get(ctx, "asservat-runtime-resources-"+strings.ReplaceAll(installation, "-", ""), meta.GetOptions{})
	if apierrors.IsNotFound(err) {
		return
	}
	if err != nil {
		t.Error("read owned runtime cleanup journal", err)
		return
	}
	state, err := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(secret.Data["state.json"]))
	if err != nil {
		t.Error("decode owned runtime cleanup journal", err)
		return
	}
	claims := map[string]contracts.InitialRuntimeResourceClaim{}
	for _, c := range state.Objects {
		claims[c.Item] = c
	}
	owned := func(item string, object meta.ObjectMeta) bool {
		claim, ok := claims[item]
		if !ok || object.Annotations["asservat.io/runtime-resource-operation"] != claim.OperationID || claim.Receipt != nil && string(object.UID) != claim.Receipt.UID {
			t.Error("refuse unbound runtime cleanup", item)
			return false
		}
		return true
	}
	for _, v := range []struct{ prefix, name string }{{"owner-source", prefix + "-owner-source-guard"}, {"owner-workload", prefix + "-workload-guard"}} {
		if _, exists := claims[v.prefix+"-binding"]; exists {
			object, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, v.name, meta.GetOptions{})
			if e == nil && owned(v.prefix+"-binding", object.ObjectMeta) {
				e = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, v.name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &object.UID, ResourceVersion: &object.ResourceVersion}})
			}
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("owned runtime binding cleanup", e)
			}
		}
		if _, exists := claims[v.prefix+"-policy"]; exists {
			object, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, v.name, meta.GetOptions{})
			if e == nil && owned(v.prefix+"-policy", object.ObjectMeta) {
				e = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(ctx, v.name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &object.UID, ResourceVersion: &object.ResourceVersion}})
			}
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("owned runtime policy cleanup", e)
			}
		}
	}
	for _, purpose := range []string{"owner", "worker"} {
		name := "asservat." + namespace + "." + prefix + "-" + purpose
		if _, exists := claims[purpose+"-cluster-binding"]; exists {
			object, e := api.RbacV1().ClusterRoleBindings().Get(ctx, name, meta.GetOptions{})
			if e == nil && owned(purpose+"-cluster-binding", object.ObjectMeta) {
				e = api.RbacV1().ClusterRoleBindings().Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &object.UID, ResourceVersion: &object.ResourceVersion}})
			}
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("owned runtime cluster binding cleanup", e)
			}
		}
		if _, exists := claims[purpose+"-cluster-role"]; exists {
			object, e := api.RbacV1().ClusterRoles().Get(ctx, name, meta.GetOptions{})
			if e == nil && owned(purpose+"-cluster-role", object.ObjectMeta) {
				e = api.RbacV1().ClusterRoles().Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &object.UID, ResourceVersion: &object.ResourceVersion}})
			}
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("owned runtime cluster role cleanup", e)
			}
		}
	}
}

// This bounded fixture wait is outside any product operation and only observes
// the exact already-created policy. It never supplies policy readiness to the
// product reader, which must check status and enforcement again itself.
func initialRuntimeNativePolicyReady(t *testing.T, ctx context.Context, api kubernetes.Interface, name, uid string, generation int64) {
	t.Helper()
	err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true, func(call context.Context) (bool, error) {
		p, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(call, name, meta.GetOptions{})
		if e != nil {
			return false, e
		}
		if string(p.UID) != uid || p.Generation != generation || p.DeletionTimestamp != nil {
			return false, errors.New("original bridge policy changed")
		}
		if p.Status.ObservedGeneration != generation || p.Status.TypeChecking == nil {
			return false, nil
		}
		if len(p.Status.TypeChecking.ExpressionWarnings) != 0 {
			return false, errors.New("native bridge policy has type-check warnings")
		}
		return true, nil
	})
	if err != nil {
		t.Fatal("exact native policy readiness", name, err)
	}
}

func initialRuntimeNativeControllerCleanup(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace string, deployment contracts.WorkerObjectReference) {
	t.Helper()
	var replicaName string
	var replicaUID types.UID
	err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true, func(call context.Context) (bool, error) {
		current, e := api.AppsV1().Deployments(namespace).Get(call, deployment.Name, meta.GetOptions{})
		if e != nil {
			return false, e
		}
		if string(current.UID) != deployment.UID || current.Spec.Replicas == nil || *current.Spec.Replicas != 0 {
			return false, errors.New("inert owner Deployment changed")
		}
		all, e := api.AppsV1().ReplicaSets(namespace).List(call, meta.ListOptions{})
		if e != nil {
			return false, e
		}
		for _, rs := range all.Items {
			for _, owner := range rs.OwnerReferences {
				if owner.UID == current.UID && owner.Controller != nil && *owner.Controller {
					if replicaName != "" {
						return false, errors.New("multiple controller children for inert owner")
					}
					if rs.Spec.Replicas == nil || *rs.Spec.Replicas != 0 {
						return false, errors.New("inert owner child started replicas")
					}
					replicaName, replicaUID = rs.Name, rs.UID
				}
			}
		}
		return replicaName != "", nil
	})
	if err != nil {
		t.Fatal("actual zero-replica Deployment controller", err)
	}
	current, err := api.AppsV1().Deployments(namespace).Get(ctx, deployment.Name, meta.GetOptions{})
	if err != nil || string(current.UID) != deployment.UID {
		t.Fatal("exact owner before controller cleanup", err)
	}
	foreground := meta.DeletePropagationForeground
	err = api.AppsV1().Deployments(namespace).Delete(ctx, deployment.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &current.UID, ResourceVersion: &current.ResourceVersion}, PropagationPolicy: &foreground})
	if err != nil {
		t.Fatal("exact original owner deletion", err)
	}
	err = wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true, func(call context.Context) (bool, error) {
		d, de := api.AppsV1().Deployments(namespace).Get(call, deployment.Name, meta.GetOptions{})
		rs, re := api.AppsV1().ReplicaSets(namespace).Get(call, replicaName, meta.GetOptions{})
		if de == nil && string(d.UID) != deployment.UID || re == nil && rs.UID != replicaUID {
			return false, errors.New("cleanup observed replacement identity")
		}
		if de != nil && !apierrors.IsNotFound(de) {
			return false, de
		}
		if re != nil && !apierrors.IsNotFound(re) {
			return false, re
		}
		return apierrors.IsNotFound(de) && apierrors.IsNotFound(re), nil
	})
	if err != nil {
		t.Fatal("actual guarded foreground controller cleanup", err)
	}
}
