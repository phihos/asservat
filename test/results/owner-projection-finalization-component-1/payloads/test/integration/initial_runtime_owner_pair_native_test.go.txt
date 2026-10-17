package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// This continuation is deliberately not called by the input-only native
// selector. Its caller must retain the original bridge/resources and the actual
// running configuration worker through this bundle's Close. The concrete SQL
// reader below reads that worker's audited accepted projection; no fixture
// observer, acceptance write, host Pod token or generated timestamp is accepted.
type initialRuntimeNativeOwner struct {
	root      *kube.OwnerIdentityRoleRoot
	sql       *postgres.OwnerIdentityOperationSQL
	selection *kube.OwnerBootstrapSelectionProducer
	bootstrap kube.OwnerBootstrapAdvance
	caller    kube.OwnerBootstrapWorkerCaller
	providers *initialRuntimeNativeProviders
}

func prepareProviderPairOwner(t *testing.T, ctx context.Context, config *pgx.ConnConfig, resources *kube.InitialRuntimeResources, bridge *kube.InitialRuntimeBridge, providers *initialRuntimeNativeProviders, accepted *postgres.OwnerConfigurations, plan contracts.OwnerBootstrapPlan) *initialRuntimeNativeOwner {
	t.Helper()
	if providers == nil || accepted == nil || plan.PKIMount != "owner-pki" || len(providers.issuerRoots) == 0 {
		t.Fatal("actual original worker/provider predecessors are required")
	}
	end := providers.trace.phase(t, "actual-owner-root-constructor")
	root, err := kube.NewProviderOwnerIdentityRoleRoot(ctx, bridge, resources, providerOwnerDiagnosticReader{t: t, reader: accepted}, postgres.OwnerIdentityRoleLayoutDigest())
	end()
	if err != nil {
		t.Fatal("actual accepted worker source cannot construct original owner root", err)
	}
	out := &initialRuntimeNativeOwner{root: root, providers: providers}
	complete := false
	defer func() {
		if !complete {
			out.Close()
		}
	}()
	end = providers.trace.phase(t, "actual-owner-sql-constructor")
	out.sql, err = postgres.NewOwnerIdentityOperationSQL(ctx, config, root, root.Input())
	end()
	if err != nil {
		t.Fatal("actual owner four-purpose SQL producer", err)
	}
	out.selection, err = kube.NewOwnerBootstrapSelectionProducer(root, plan)
	if err != nil {
		t.Fatal("original owner public selection producer", err)
	}
	end = providers.trace.phase(t, "actual-owner-original-selection")
	out.bootstrap, err = out.selection.Complete(ctx)
	end()
	if err != nil || out.bootstrap.Status != kube.OwnerBootstrapComplete || out.bootstrap.Input.ProviderAuthentication == nil || out.bootstrap.Input.Observation == nil || out.bootstrap.Snapshot.State.OwnerBootstrap == nil || out.bootstrap.Snapshot.State.OwnerBootstrap.Child == nil || out.bootstrap.Snapshot.State.OwnerBootstrap.Child.Receipt == nil {
		t.Fatal("original owner selection not acknowledged", err, out.bootstrap.Status, out.bootstrap.Stop)
	}
	end = providers.trace.phase(t, "actual-original-worker-caller")
	out.caller, err = out.selection.ReadWorkerCaller(ctx)
	end()
	if err != nil || !out.caller.Pin.Valid() || out.caller.Pin.RootID != out.bootstrap.Input.PermissionRootID || out.caller.Resources != root.Input().Resources || out.caller.Selection != out.bootstrap.Snapshot.State.OwnerBootstrap.Child.Receipt.Object {
		t.Fatal("actual original worker caller provenance unavailable", err)
	}
	complete = true
	return out
}

// This fixture observes only the concrete accepted reader's already-returned
// fixed diagnostic. It delegates exactly once with the original context and
// returns the observation/error unchanged; no extra query, clock or authority.
// Product native normalization remains unchanged and still exposes unavailable.
type providerOwnerDiagnosticReader struct {
	t      *testing.T
	reader *postgres.OwnerConfigurations
}

func (r providerOwnerDiagnosticReader) ReadOwnerConfiguration(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
	out, err := r.reader.ReadOwnerConfiguration(ctx)
	var failure *postgres.OwnerConfigurationReadFailure
	if errors.As(err, &failure) {
		r.t.Logf("actual accepted owner SQL read refused check=%s reason=%s; original statements and database clock only", failure.Check(), failure.Reason())
	}
	return out, err
}

// Close runs after the fixed installation driver joins and before the caller
// closes the accepted reader's pool, original worker, bridge or resource root.
func (o *initialRuntimeNativeOwner) Close() {
	if o == nil {
		return
	}
	if o.selection != nil {
		o.selection.Close()
	}
	if o.root != nil {
		o.root.Close()
	}
	if o.sql != nil {
		o.sql.Close()
	}
}

// The actual external provider already owns the auth mount/reviewer and the
// separate PKI CA fixed before the first resource binding. This helper applies
// only the generated four policies/auth roles and two exact PKI role recipes.
// No CA, mount, reviewer or provider endpoint is replaced after that binding.
func (o *initialRuntimeNativeOwner) configureProvider(t *testing.T, ctx context.Context, accepted *postgres.OwnerConfigurations) *providerconfig.SetupReader {
	t.Helper()
	input := o.bootstrap.Input
	end := o.providers.trace.phase(t, "actual-owner-provider-accepted-source")
	observed, err := accepted.ReadOwnerConfiguration(ctx)
	end()
	if err != nil || !observed.Valid(time.Now()) || observed.Configuration.Revision.UID != input.ConfigurationUID || observed.Configuration.Pool.InstallationID != input.InstallationID || observed.Configuration.Pool.ClusterID != input.ClusterID || !sameNativeOwnerRoots(observed.Configuration.IssuerRoots, o.providers.issuerRoots) {
		t.Fatal("actual accepted owner pool or original PKI roots unavailable", err)
	}
	t.Logf("owner provider setup begins with actual accepted observation age=%s remaining=%s", time.Since(observed.ObservedAt), time.Until(observed.FreshUntil))
	profile := input.ProviderAuthentication
	if profile == nil || profile.AuditCredentials != o.providers.owner.AuditCredentials || profile.AuthMount != o.providers.owner.AuthMount || profile.AuthMountAccessor != o.providers.owner.AuthMountAccessor || input.KeyService.PKIMount != "owner-pki" {
		t.Fatal("generated owner input changed original provider selection")
	}
	recipe, err := providerconfig.OwnerSetupRecipeFor(input, *profile, observed.Configuration.Pool, observed.Configuration.IssuerRoots, time.Now())
	if err != nil {
		t.Fatal("generate exact original owner provider recipe", err)
	}
	for _, role := range recipe.Authentication.Roles {
		o.providers.admin(t, ctx, http.MethodPost, "sys/policies/acl/"+role.Name, map[string]string{"policy": string(role.Policy)}, http.StatusNoContent)
		o.providers.admin(t, ctx, http.MethodPost, "auth/"+profile.AuthMount+"/role/"+role.Name, json.RawMessage(role.Role), http.StatusNoContent)
	}
	for _, role := range recipe.PKIRoles {
		o.providers.admin(t, ctx, http.MethodPost, input.KeyService.PKIMount+"/roles/"+role.Name, json.RawMessage(role.Role), http.StatusOK)
	}
	const policy = "owner-setup-inspection"
	o.providers.admin(t, ctx, http.MethodPost, "sys/policies/acl/"+policy, map[string]string{"policy": string(recipe.InspectionPolicy)}, http.StatusNoContent)
	reply := o.providers.admin(t, ctx, http.MethodPost, "auth/token/create", map[string]any{"policies": []string{policy}, "no_default_policy": true, "renewable": false, "ttl": "5m", "explicit_max_ttl": "5m"}, http.StatusOK)
	var token struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	if json.Unmarshal(reply, &token) != nil || token.Auth.Token == "" {
		clear(reply)
		t.Fatal("actual named owner inspector credential unavailable")
	}
	clear(reply)
	t.Cleanup(func() {
		call, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		o.providers.admin(t, call, http.MethodPost, "auth/token/revoke", map[string]string{"token": token.Auth.Token}, http.StatusNoContent)
	})
	reader, err := providerconfig.NewSetupReader(contracts.OwnerProviderEndpoint{Endpoint: input.KeyService.Endpoint, Roots: input.KeyService.Roots}, []byte(token.Auth.Token))
	if err != nil {
		t.Fatal("actual fixed owner setup reader", err)
	}
	// Return the reader, not a setup proof. The concrete projection obtains its
	// own fresh sixteen named GETs before each original SQL/native phase.
	return reader
}

// Call only after independently qualifying and filling the original selected
// one-key owner S3 Secret. The concrete projection checks that identity/content;
// this helper does not install a placeholder or substitute storage credentials.
func (o *initialRuntimeNativeOwner) install(t *testing.T, ctx context.Context, api kubernetes.Interface, setup *providerconfig.SetupReader) {
	t.Helper()
	projection, err := kube.NewProviderOwnerProjection(o.root, &nativeOwnerProjectionSQLDiagnostic{sql: o.sql, t: t, trace: o.providers.trace}, o.bootstrap.Input, setup)
	if err != nil {
		t.Fatal("actual generated owner projection", err)
	}
	driver, err := kube.NewProviderOwnerInstallation(projection, o.sql)
	if err != nil {
		t.Fatal("actual finite owner installation driver", err)
	}
	defer driver.Close()
	end := o.providers.trace.phase(t, "actual-owner-four-roles-projection-launch")
	result, err := driver.Run(ctx)
	end()
	if err != nil || !result.Complete || result.Phase != "launch-receipt" || result.ResourceRootUID != o.root.Input().Resources.UID || result.Calls > 27 || result.Finalizations != 8 || result.Inspections > 1 {
		t.Fatal("actual owner installation stopped", result.Phase, result.Stop, result.Calls, result.Inspections, err)
	}
	end = o.providers.trace.phase(t, "actual-owner-launch-current-readback")
	final, err := projection.InspectLaunch(ctx)
	end()
	if err != nil || final.Status != kube.OwnerProjectionAdvanceComplete || final.Snapshot.UID != result.ResourceRootUID || final.Snapshot.State.OwnerIdentity == nil || final.Snapshot.State.OwnerIdentity.Receipt == nil || final.Snapshot.State.OwnerLaunch == nil || final.Snapshot.State.OwnerLaunch.Receipt == nil || final.Snapshot.State.OwnerLaunch.OperationID != result.OperationID {
		t.Fatal("actual acknowledged owner launch readback", err)
	}
	claim := final.Snapshot.State.OwnerIdentity
	if claim.RoleRoot.UID != result.RoleRootUID || claim.Credentials == nil || claim.Credentials.Receipt == nil || claim.Configuration == nil || claim.Configuration.Receipt == nil || claim.Receipt.Configuration != claim.Configuration.Receipt.Object || claim.Receipt.Credentials != claim.Credentials.Receipt.Object {
		t.Fatal("owner joint receipt lost individually acknowledged originals")
	}
	input := o.root.Input()
	deployment, err := api.AppsV1().Deployments(input.Namespace.Name).Get(ctx, input.Deployment.Name, meta.GetOptions{})
	if err != nil || string(deployment.UID) != input.Deployment.UID || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Generation != final.Snapshot.State.OwnerLaunch.Receipt.Generation {
		t.Fatal("actual owner deployment is not the acknowledged original launch", err)
	}
	t.Log("actual accepted-worker owner root, original selection and caller provenance, four SQL roles, immutable projection children and acknowledged original zero-to-one launch; no running-owner readiness, observation backend or public workflow claim")
}

func sameNativeOwnerRoots(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// Exact delegate: same concrete SQL adapter once, same context and return.
// Only its reviewed closed enum is rendered, never a driver error/string.
type nativeOwnerProjectionSQLDiagnostic struct {
	sql           *postgres.OwnerIdentityOperationSQL
	t             *testing.T
	calls         int
	finalizations int
	trace         *initialRuntimeNativeTrace
}

func (s *nativeOwnerProjectionSQLDiagnostic) AdvanceOwnerProjectionOperation(ctx context.Context, op *kube.OwnerProjectionOperation) (kube.OwnerProjectionAdvance, error) {
	s.calls++
	before := s.trace.limiterSnapshot()
	out, err := s.sql.AdvanceOwnerProjectionOperation(ctx, op)
	delta := s.trace.limiterSnapshot().subtract(before)
	s.t.Logf("actual owner projection SQL call=%d limiter[C B H S W T] waits=%v wait-refusals-live-context=%v wait-refusals-cancelled-context=%v; same original buckets, no time samples", s.calls, delta.waits, delta.liveRefusals, delta.cancelledRefusals)
	var detail *postgres.OwnerProjectionSQLFailure
	if errors.As(err, &detail) {
		s.t.Logf("actual owner projection SQL call=%d refused check=%s reason=%s; original statements and time checks only", s.calls, detail.Check().String(), detail.Reason().String())
	}
	return out, err
}

func (s *nativeOwnerProjectionSQLDiagnostic) FinalizeOwnerProjectionOperation(ctx context.Context, op *kube.OwnerProjectionFinalization) (kube.OwnerProjectionAdvance, error) {
	s.finalizations++
	before := s.trace.limiterSnapshot()
	out, err := s.sql.FinalizeOwnerProjectionOperation(ctx, op)
	delta := s.trace.limiterSnapshot().subtract(before)
	s.t.Logf("actual owner read-only finalization SQL call=%d limiter[C B H S W T] waits=%v wait-refusals-live-context=%v wait-refusals-cancelled-context=%v; same original buckets", s.finalizations, delta.waits, delta.liveRefusals, delta.cancelledRefusals)
	return out, err
}
