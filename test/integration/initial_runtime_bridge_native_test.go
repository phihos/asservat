package integration

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	auth "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

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
	fleetSource, err := kube.NewProtectedFleetSettings(observer, fleetGuard, inventory.FleetSource.Name, inventory.FleetSource.UID, record.Scope.InstallationID, "22222222-2222-4222-8222-222222222222")
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
// inspection when the harness runs with --keep-on-failure, and every run's
// objects in the development-only --keep-installed mode; the harness's
// --cleanup-kept removes the owned clusters and containers afterwards.
func keepFailedFixture(t *testing.T) bool {
	return installedKeepMode() || t.Failed() && os.Getenv("ASSERVAT_KEEP_ON_FAILURE") == "1"
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
