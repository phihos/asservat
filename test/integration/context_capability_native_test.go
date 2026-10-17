package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// Recovery acceptance and image qualification are fixture facts. Admission,
// source identities, scoped credentials and all observations below use the
// actual owned Kubernetes API. This does not qualify an installed collector.
type capabilityNativeRecovery struct{ proof artifact.RecoveryProof }

func (r *capabilityNativeRecovery) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	p := r.proof
	p.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	p.FreshUntil = p.ObservedAt.Add(5 * time.Second)
	return p, ctx.Err()
}

func TestContextCapabilityWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run the owned context integration fixture")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture file unavailable")
	}
	var f fixture
	if json.Unmarshal(raw, &f) != nil || len(f.Clusters) != 2 {
		t.Fatal("invalid fixture")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	config, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := admin.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "context-capability-native", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	who, err := admin.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil || who.Status.UserInfo.Username == "" {
		t.Fatal("fixture administrator", err)
	}
	cluster := custodyID()
	projection := compiler.ProjectionDigest()
	image := strings.Split(f.WorkerImage, "@sha256:")
	if len(image) != 2 {
		t.Fatal("owned compiled fixture image is not digest pinned")
	}
	installed := contracts.ContextCapabilitySettings{Format: contracts.ContextCapabilityFormat, RootID: custodyID(), InstallationID: custodyID(), ClusterID: cluster, IssuerEpoch: custodyID(), Revision: 1, Enabled: true, ExecutionClass: string(artifact.ContextAPIExecution), CollectorVersion: "synthetic-qualified-fixture", CollectorImageDigest: image[1], ProjectionDigest: hex.EncodeToString(projection[:])}
	data, err := json.Marshal(installed)
	if err != nil {
		t.Fatal(err)
	}
	object, err := admin.CoreV1().ConfigMaps(ns.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "context-capability"}, Immutable: ptr.To(true), Data: map[string]string{"context-capability.json": string(data)}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan := cfg.ConfigMapAdministration{Name: ns.Name, SourceName: object.Name, ControlNamespace: cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}
	policy, binding, err := kube.ContextCapabilityAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	binding, err = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	makeClient := func(name string, verbs []string) (*kube.PermissionClient, kubernetes.Interface) {
		t.Helper()
		if _, e := admin.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		token, e := admin.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, name, &auth.TokenRequest{}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		limited := rest.AnonymousClientConfig(config)
		limited.BearerToken = token.Status.Token
		reader, e := kube.NewPermissionClient(limited, cluster, plan.ControlNamespace, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		api, e := kubernetes.NewForConfig(limited)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = admin.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{object.Name}, Verbs: verbs}}}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e = admin.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: name, Namespace: ns.Name}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: name}}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		return reader, api
	}
	reader, readonly := makeClient("reader", []string{"get"})
	probe, probeAPI := makeClient("probe", []string{"get", "update"})
	if _, err = admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: plan.Name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns.Name}, Verbs: []string{"get"}}, {APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{plan.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: plan.Name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "reader", Namespace: ns.Name}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: plan.Name}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pin := kube.GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion}
	guard, err := kube.NewContextCapabilityProtection(reader, probe, plan, pin)
	if err != nil {
		t.Fatal(err)
	}
	recovery := &capabilityNativeRecovery{artifact.RecoveryProof{InstallationID: installed.InstallationID, IssuerEpoch: installed.IssuerEpoch, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{1}}}}
	source, err := kube.NewContextCapabilitySource(reader, guard, recovery, object.Name, string(object.UID), installed)
	if err != nil {
		t.Fatal(err)
	}
	target := authorization.Target{ClusterID: cluster, NamespaceUID: string(ns.UID), WorkloadUID: custodyID(), PodUID: custodyID()}
	// Only wait for this exact newly installed policy to compile and enforce.
	// No unrelated admission policy exists in this fixture namespace.
	if err = wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 20*time.Second, true, func(c context.Context) (bool, error) {
		_, e := source.ContextCapability(c, target)
		return e == nil, nil
	}); err != nil {
		t.Fatal("native capability protection never became available", err)
	}
	first, err := source.ContextCapability(ctx, target)
	if err != nil || !first.Valid(time.Now()) || first.Revision.UID != string(object.UID) || first.ProjectionDigest != projection || first.FreshUntil.Sub(first.ObservedAt) > 5*time.Second {
		t.Fatal("original capability observation", err)
	}
	unchanged := func() {
		t.Helper()
		got, e := admin.CoreV1().ConfigMaps(ns.Name).Get(ctx, object.Name, meta.GetOptions{})
		if e != nil || got.UID != object.UID || got.ResourceVersion != object.ResourceVersion {
			t.Fatal("read/probe changed original source", e)
		}
	}
	unchanged()
	if _, err = readonly.CoreV1().ConfigMaps(ns.Name).Update(ctx, object, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); !apierrors.IsForbidden(err) {
		t.Fatal("reader has write permission", err)
	}
	if _, err = probeAPI.CoreV1().ConfigMaps(ns.Name).Update(ctx, object, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); err == nil || !strings.Contains(err.Error(), "Asservat context capability administrator is required.") {
		t.Fatal("probe was not denied by exact capability guard", err)
	}
	foreign := target
	foreign.ClusterID = custodyID()
	if _, err = source.ContextCapability(ctx, foreign); err == nil {
		t.Fatal("foreign target accepted")
	}
	recovery.proof.IssuerEpoch = custodyID()
	if _, err = source.ContextCapability(ctx, target); err == nil {
		t.Fatal("changed recovery epoch accepted")
	}
	recovery.proof.IssuerEpoch = installed.IssuerEpoch
	wrongImage := installed
	wrongImage.CollectorImageDigest = strings.Repeat("f", 64)
	other, err := kube.NewContextCapabilitySource(reader, guard, recovery, object.Name, string(object.UID), wrongImage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.ContextCapability(ctx, target); err == nil {
		t.Fatal("observed source qualified a different image")
	}
	unchanged()
	// Binding deletion invalidates reads immediately. Demonstrate independently
	// that RBAC permits the same dry-run once native admission is absent.
	if err = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, binding.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &binding.UID}}); err != nil {
		t.Fatal(err)
	}
	if _, err = source.ContextCapability(ctx, target); err == nil {
		t.Fatal("missing protection accepted")
	}
	if err = wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 10*time.Second, true, func(c context.Context) (bool, error) {
		_, e := probeAPI.CoreV1().ConfigMaps(ns.Name).Update(c, object, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		return e == nil, nil
	}); err != nil {
		t.Fatal("independent probe lacked update RBAC", err)
	}
	unchanged()
	// Restore the identical spec under a new UID: old guard pins must not adopt it.
	replacementBinding := binding.DeepCopy()
	replacementBinding.UID, replacementBinding.ResourceVersion = "", ""
	replacementBinding, err = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, replacementBinding, meta.CreateOptions{})
	if err != nil || replacementBinding.UID == binding.UID {
		t.Fatal("replace owned binding", err)
	}
	if _, err = source.ContextCapability(ctx, target); err == nil {
		t.Fatal("same-name binding replacement accepted")
	}
	// Independent source-UID test with the newly pinned native guard.
	pin.BindingUID, pin.BindingResourceVersion = string(replacementBinding.UID), replacementBinding.ResourceVersion
	guard, err = kube.NewContextCapabilityProtection(reader, probe, plan, pin)
	if err != nil {
		t.Fatal(err)
	}
	source, err = kube.NewContextCapabilitySource(reader, guard, recovery, object.Name, string(object.UID), installed)
	if err != nil {
		t.Fatal(err)
	}
	if err = wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 10*time.Second, true, func(c context.Context) (bool, error) {
		_, e := source.ContextCapability(c, target)
		return e == nil, nil
	}); err != nil {
		t.Fatal("re-pinned fixture guard unavailable", err)
	}
	originalUID := types.UID(object.UID)
	if err = admin.CoreV1().ConfigMaps(ns.Name).Delete(ctx, object.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &originalUID}}); err != nil {
		t.Fatal(err)
	}
	replacement := object.DeepCopy()
	replacement.UID, replacement.ResourceVersion = "", ""
	replacement, err = admin.CoreV1().ConfigMaps(ns.Name).Create(ctx, replacement, meta.CreateOptions{})
	if err != nil || replacement.UID == originalUID {
		t.Fatal("replace owned source", err)
	}
	if _, err = source.ContextCapability(ctx, target); err == nil {
		t.Fatal("same-name source replacement accepted")
	}
	t.Log("actual native capability guard, separate RBAC/probe, immutable source/image/cluster/epoch pins and replacement denial passed; image/recovery acceptance remain synthetic")
}
