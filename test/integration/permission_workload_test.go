package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	configapp "asservat.local/asservat/internal/application/configuration"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// journalWorkloads reads the real connector workload journal service in
// process, as the hub-worker reads it over the cluster-observation channel.
type journalWorkloads struct {
	journal *configapp.WorkloadJournalService
}

func (j journalWorkloads) RemoteWorkloads(ctx context.Context, cluster string, sel cfg.WorkloadSelection) (cfg.WorkloadList, error) {
	s, err := j.journal.Snapshot(ctx, sel)
	if err != nil {
		return cfg.WorkloadList{}, err
	}
	return cfg.WorkloadList{ClusterID: cluster, Journal: s.Journal, Selection: sel, ObservedAt: s.ObservedAt, Workloads: s.Workloads}, nil
}

type realWorkloadGuard struct{ guard *kube.WorkloadGuard }

func (g realWorkloadGuard) WorkloadGuard(ctx context.Context, cluster string) (cfg.NamespaceGuardProof, error) {
	p, err := g.guard.WorkloadGuardProof(ctx)
	if err != nil || p.ClusterID != cluster {
		return cfg.NamespaceGuardProof{}, cfg.ErrUnavailable
	}
	return p, nil
}

// workloadFixture is the ADR-247 workload metadata guard with its probe in
// an empty quota-zero namespace, two Deployments in one shared namespace and
// the connector workload journal.
type workloadFixture struct {
	guard     realWorkloadGuard
	journal   *configapp.WorkloadJournalService
	namespace *core.Namespace
	api, web  *apps.Deployment
	source    *unstructured.Unstructured
	cleanup   func()
}

const (
	workloadManaged = "workload.example.invalid/managed"
	workloadOwner   = "workload.example.invalid/owner"
)

func workloadDeployment(name, owner string) *apps.Deployment {
	selector := map[string]string{"app.kubernetes.io/name": name}
	return &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{workloadManaged: "true", workloadOwner: owner}},
		Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(0)), Selector: &meta.LabelSelector{MatchLabels: selector}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: selector}, Spec: core.PodSpec{Containers: []core.Container{{Name: "app", Image: "registry.invalid/app:0"}}}}}}
}

func newWorkloadFixture(t *testing.T, ctx context.Context, c *rest.Config, native, adminNative kubernetes.Interface, admins []cfg.KubernetesActor, cluster string, control cfg.NamespaceRef, issuer string) *workloadFixture {
	t.Helper()
	f := &workloadFixture{}
	probeNS, err := native.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "workload-guard-probe"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	account, err := native.CoreV1().ServiceAccounts(probeNS.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "probe"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	probeRef := cfg.NamespaceRef{Name: probeNS.Name, UID: string(probeNS.UID)}
	plan := cfg.WorkloadAdministration{Name: "workload-metadata-guard", Administrators: admins, LabelKeys: []string{workloadManaged, workloadOwner}, ProbeNamespace: probeRef, ProbeAccount: cfg.NamespaceRef{Name: account.Name, UID: string(account.UID)}}
	pin, err := kube.EnsureWorkloadGuard(ctx, native, plan)
	if err != nil {
		t.Fatal(err)
	}
	expiry := int64(600)
	token, err := native.CoreV1().ServiceAccounts(probeNS.Name).CreateToken(ctx, account.Name, &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &expiry}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	probeConfig := rest.AnonymousClientConfig(c)
	probeConfig.BearerToken = token.Status.Token
	probe, err := kube.NewPermissionClient(probeConfig, cluster, probeRef, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := kube.NewPermissionClient(c, cluster, probeRef, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	g, err := kube.NewWorkloadGuard(observer, probe, plan, kube.GuardPin{PolicyUID: pin.PolicyUID, PolicyGeneration: pin.PolicyGeneration, BindingUID: pin.BindingUID, BindingResourceVersion: pin.BindingResourceVersion})
	if err != nil {
		t.Fatal(err)
	}
	f.guard = realWorkloadGuard{g}
	var proven bool
	for range 100 {
		if _, err = f.guard.WorkloadGuard(ctx, cluster); err == nil {
			proven = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !proven {
		t.Fatal("workload guard never proved enforcement", err)
	}
	// The probe's create right cannot run anything: the quota admits no
	// Deployment, so an unkeyed real create is refused too.
	probeNative, err := kubernetes.NewForConfig(probeConfig)
	if err != nil {
		t.Fatal(err)
	}
	unkeyed := workloadDeployment("probe-escape", "x")
	unkeyed.Labels = nil
	if _, err = probeNative.AppsV1().Deployments(probeNS.Name).Create(ctx, unkeyed, meta.CreateOptions{}); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatal("probe account created a real Deployment", err)
	}
	if f.namespace, err = adminNative.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "shared-apps"}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Unprivileged writers can neither create keyed workloads nor change keys.
	outsider := rest.CopyConfig(c)
	outsider.Impersonate = rest.ImpersonationConfig{UserName: "fixture-outsider", Groups: []string{"system:authenticated", "system:masters"}}
	outsiderNative, err := kubernetes.NewForConfig(outsider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = outsiderNative.AppsV1().Deployments(f.namespace.Name).Create(ctx, workloadDeployment("forged", "payments"), meta.CreateOptions{}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatal("unprivileged keyed workload creation was not denied", err)
	}
	if f.api, err = adminNative.AppsV1().Deployments(f.namespace.Name).Create(ctx, workloadDeployment("api", "payments"), meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if f.web, err = adminNative.AppsV1().Deployments(f.namespace.Name).Create(ctx, workloadDeployment("web", "other"), meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = outsiderNative.AppsV1().Deployments(f.namespace.Name).Patch(ctx, "web", "application/merge-patch+json", []byte(`{"metadata":{"labels":{"`+workloadOwner+`":"payments"}}}`), meta.PatchOptions{}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatal("unprivileged owner change was not denied", err)
	}
	journalClient, err := kube.NewPermissionClient(c, cluster, control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	f.journal = &configapp.WorkloadJournalService{Observer: journalClient, Now: time.Now}
	f.source = &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "PermissionSource", "metadata": map[string]any{"name": "workload-owners", "namespace": control.Name},
		"spec": map[string]any{"enabled": true, "clusterID": cluster, "type": "workloadMetadata", "namespaceSelector": map[string]any{"matchLabels": map[string]any{}}, "workloadSelector": map[string]any{"matchLabels": map[string]any{workloadManaged: "true"}}, "excludedNamespaces": []any{"kube-system"},
			"role": "workload-maintainer", "maxDecisionAgeSeconds": int64(30), "maxNamespaces": int64(100), "protection": map[string]any{"mode": "admissionEnforced", "reviewRef": "synthetic-workload-review", "guardRef": kube.WorkloadGuardProfile},
			"metadataMapping": map[string]any{"field": "label", "key": workloadOwner, "mode": "valueMap", "issuer": issuer, "values": map[string]any{"payments": []any{"team-workload"}}}}}}
	f.cleanup = func() {
		f.journal.Close()
		for _, n := range []string{f.namespace.Name, probeNS.Name} {
			_ = native.CoreV1().Namespaces().Delete(context.Background(), n, meta.DeleteOptions{})
		}
		_ = native.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(context.Background(), plan.Name, meta.DeleteOptions{})
		_ = native.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(context.Background(), plan.Name, meta.DeleteOptions{})
	}
	return f
}
