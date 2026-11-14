package integration

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5/pgxpool"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// helmNativeKind is the e2e driver's description of an installed Helm-native
// release on an owned kind cluster (hn-kind/e2e.sh journey writes it).
type helmNativeKind struct {
	Kubeconfig, Namespace, NodeIP, ConsoleCAFile, KeycloakCAFile string
	ConsolePort                                                  int
}

// TestHelmNativeKindJourney drives the real user journey against a running
// all-bundled combined-mode install: Keycloak sign-in of a synthetic human,
// processing initialization, pod-status capture of a synthetic workload,
// inspection and native download. Development harness: it only runs with
// ASSERVAT_HN_KIND naming the driver's JSON description.
func TestHelmNativeKindJourney(t *testing.T) {
	path := os.Getenv("ASSERVAT_HN_KIND")
	if path == "" {
		t.Skip("ASSERVAT_HN_KIND unset")
	}
	raw, err := os.ReadFile(path)
	var k helmNativeKind
	if err != nil || json.Unmarshal(raw, &k) != nil {
		t.Fatal("kind description", err)
	}
	t.Setenv("ASSERVAT_HELM_BUNDLED_IDENTITY", "1")
	ctx, cancel := context.WithTimeout(t.Context(), 18*time.Minute)
	defer cancel()
	config, err := clientcmd.BuildConfigFromFlags("", k.Kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	api := kubernetes.NewForConfigOrDie(config)
	secret := func(name string) map[string][]byte {
		s, err := api.CoreV1().Secrets(k.Namespace).Get(ctx, name, meta.GetOptions{})
		if err != nil {
			t.Fatal("secret", name, err)
		}
		return s.Data
	}
	ids, kc := secret("asservat-ids"), secret("asservat-keycloak-state")
	settings, err := contracts.DecodeSmallKeycloakSettings(strings.NewReader(string(kc[contracts.SmallKeycloakSettingsFile])))
	if err != nil {
		t.Fatal("keycloak settings", err)
	}
	ca, err := os.ReadFile(k.KeycloakCAFile)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{Identity: &struct{ Base, RootCA, AdminUser, AdminPassword, UserPassword string }{Base: settings.Hostname, RootCA: string(ca),
		AdminUser: string(kc[contracts.SmallKeycloakAdminUsername]), AdminPassword: string(kc[contracts.SmallKeycloakAdminPassword]), UserPassword: "hn-synthetic-human-1"}}
	identity := newInstalledBundledIdentity(t, f, settings, string(kc[contracts.SmallKeycloakUsersGroup]), string(kc[contracts.SmallKeycloakConsoleSecret]), true)
	t.Logf("hn journey: synthetic humans created (developer %s) in the bundled realm", identity.SubjectID)

	root, cluster, installation := string(ids["permissionRootID"]), string(ids["clusterID"]), string(ids["installationID"])
	workload := createHelmNativeWorkload(t, ctx, api)
	budget := newRegionalBudget(t, ctx, api, k.Namespace, identity.Issuer, cluster, 1)
	budget.subjectKind, budget.subjectID = "User", identity.SubjectID
	// Combined mode: the chart's EvidenceBudgetPolicy (no clusterID: the hub
	// cluster) already covers the workload namespace; only the maintainer
	// AccessBinding is the operator's step.
	budget.addBinding(workload)

	admin := helmNativeAdminPool(t, ctx, k, secret("asservat-postgres-state"))
	consolePEM, err := os.ReadFile(k.ConsoleCAFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(consolePEM)
	if block == nil {
		t.Fatal("console CA")
	}
	origin := fmt.Sprintf("https://%s:%d", k.NodeIP, k.ConsolePort)
	diagnose := func() {
		pods, _ := api.CoreV1().Pods(k.Namespace).List(ctx, meta.ListOptions{})
		for _, p := range pods.Items {
			t.Logf("diagnostics: pod %s phase=%s", p.Name, p.Status.Phase)
		}
	}
	noDeletion := func(string) func() { return func() {} }
	noProjection := func(string) func(string, string) func() { return func(string, string) func() { return func() {} } }
	journey := installedJourney(t, ctx, admin, root, identity, block.Bytes, net.JoinHostPort(k.NodeIP, fmt.Sprint(k.ConsolePort)), origin, diagnose, noDeletion, noProjection,
		func(string, installedProcessingRun) { t.Log("hn journey: native download verified") })
	journey(cluster, workload.ns.Name, workload.app.Name, nil, nil)
	t.Logf("hn journey: complete for installation %s", installation)
}

// createHelmNativeWorkload is the synthetic capture target: a restricted
// namespace with the context trial's selector labels and one pause Pod.
func createHelmNativeWorkload(t *testing.T, ctx context.Context, api kubernetes.Interface) regionalWorkload {
	t.Helper()
	labels := helmContextTrialProfile(t).Public.Capacity.PolicySpec.Scope.NamespaceSelector.MatchLabels
	nsLabels := map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}
	for k, v := range labels {
		nsLabels[k] = v
	}
	ns, err := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "apps-hn", Labels: nsLabels}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("workload namespace", err)
	}
	selector := map[string]string{"app": "hn-app"}
	app, err := api.AppsV1().Deployments(ns.Name).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "hn-app"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Selector: &meta.LabelSelector{MatchLabels: selector},
		Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: selector}, Spec: core.PodSpec{AutomountServiceAccountToken: ptr.To(false), TerminationGracePeriodSeconds: ptr.To(int64(3)),
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
			Containers: []core.Container{{Name: "app", Image: "registry.k8s.io/pause:3.10", ImagePullPolicy: core.PullIfNotPresent, Resources: regionalWorkloadResources(false),
				SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("workload", err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		d, err := api.AppsV1().Deployments(ns.Name).Get(ctx, app.Name, meta.GetOptions{})
		if err == nil && d.Status.ReadyReplicas == 1 {
			return regionalWorkload{ns: ns, app: d}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("synthetic workload not ready")
	return regionalWorkload{}
}

// helmNativeAdminPool connects as the bundled PostgreSQL administrator
// through a kubectl port-forward (diagnostics and journey SQL checks only).
func helmNativeAdminPool(t *testing.T, ctx context.Context, k helmNativeKind, state map[string][]byte) *pgxpool.Pool {
	t.Helper()
	var admin contracts.OwnerSQLCredential
	if json.Unmarshal(state["postgres-administrator.json"], &admin) != nil {
		t.Fatal("postgres administrator")
	}
	forward := exec.CommandContext(ctx, "kubectl", "--kubeconfig", k.Kubeconfig, "-n", k.Namespace, "port-forward", "svc/asservat-postgres", "25432:5432")
	if err := forward.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forward.Process.Kill(); _ = forward.Wait() })
	caFile := t.TempDir() + "/ca.crt"
	if err := os.WriteFile(caFile, state["ca.crt"], 0o600); err != nil {
		t.Fatal(err)
	}
	dsn := fmt.Sprintf("postgres://%s:%s@127.0.0.1:25432/asservat?sslmode=require", admin.Username, admin.Password)
	for range 30 {
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil && pool.Ping(ctx) == nil {
			t.Cleanup(pool.Close)
			return pool
		}
		if pool != nil {
			pool.Close()
		}
		time.Sleep(time.Second)
	}
	t.Fatal("admin SQL port-forward")
	return nil
}
