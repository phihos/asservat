package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// permissionFixtureCluster is the owned permission fixture's cluster ID.
const permissionFixtureCluster = "11111111-1111-4111-8111-111111111111"

// permissionFixtureTarget is the fixture's application namespace, where its
// AccessBindings live (ADR-329).
func permissionFixtureTarget(t *testing.T, ctx context.Context, c *rest.Config) value.NamespaceRef {
	t.Helper()
	client, err := kubernetes.NewForConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, "payments", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return value.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}
}

// TestPermissionNamespaceBindingsWithRealKubernetes reconciles AccessBindings
// from application namespaces and PermissionSources from the control
// namespace with real SQL and encrypted audit (ADR-329). Kubernetes RBAC
// decides the writers; the fixture group holds ordinary CRUD.
func TestPermissionNamespaceBindingsWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_PERMISSION_FIXTURE")
	if path == "" {
		t.Skip("run make permission-integration")
	}
	var fixture struct{ Config, Token, Postgres, S3 string }
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &fixture) != nil {
		t.Fatal("fixture unavailable")
	}
	clear(data)
	c, err := clientcmd.BuildConfigFromFlags("", fixture.Config)
	if err != nil {
		t.Fatal(err)
	}
	c.Timeout = 5 * time.Second
	client, err := kubernetes.NewForConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	control, err := client.CoreV1().Namespaces().Get(ctx, "asservat-system", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "permission-fixture-writers"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"asservat.io"}, Resources: []string{"accessbindings", "permissionsources", "accessbindings/status", "permissionsources/status"}, Verbs: []string{"create", "update", "patch", "delete", "get", "list"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "permission-fixture-writers"}, Subjects: []rbac.Subject{{Kind: "Group", APIGroup: rbac.GroupName, Name: "asservat-fixture-writers"}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "permission-fixture-writers"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan := value.PermissionAdministration{Name: "asservat-permissions", ControlNamespace: value.NamespaceRef{Name: control.Name, UID: string(control.UID)}, Administrators: []value.KubernetesActor{{Kind: "User", Name: "fixture-admin"}}, StatusUsers: []string{"fixture-status"}}
	observer, err := kube.NewPermissionClient(c, permissionFixtureCluster, plan.ControlNamespace, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	digest := artifact.Digest(sha256.Sum256([]byte("asservat-permission-fixture-trust")))
	trust, err := kube.NewPlainPermissionTrust(observer, digest)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("reconciliation-with-SQL-and-encrypted-audit", func(t *testing.T) {
		testGuardedReconciliation(t, ctx, c, observer, trust, plan, fixture.Postgres, fixture.S3, fixture.Token)
		testIdentitySettings(t, ctx, c, permissionFixtureCluster, plan.ControlNamespace, fixture.Token)
		testBrowserSettingsSource(t, ctx, c, permissionFixtureCluster, plan.ControlNamespace, fixture.Token, fixture.Postgres)
	})
	t.Run("namespace-inheritance-with-real-namespaces-SQL-and-audit", func(t *testing.T) {
		testInheritedReconciliation(t, c, observer, trust, plan, fixture.Postgres, fixture.S3)
	})
	t.Run("guarded-and-group-id-inheritance-with-real-guard-and-identity-settings", func(t *testing.T) {
		testGuardedAndGroupInheritance(t, c, observer, trust, plan, fixture.Postgres, fixture.S3)
	})
	t.Run("decision-time-reviews-with-real-subject-access-reviews-SQL-and-audit", func(t *testing.T) {
		testDecisionTimeReviews(t, c, fixture.Postgres, fixture.S3)
	})
}
