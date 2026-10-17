package integration

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	configuration "asservat.local/asservat/internal/application/configuration"
	value "asservat.local/asservat/internal/domain/configuration"
	privacy "asservat.local/asservat/internal/domain/privacy"
	admission "k8s.io/api/admissionregistration/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func TestRetentionWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_PERMISSION_FIXTURE")
	if path == "" {
		t.Skip("run make permission-integration")
	}
	var f struct{ Config, Postgres, S3 string }
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	c, err := clientcmd.BuildConfigFromFlags("", f.Config)
	if err != nil {
		t.Fatal(err)
	}
	c.Timeout = 5 * time.Second
	core, err := kubernetes.NewForConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ns, err := core.CoreV1().Namespaces().Get(ctx, "asservat-system", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	gr := schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "evidenceretentionpolicies"}
	_, err = core.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "retention-fixture"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"asservat.io"}, Resources: []string{gr.Resource, gr.Resource + "/status"}, Verbs: []string{"get", "list", "create", "update", "patch", "delete"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "retention-fixture"}, Subjects: []rbac.Subject{{Kind: "Group", APIGroup: rbac.GroupName, Name: "retention-fixture"}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "retention-fixture"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	actor := func(name string) dynamic.ResourceInterface {
		t.Helper()
		cp := rest.CopyConfig(c)
		cp.Impersonate = rest.ImpersonationConfig{UserName: name, Groups: []string{"retention-fixture"}}
		d, err := dynamic.NewForConfig(cp)
		if err != nil {
			t.Fatal(err)
		}
		return d.Resource(gr).Namespace(ns.Name)
	}
	admin, delegate, outsider, status := actor("retention-admin"), actor("retention-delegate"), actor("retention-outsider"), actor("retention-status")
	const cluster = "11111111-1111-4111-8111-111111111111"
	plan := value.RetentionAdministration{Name: "asservat-retention-test", ControlNamespace: value.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, Administrators: []value.KubernetesActor{{Kind: "User", Name: "retention-admin"}}, StatusUsers: []string{"retention-status"}, Delegations: []value.RetentionDelegation{{Writers: []value.KubernetesActor{{Kind: "User", Name: "retention-delegate"}}, Scope: privacy.PolicyScope{ClusterIDs: []string{cluster}, NamespaceLabels: map[string]string{"privacy.example.test/team": "payments"}}}}}
	policy, binding, err := kube.RetentionAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = core.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = core.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	object := func(name string, scoped bool) *unstructured.Unstructured {
		scope := map[string]any{}
		if scoped {
			scope = map[string]any{"clusterIDs": []any{cluster}, "namespaceSelector": map[string]any{"matchLabels": map[string]any{"privacy.example.test/team": "payments"}}}
		}
		durations := func() map[string]any {
			return map[string]any{"evidenceSeconds": int64(3600), "caseMetadataSeconds": int64(7200), "auditMetadataSeconds": int64(86400)}
		}
		return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceRetentionPolicy", "metadata": map[string]any{"name": name, "namespace": ns.Name}, "spec": map[string]any{"scope": scope, "purposeRef": "diagnostics", "defaults": durations(), "maxima": durations(), "rules": []any{}, "deletionBudgetSeconds": int64(300), "legalExceptions": "disabled"}}}
	}
	dry := meta.CreateOptions{DryRun: []string{meta.DryRunAll}, FieldValidation: "Strict"}
	denied := func(err error) bool {
		return (apierrors.IsInvalid(err) || apierrors.IsForbidden(err)) && strings.Contains(err.Error(), "Asservat retention administrator")
	}
	for i := 0; i < 100; i++ {
		_, err = outsider.Create(ctx, object("probe", false), dry)
		if denied(err) {
			break
		}
		if i == 99 {
			t.Fatalf("retention guard did not enforce: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	livePolicy, err := core.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, policy.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if livePolicy.Status.TypeChecking != nil && len(livePolicy.Status.TypeChecking.ExpressionWarnings) > 0 {
		t.Fatalf("CEL warnings: %+v", livePolicy.Status.TypeChecking.ExpressionWarnings)
	}
	t.Run("baseline-and-delegated-write", func(t *testing.T) {
		if _, err := admin.Create(ctx, object("baseline", false), meta.CreateOptions{FieldValidation: "Strict"}); err != nil {
			t.Fatal(err)
		}
		if _, err := delegate.Create(ctx, object("delegated", true), meta.CreateOptions{FieldValidation: "Strict"}); err != nil {
			t.Fatal(err)
		}
		for _, a := range []dynamic.ResourceInterface{delegate, outsider, status} {
			if _, err := a.Create(ctx, object("unbounded", false), dry); !denied(err) {
				t.Fatal("unbounded writer accepted", err)
			}
		}
	})
	t.Run("scope-cannot-be-erased-or-moved", func(t *testing.T) {
		current, err := delegate.Get(ctx, "delegated", meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"cluster", "namespace", "takeover"} {
			changed := current.DeepCopy()
			switch mode {
			case "cluster":
				unstructured.SetNestedSlice(changed.Object, []any{"22222222-2222-4222-8222-222222222222"}, "spec", "scope", "clusterIDs")
			case "namespace":
				unstructured.RemoveNestedField(changed.Object, "spec", "scope", "namespaceSelector")
			case "takeover":
				changed, err = admin.Get(ctx, "baseline", meta.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				scope, _, _ := unstructured.NestedMap(current.Object, "spec", "scope")
				unstructured.SetNestedMap(changed.Object, scope, "spec", "scope")
			}
			if _, err = delegate.Update(ctx, changed, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}, FieldValidation: "Strict"}); !denied(err) {
				t.Fatal("delegation escaped old/new scope", mode, err)
			}
		}
		if err := delegate.Delete(ctx, "baseline", meta.DeleteOptions{DryRun: []string{meta.DryRunAll}}); !denied(err) {
			t.Fatal("delegate deleted baseline", err)
		}
	})
	t.Run("invalid-limits-duplicate-rules-and-unknown-fields", func(t *testing.T) {
		for _, mode := range []string{"budget", "rules", "unknown"} {
			o := object("invalid", false)
			switch mode {
			case "budget":
				unstructured.SetNestedField(o.Object, int64(3600), "spec", "deletionBudgetSeconds")
			case "rules":
				rule := map[string]any{"name": "duplicate", "maxAgeSeconds": int64(1000)}
				unstructured.SetNestedSlice(o.Object, []any{rule, rule}, "spec", "rules")
			case "unknown":
				unstructured.SetNestedField(o.Object, true, "spec", "allowEverything")
			}
			if _, err := admin.Create(ctx, o, dry); err == nil {
				t.Fatal("invalid policy persisted", mode)
			}
		}
	})
	t.Run("status-writer-separated-from-spec-author", func(t *testing.T) {
		o, err := status.Get(ctx, "baseline", meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		o.Object["status"] = map[string]any{"phase": "Ready", "observedGeneration": o.GetGeneration(), "policyDigest": strings.Repeat("a", 64), "backendCompatible": true, "maximumOutstandingLeaseSeconds": int64(0)}
		if _, err = admin.UpdateStatus(ctx, o, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); !denied(err) {
			t.Fatal("spec admin forged status", err)
		}
		if _, err = status.UpdateStatus(ctx, o, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		o, err = status.Get(ctx, "baseline", meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		unstructured.SetNestedField(o.Object, "other-purpose", "spec", "purposeRef")
		if _, err = status.Update(ctx, o, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); !denied(err) {
			t.Fatal("status role changed spec", err)
		}
	})
	t.Run("current-guard-proof-is-dry-run-and-pinned", func(t *testing.T) {
		const observerName = "retention-guard-observer"
		_, err := core.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: observerName}, Rules: []rbac.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns.Name}, Verbs: []string{"get"}},
			{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{plan.Name}, Verbs: []string{"get"}},
		}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = core.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: observerName}, Subjects: []rbac.Subject{{Kind: "User", APIGroup: rbac.GroupName, Name: observerName}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: observerName}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		permissionClient := func(user string, writer bool) *kube.PermissionClient {
			t.Helper()
			config := rest.CopyConfig(c)
			groups := []string{"system:authenticated"}
			if writer {
				groups = append(groups, "retention-fixture")
			}
			config.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
			client, err := kube.NewPermissionClient(config, cluster, plan.ControlNamespace, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			return client
		}
		observer := permissionClient(observerName, false)
		probe := permissionClient("retention-outsider", true)
		latest, err := core.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, plan.Name, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := core.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, plan.Name, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		pin := kube.GuardPin{PolicyUID: string(latest.UID), PolicyGeneration: latest.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion}
		guard, err := kube.NewRetentionGuard(observer, probe, plan, pin)
		if err != nil {
			t.Fatal(err)
		}
		before, err := admin.List(ctx, meta.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		trust, err := guard.RetentionProtection(ctx)
		if err != nil || trust.SourceClusterID != cluster || trust.ControlNamespaceUID != string(ns.UID) || trust.FreshUntil.Sub(trust.ObservedAt) != 5*time.Second {
			t.Fatal("current retention protection", err)
		}
		after, err := admin.List(ctx, meta.ListOptions{})
		if err != nil || len(after.Items) != len(before.Items) {
			t.Fatal("dry run persisted a policy", err)
		}
		for _, name := range []string{"retention-admin", "retention-delegate", "retention-status"} {
			invalid, err := kube.NewRetentionGuard(observer, permissionClient(name, true), plan, pin)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = invalid.RetentionProtection(ctx); err == nil {
				t.Fatal("privileged actor used as negative control", name)
			}
		}
		noRBAC, err := kube.NewRetentionGuard(observer, permissionClient("retention-no-rbac", false), plan, pin)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = noRBAC.RetentionProtection(ctx); err == nil {
			t.Fatal("RBAC refusal used as admission proof")
		}
		original := binding.DeepCopy()
		binding.Spec.ValidationActions = []admission.ValidationAction{admission.Warn}
		updated, err := core.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Update(ctx, binding, meta.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = guard.RetentionProtection(ctx); err == nil {
			t.Fatal("changed binding retained authority")
		}
		original.ResourceVersion = updated.ResourceVersion
		if _, err = core.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Update(ctx, original, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err = guard.RetentionProtection(ctx); err == nil {
			t.Fatal("restored value hid unqualified enforcement gap")
		}
	})
	t.Run("reader-role-current-snapshot-and-deletion", func(t *testing.T) {
		readerName := "retention-reader"
		_, err = core.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: readerName}, Rules: []rbac.PolicyRule{{APIGroups: []string{"asservat.io"}, Resources: []string{gr.Resource}, Verbs: []string{"get", "list", "watch"}}}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = core.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: readerName}, Subjects: []rbac.Subject{{Kind: "User", APIGroup: rbac.GroupName, Name: readerName}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: readerName}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = core.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: readerName}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = core.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: readerName}, Subjects: []rbac.Subject{{Kind: "User", APIGroup: rbac.GroupName, Name: readerName}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: readerName}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		cp := rest.CopyConfig(c)
		cp.Impersonate = rest.ImpersonationConfig{UserName: readerName}
		client, err := kube.NewPermissionClient(cp, cluster, plan.ControlNamespace, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := kube.NewRetentionClient(client, true)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := reader.RetentionSnapshot(ctx)
		if err != nil || len(snapshot.Policies) != 2 {
			t.Fatal("current policy snapshot", err)
		}
		d, err := dynamic.NewForConfig(cp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = d.Resource(gr).Namespace(ns.Name).Create(ctx, object("forbidden", false), dry); !apierrors.IsForbidden(err) {
			t.Fatal("reader acquired writer privileges", err)
		}

		t.Run("watch-retains-lower-then-raise", func(t *testing.T) {
			initial, err := reader.RetentionPolicyList(ctx)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := configuration.NewRetentionJournal(initial, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, err := journal.Checkpoint(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			// Test-only acknowledgement exercises ordering; no SQL source acceptance or
			// production policy authority is asserted by this Kubernetes watch fixture.
			if err = journal.Accepted(checkpoint); err != nil {
				t.Fatal(err)
			}
			watcher, err := reader.WatchRetentionPolicies(ctx, initial.ResourceVersion)
			if err != nil {
				t.Fatal(err)
			}
			defer watcher.Close()
			baseline, err := admin.Get(ctx, "baseline", meta.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, maximum := range []int64{600, 3600} {
				if err = unstructured.SetNestedField(baseline.Object, maximum, "spec", "maxima", "evidenceSeconds"); err != nil {
					t.Fatal(err)
				}
				baseline, err = admin.Update(ctx, baseline, meta.UpdateOptions{FieldValidation: "Strict"})
				if err != nil {
					t.Fatal(err)
				}
			}
			latest, err := reader.RetentionPolicyList(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if journal.Confirm(latest, time.Now()) == nil {
				t.Fatal("final list erased intermediate maximum")
			}
			observed := []int64{}
			for len(observed) < 2 {
				event, err := watcher.Next(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err = journal.Apply(event); err != nil {
					t.Fatal(err)
				}
				if event.Type == "BOOKMARK" {
					continue
				}
				checkpoint, err = journal.Checkpoint(time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if event.Policy != nil && event.Policy.Name == "baseline" {
					observed = append(observed, event.Policy.Policy.MaximumSeconds)
				}
				if err = journal.Accepted(checkpoint); err != nil {
					t.Fatal(err)
				}
			}
			if len(observed) != 2 || observed[0] != 600 || observed[1] != 3600 {
				t.Fatal("watch coalesced maxima", observed)
			}
			if err = journal.Confirm(latest, time.Now()); err != nil {
				t.Fatal("complete processed history did not refresh", err)
			}
		})
		t.Run("durable-guarded-reconciliation", func(t *testing.T) {
			testGuardedRetentionReconciliation(t, ctx, c, client, reader, plan, admin, f.Postgres, f.S3)
		})
		if err = admin.Delete(ctx, "baseline", meta.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		snapshot, err = reader.RetentionSnapshot(ctx)
		if err != nil || len(snapshot.Policies) != 1 || snapshot.Policies[0].Policy.Baseline {
			t.Fatal("deleted baseline retained", err)
		}
	})
}
