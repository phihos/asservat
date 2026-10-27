package integration

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	value "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func TestPermissionAdmissionWithRealKubernetes(t *testing.T) {
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
	payments, err := client.CoreV1().Namespaces().Get(ctx, "payments", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// All test actors have ordinary resource CRUD, deliberately including status.
	// CEL must enforce content delegation; native RBAC alone cannot do this.
	_, err = client.RbacV1().Roles(control.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "admission-fixture"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"asservat.io"}, Resources: []string{"accessbindings", "permissionsources", "accessbindings/status", "permissionsources/status"}, Verbs: []string{"create", "update", "patch", "delete", "get", "list"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RbacV1().RoleBindings(control.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "admission-fixture"}, Subjects: []rbac.Subject{{Kind: "Group", APIGroup: rbac.GroupName, Name: "asservat-fixture-writers"}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "admission-fixture"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	actor := func(name string) dynamic.Interface {
		t.Helper()
		copy := rest.CopyConfig(c)
		copy.Impersonate = rest.ImpersonationConfig{UserName: name, Groups: []string{"asservat-fixture-writers"}}
		d, err := dynamic.NewForConfig(copy)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	admin, delegate, outsider, status := actor("fixture-admin"), actor("fixture-delegate"), actor("fixture-outsider"), actor("fixture-status")
	cluster := "11111111-1111-4111-8111-111111111111"
	plan := value.PermissionAdministration{Name: "asservat-permissions", ControlNamespace: value.NamespaceRef{Name: control.Name, UID: string(control.UID)}, Administrators: []value.KubernetesActor{{Kind: "User", Name: "fixture-admin"}}, StatusUsers: []string{"fixture-status"}, Delegations: []value.PermissionDelegation{{Writers: []value.KubernetesActor{{Kind: "User", Name: "fixture-delegate"}}, Scope: value.Scope{ClusterID: cluster, Namespace: value.NamespaceRef{Name: payments.Name, UID: string(payments.UID)}}, Roles: []string{"workload-maintainer", "evidence-reader"}, Issuers: []string{"https://id.example.invalid"}}}}
	policy, binding, err := kube.PermissionAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	gr := schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "accessbindings"}
	sr := schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "permissionsources"}
	makeBinding := func(name string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": name, "namespace": control.Name}, "spec": map[string]any{"effect": "Allow", "subjects": []any{map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": "payments-team"}}, "roles": []any{"workload-maintainer"}, "scope": map[string]any{"clusterID": cluster, "namespaceRef": map[string]any{"name": payments.Name, "uid": string(payments.UID)}}, "reason": "synthetic test"}}}
	}
	dry := meta.CreateOptions{DryRun: []string{meta.DryRunAll}, FieldValidation: "Strict"}
	denied := func(err error) bool {
		return apierrors.IsInvalid(err) && strings.Contains(err.Error(), "Asservat permission administrator") || apierrors.IsForbidden(err) && strings.Contains(err.Error(), "Asservat permission administrator")
	}
	for i := 0; i < 100; i++ {
		_, err = outsider.Resource(gr).Namespace(control.Name).Create(ctx, makeBinding("readiness-probe"), dry)
		if denied(err) {
			break
		}
		if i == 99 {
			t.Fatalf("guard did not enforce: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	current, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, policy.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if current.Status.TypeChecking != nil && len(current.Status.TypeChecking.ExpressionWarnings) > 0 {
		t.Fatalf("CEL type warnings: %+v", current.Status.TypeChecking.ExpressionWarnings)
	}
	t.Run("delegation-and-structural-schema", func(t *testing.T) {
		if _, err := delegate.Resource(gr).Namespace(control.Name).Create(ctx, makeBinding("delegated"), meta.CreateOptions{FieldValidation: "Strict"}); err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			name string
			edit func(*unstructured.Unstructured)
		}{
			{"wrong-namespace", func(o *unstructured.Unstructured) {
				_ = unstructured.SetNestedField(o.Object, "other-uid", "spec", "scope", "namespaceRef", "uid")
			}},
			{"wrong-role", func(o *unstructured.Unstructured) {
				_ = unstructured.SetNestedSlice(o.Object, []any{"evidence-owner"}, "spec", "roles")
			}},
			{"wrong-issuer", func(o *unstructured.Unstructured) {
				_ = unstructured.SetNestedSlice(o.Object, []any{map[string]any{"kind": "Group", "issuer": "https://other.example.invalid", "id": "payments-team"}}, "spec", "subjects")
			}},
			{"unknown-field", func(o *unstructured.Unstructured) {
				_ = unstructured.SetNestedField(o.Object, true, "spec", "permissionAdministrator")
			}},
			{"duplicate-role", func(o *unstructured.Unstructured) {
				_ = unstructured.SetNestedSlice(o.Object, []any{"workload-maintainer", "workload-maintainer"}, "spec", "roles")
			}},
		}
		for _, test := range cases {
			o := makeBinding(test.name)
			test.edit(o)
			if _, err := delegate.Resource(gr).Namespace(control.Name).Create(ctx, o, dry); err == nil {
				t.Fatalf("accepted %s", test.name)
			}
		}
	})
	t.Run("automation-is-administrator-only", func(t *testing.T) {
		o := makeBinding("team-automation")
		envelope := map[string]any{"allowedActions": []any{"packetCapture"}, "maxLifetimeSeconds": int64(86400), "maxExecutions": int64(10), "maxBytes": int64(1048576), "maxObservedBytes": int64(2097152)}
		_ = unstructured.SetNestedMap(o.Object, envelope, "spec", "automation")
		if _, err := delegate.Resource(gr).Namespace(control.Name).Create(ctx, o, dry); !denied(err) {
			t.Fatalf("ordinary delegate created automation: %v", err)
		}
		created, err := admin.Resource(gr).Namespace(control.Name).Create(ctx, o, meta.CreateOptions{FieldValidation: "Strict"})
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"effect", "subjects", "roles"} {
			bad := o.DeepCopy()
			bad.SetName("invalid-automation")
			switch field {
			case "effect":
				_ = unstructured.SetNestedField(bad.Object, "Deny", "spec", "effect")
			case "subjects":
				_ = unstructured.SetNestedSlice(bad.Object, []any{map[string]any{"kind": "User", "issuer": "https://id.example.invalid", "id": "person"}}, "spec", "subjects")
			case "roles":
				_ = unstructured.SetNestedSlice(bad.Object, []any{"evidence-reader"}, "spec", "roles")
			}
			if _, err := admin.Resource(gr).Namespace(control.Name).Create(ctx, bad, dry); err == nil {
				t.Fatalf("structural automation rule accepted invalid %s", field)
			}
		}
		unstructured.RemoveNestedField(created.Object, "spec", "automation")
		if _, err := delegate.Resource(gr).Namespace(control.Name).Update(ctx, created, meta.UpdateOptions{}); !denied(err) {
			t.Fatalf("delegate stripped administrator automation: %v", err)
		}
		if err := delegate.Resource(gr).Namespace(control.Name).Delete(ctx, o.GetName(), meta.DeleteOptions{}); !denied(err) {
			t.Fatalf("delegate deleted administrator automation: %v", err)
		}
		if err := admin.Resource(gr).Namespace(control.Name).Delete(ctx, o.GetName(), meta.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("updates-patches-apply-delete-and-status", func(t *testing.T) {
		o, err := delegate.Resource(gr).Namespace(control.Name).Get(ctx, "delegated", meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_ = unstructured.SetNestedField(o.Object, "changed", "spec", "reason")
		if _, err = outsider.Resource(gr).Namespace(control.Name).Update(ctx, o, meta.UpdateOptions{}); !denied(err) {
			t.Fatalf("outsider update %v", err)
		}
		patch := []byte(`{"spec":{"roles":["evidence-owner"]}}`)
		if _, err = delegate.Resource(gr).Namespace(control.Name).Patch(ctx, o.GetName(), types.MergePatchType, patch, meta.PatchOptions{}); !denied(err) {
			t.Fatalf("escalating patch %v", err)
		}
		if err = outsider.Resource(gr).Namespace(control.Name).Delete(ctx, o.GetName(), meta.DeleteOptions{}); !denied(err) {
			t.Fatalf("outsider delete %v", err)
		}
		applied := makeBinding("delegated")
		_ = unstructured.SetNestedSlice(applied.Object, []any{"evidence-owner"}, "spec", "roles")
		body, _ := json.Marshal(applied.Object)
		force := true
		validApply := makeBinding("valid-apply")
		validBody, _ := json.Marshal(validApply.Object)
		if _, err = delegate.Resource(gr).Namespace(control.Name).Patch(ctx, "valid-apply", types.ApplyPatchType, validBody, meta.PatchOptions{FieldManager: "synthetic-gitops", Force: &force}); err != nil {
			t.Fatalf("valid GitOps apply %v", err)
		}
		if _, err = delegate.Resource(gr).Namespace(control.Name).Patch(ctx, o.GetName(), types.ApplyPatchType, body, meta.PatchOptions{FieldManager: "synthetic-gitops", Force: &force}); !denied(err) {
			t.Fatalf("forced apply bypass %v", err)
		}
		_ = unstructured.SetNestedMap(o.Object, map[string]any{"phase": "Ready", "observedGeneration": o.GetGeneration()}, "status")
		if _, err = delegate.Resource(gr).Namespace(control.Name).UpdateStatus(ctx, o, meta.UpdateOptions{}); !denied(err) {
			t.Fatalf("forged status %v", err)
		}
		if _, err = status.Resource(gr).Namespace(control.Name).UpdateStatus(ctx, o, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		foreign := makeBinding("foreign")
		_ = unstructured.SetNestedField(foreign.Object, "foreign-uid", "spec", "scope", "namespaceRef", "uid")
		foreign, err = admin.Resource(gr).Namespace(control.Name).Create(ctx, foreign, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_ = unstructured.SetNestedField(foreign.Object, string(payments.UID), "spec", "scope", "namespaceRef", "uid")
		if _, err = delegate.Resource(gr).Namespace(control.Name).Update(ctx, foreign, meta.UpdateOptions{}); !denied(err) {
			t.Fatalf("old scope takeover %v", err)
		}
		if err = delegate.Resource(gr).Namespace(control.Name).Delete(ctx, "foreign", meta.DeleteOptions{}); !denied(err) {
			t.Fatalf("foreign delete %v", err)
		}
	})
	t.Run("source-conditional-validation-and-admin-only", func(t *testing.T) {
		source := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "PermissionSource", "metadata": map[string]any{"name": "native-source", "namespace": control.Name}, "spec": map[string]any{"enabled": true, "clusterID": cluster, "type": "namespaceMetadata", "namespaceSelector": map[string]any{"matchLabels": map[string]any{}}, "excludedNamespaces": []any{}, "role": "workload-maintainer", "maxDecisionAgeSeconds": int64(30), "maxNamespaces": int64(100), "protection": map[string]any{"mode": "administratorManaged", "reviewRef": "synthetic-review"}, "metadataMapping": map[string]any{"field": "annotation", "key": "example.invalid/owner", "mode": "valueMap", "issuer": "https://id.example.invalid", "values": map[string]any{"payments": []any{"payments-team"}}}}}}
		if _, err := delegate.Resource(sr).Namespace(control.Name).Create(ctx, source, dry); !denied(err) {
			t.Fatalf("source trust change %v", err)
		}
		if _, err := admin.Resource(sr).Namespace(control.Name).Create(ctx, source, dry); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"protection", "metadataMapping"} {
			bad := source.DeepCopy()
			unstructured.RemoveNestedField(bad.Object, "spec", field)
			if _, err := admin.Resource(sr).Namespace(control.Name).Create(ctx, bad, dry); err == nil {
				t.Fatalf("missing %s accepted", field)
			}
		}
		bad := source.DeepCopy()
		_ = unstructured.SetNestedField(bad.Object, "admissionEnforced", "spec", "protection", "mode")
		if _, err := admin.Resource(sr).Namespace(control.Name).Create(ctx, bad, dry); err == nil {
			t.Fatal("missing guard accepted")
		}
		bad = source.DeepCopy()
		_ = unstructured.SetNestedField(bad.Object, "groupID", "spec", "metadataMapping", "mode")
		if _, err := admin.Resource(sr).Namespace(control.Name).Create(ctx, bad, dry); err == nil {
			t.Fatal("groupID plus values accepted")
		}
	})
	t.Run("live-guard-proof-and-binding-revocation", func(t *testing.T) {
		latest, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, policy.Name, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		bound, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, binding.Name, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		observer, err := kube.NewPermissionClient(c, cluster, plan.ControlNamespace, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		probeConfig := rest.CopyConfig(c)
		probeConfig.Impersonate = rest.ImpersonationConfig{UserName: "fixture-outsider", Groups: []string{"asservat-fixture-writers", "system:authenticated"}}
		probe, err := kube.NewPermissionClient(probeConfig, cluster, plan.ControlNamespace, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		pin := kube.GuardPin{PolicyUID: string(latest.UID), PolicyGeneration: latest.Generation, BindingUID: string(bound.UID), BindingResourceVersion: bound.ResourceVersion}
		guard, err := kube.NewPermissionGuard(observer, probe, plan, pin)
		if err != nil {
			t.Fatal(err)
		}
		trust, err := guard.PermissionTrust(ctx)
		if err != nil {
			t.Fatalf("live denial qualification: %v", err)
		}
		if trust.FreshUntil.Sub(trust.ObservedAt) != 5*time.Second {
			t.Fatal("incorrect qualification deadline")
		}
		t.Run("guarded-reconciliation-with-SQL-and-encrypted-audit", func(t *testing.T) {
			testGuardedReconciliation(t, ctx, c, observer, guard, plan, fixture.Postgres, fixture.S3, fixture.Token)
			testIdentitySettings(t, ctx, c, cluster, plan.ControlNamespace, fixture.Token)
			testBrowserSettingsSource(t, ctx, c, cluster, plan.ControlNamespace, fixture.Token, fixture.Postgres)
		})
		t.Run("namespace-inheritance-with-real-namespaces-SQL-and-audit", func(t *testing.T) {
			testInheritedReconciliation(t, c, observer, guard, plan, fixture.Postgres, fixture.S3)
		})
		t.Run("decision-time-reviews-with-real-subject-access-reviews-SQL-and-audit", func(t *testing.T) {
			testDecisionTimeReviews(t, c, fixture.Postgres, fixture.S3)
		})
		// A probe that would pass administration is never a valid negative control.
		badConfig := rest.CopyConfig(c)
		badConfig.Impersonate = rest.ImpersonationConfig{UserName: "fixture-admin", Groups: []string{"asservat-fixture-writers", "system:authenticated"}}
		privileged, err := kube.NewPermissionClient(badConfig, cluster, plan.ControlNamespace, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		wrong, err := kube.NewPermissionGuard(observer, privileged, plan, pin)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = wrong.PermissionTrust(ctx); err == nil {
			t.Fatal("administrator accepted as negative probe")
		}
		// Compilation of a zero-delegation configuration must also work.
		adminOnly := plan
		adminOnly.Name = "asservat-admin-only"
		adminOnly.Delegations = nil
		only, _, err := kube.PermissionAdmission(adminOnly)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, only, meta.CreateOptions{DryRun: []string{meta.DryRunAll}}); err != nil {
			t.Fatal(err)
		}
		bound.Spec.ValidationActions = []admission.ValidationAction{admission.Warn}
		if _, err = client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Update(ctx, bound, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err = guard.PermissionTrust(ctx); err == nil {
			t.Fatal("non-enforcing binding stayed qualified")
		}
	})

}
