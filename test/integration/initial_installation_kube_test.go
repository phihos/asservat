package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	cfg "asservat.local/asservat/internal/domain/configuration"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func nativeInitialInstallationInputs(t *testing.T, ctx context.Context, f fixture) (installationWitnessLab, *kube.ProtectedFleetSettings, func()) {
	t.Helper()
	if len(f.Clusters) == 0 {
		t.Fatal("missing owned native fixture")
	}
	config, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	w := newInstallationWitnessLab(t, ctx, config, admin, "initial-activation")
	who, err := admin.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../examples/fleet-settings.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		t.Fatal("invalid fixture")
	}
	doc["installationID"], doc["issuerEpoch"] = w.scope.InstallationID, w.scope.IssuerEpoch
	b, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	cm, err := admin.CoreV1().ConfigMaps(w.scope.Namespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "fleet"}, Data: map[string]string{"fleet.json": string(b)}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan := cfg.ConfigMapAdministration{Name: "initial-activation-fleet", SourceName: cm.Name, ControlNamespace: cfg.NamespaceRef{Name: w.scope.Namespace, UID: w.scope.NamespaceUID}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}
	policy, binding, err := kube.FleetConfigurationAdmission(plan)
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
	// Existing witness clients gain only the second exact source/guard read or
	// probe operation; neither bootstrap nor a developer gets fleet writes.
	role, err := admin.RbacV1().ClusterRoles().Get(ctx, w.scope.Namespace, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	role.Rules = append(role.Rules, rbac.PolicyRule{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{plan.Name}, Verbs: []string{"get"}})
	if _, err = admin.RbacV1().ClusterRoles().Update(ctx, role, meta.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{"reader", "probe"} {
		r, err := admin.RbacV1().Roles(w.scope.Namespace).Get(ctx, account, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		r.Rules[0].ResourceNames = append(r.Rules[0].ResourceNames, cm.Name)
		if _, err = admin.RbacV1().Roles(w.scope.Namespace).Update(ctx, r, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	guard, err := kube.NewFleetConfigurationProtection(w.clients["reader"], w.clients["probe"], plan, kube.GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion})
	if err != nil {
		t.Fatal(err)
	}
	source, err := kube.NewProtectedFleetSettings(w.clients["reader"], guard, cm.Name, string(cm.UID), w.scope.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(15 * time.Second)
	for {
		if _, err = source.FleetAdministration(ctx); err == nil {
			break
		}
		if !time.Now().Before(until) {
			t.Fatal("source protection not ready", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return w, source, func() {
		t.Helper()
		if err := admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, binding.Name, meta.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}
