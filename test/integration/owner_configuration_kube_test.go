package integration

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func exerciseOwnerConfiguration(t *testing.T, ctx context.Context, f fixture, admin kubernetes.Interface, config *rest.Config, p value.OwnerPool, b value.OwnerBinding, endpoints app.OwnerEndpointReader, accepted func(app.OwnerConfigurationReader, *ownerConfigLab)) {
	t.Helper()
	// Fixture issuer bootstrap is explicit. Runtime enrollment below uses only
	// scoped HTTPS signing credentials and this protected public root.
	request(t, f.KMS, "synthetic-root", "sys/mounts/owner-native-pki", map[string]any{"type": "pki"}, 204)
	result := request(t, f.KMS, "synthetic-root", "owner-native-pki/root/generate/internal", map[string]any{"common_name": "synthetic-native-owner-root", "ttl": "1h", "key_type": "ec", "key_bits": 256}, 200)
	root, _ := pem.Decode([]byte(result["data"].(map[string]any)["certificate"].(string)))
	if root == nil {
		t.Fatal("native owner fixture root")
	}
	der := root.Bytes
	ref := func(name, uid string) contracts.WorkerObjectReference {
		return contracts.WorkerObjectReference{Name: name, UID: uid}
	}
	wire := contracts.OwnerConfiguration{Format: contracts.OwnerConfigurationFormat, InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, Revision: 1, Namespace: ref(p.Namespace, p.NamespaceUID), Service: ref(p.Service, p.ServiceUID), Deployment: ref(p.Deployment, p.DeploymentUID), ServiceAccount: ref(p.ServiceAccount, p.AccountUID), Port: p.Port, IssuerRoots: [][]byte{der}}
	raw, _ := json.Marshal(wire)
	object, err := admin.CoreV1().ConfigMaps(p.Namespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "owner-pool"}, Data: map[string]string{"owner-pool.json": string(raw)}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	who, err := admin.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil || who.Status.UserInfo.Username == "" {
		t.Fatal("fixture administrator identity", err)
	}
	plan := cfg.ConfigMapAdministration{Name: "asservat-owner-configuration", SourceName: object.Name, ControlNamespace: cfg.NamespaceRef{Name: p.Namespace, UID: p.NamespaceUID}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}
	policy, binding, err := kube.OwnerConfigurationAdmission(plan)
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
	makeClient := func(name string) (*kube.PermissionClient, kubernetes.Interface) {
		t.Helper()
		if _, err = admin.CoreV1().ServiceAccounts(p.Namespace).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}}, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		token, e := admin.CoreV1().ServiceAccounts(p.Namespace).CreateToken(ctx, name, &auth.TokenRequest{}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		limited := &rest.Config{Host: config.Host, BearerToken: token.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: config.CAData, CAFile: config.CAFile}}
		reader, e := kube.NewPermissionClient(limited, p.ClusterID, plan.ControlNamespace, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		api, e := kubernetes.NewForConfig(limited)
		if e != nil {
			t.Fatal(e)
		}
		return reader, api
	}
	reader, readonly := makeClient("owner-config-reader")
	probe, probeAPI := makeClient("owner-config-probe")
	_, err = admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: plan.Name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{p.Namespace}, Verbs: []string{"get"}}, {APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{plan.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: plan.Name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "owner-config-reader", Namespace: p.Namespace}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: plan.Name}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"owner-config-reader", "owner-config-probe"} {
		verbs := []string{"get"}
		if name == "owner-config-probe" {
			verbs = append(verbs, "update")
		}
		_, err = admin.RbacV1().Roles(p.Namespace).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{object.Name}, Verbs: verbs}}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = admin.RbacV1().RoleBindings(p.Namespace).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: name, Namespace: p.Namespace}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: name}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	pin := kube.GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion}
	guard, err := kube.NewOwnerConfigurationProtection(reader, probe, plan, pin)
	if err != nil {
		t.Fatal(err)
	}
	source, err := kube.NewOwnerConfigurationSource(reader, guard, object.Name, string(object.UID), p.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	var observed value.OwnerConfigurationObservation
	until := time.Now().Add(15 * time.Second)
	for time.Now().Before(until) {
		observed, err = source.ReadOwnerConfiguration(ctx)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || !observed.Valid(time.Now()) || observed.Configuration.Pool != p {
		t.Fatal("owner source admission qualification", err)
	}
	lab := ownerConfigurationLab(t, ctx, f, observed.Configuration)
	observer := &app.OwnerConfigurationObserver{Reader: source, Ledger: lab.writer, Audit: lab.audit, Acknowledgements: lab.ack, Now: time.Now}
	if _, _, err = lab.writer.ObserveOwnerConfiguration(ctx, observed); err != nil {
		t.Fatal(err)
	}
	if _, err = lab.reader.ReadOwnerConfiguration(ctx); err == nil {
		t.Fatal("unaudited owner configuration usable")
	}
	routes := app.OwnerRoutes{Configurations: refreshedOwnerConfiguration{observer, lab.reader}, Endpoints: endpoints, Now: time.Now}
	route, err := routes.CurrentOwnerRoute(ctx, b)
	if err != nil || !route.Valid(time.Now()) || !route.Configuration.Configuration.Equal(observed.Configuration) {
		t.Fatal("protected route composition", err)
	}
	unchanged, err := admin.CoreV1().ConfigMaps(p.Namespace).Get(ctx, object.Name, meta.GetOptions{})
	if err != nil || unchanged.ResourceVersion != object.ResourceVersion {
		t.Fatal("dry-run proof persisted state", err)
	}
	if _, err = readonly.CoreV1().ConfigMaps(p.Namespace).Update(ctx, object, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); !apierrors.IsForbidden(err) {
		t.Fatal("reader may update configuration")
	}
	if _, err = probeAPI.CoreV1().ConfigMaps(p.Namespace).Update(ctx, object, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); !apierrors.IsInvalid(err) && !apierrors.IsForbidden(err) {
		t.Fatal("non-administrator bypassed admission")
	}
	// The installation administrator can suspend discovery without waiting for
	// a client-held certificate to expire; no new route may ignore this value.
	wire.Suspended = true
	wire.Revision++
	raw, _ = json.Marshal(wire)
	object.Data["owner-pool.json"] = string(raw)
	object, err = admin.CoreV1().ConfigMaps(p.Namespace).Update(ctx, object, meta.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = routes.CurrentOwnerRoute(ctx, b); err == nil {
		t.Fatal("suspended configuration permitted route")
	}
	wire.Suspended = false
	wire.Revision++
	raw, _ = json.Marshal(wire)
	object.Data["owner-pool.json"] = string(raw)
	object, err = admin.CoreV1().ConfigMaps(p.Namespace).Update(ctx, object, meta.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = routes.CurrentOwnerRoute(ctx, b); err != nil {
		t.Fatal("administrator resume not observed", err)
	}
	if accepted != nil {
		accepted(routes.Configurations, lab)
		// The nested native enrollment case exercises administrator revisions.
		// Re-read its actual object before proving a no-write negative control.
		object, err = admin.CoreV1().ConfigMaps(p.Namespace).Get(ctx, object.Name, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, binding.Name, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = observer.Observe(ctx); err == nil {
		t.Fatal("missing admission protection accepted")
	}
	if _, err = lab.reader.ReadOwnerConfiguration(ctx); err == nil {
		t.Fatal("missing guard left accepted trust usable")
	}
	// Negative control: RBAC alone permits this probe. With admission removed,
	// a dry-run succeeds but still cannot modify the source.
	until = time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		_, err = probeAPI.CoreV1().ConfigMaps(p.Namespace).Update(ctx, object, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("probe did not independently have update RBAC", err)
	}
	unchanged, err = admin.CoreV1().ConfigMaps(p.Namespace).Get(ctx, object.Name, meta.GetOptions{})
	if err != nil || unchanged.ResourceVersion != object.ResourceVersion {
		t.Fatal("negative dry-run persisted source", err)
	}
	t.Log("protected owner configuration, audited SQL acceptance and routing passed: pinned admission, separate probe, no dry-run writes, suspension/resume, and missing-protection rejection")
}
