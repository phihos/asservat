package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

func TestInitialNamespaceProtectionWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run make context-integration")
	}
	var f fixture
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("fixture unavailable")
	}
	ctx, end := context.WithTimeout(context.Background(), 90*time.Second)
	defer end()
	kc, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(kc)
	if err != nil {
		t.Fatal(err)
	}
	who, err := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.InitialNamespaceAdministration{Name: "initial-stage-guard", Namespace: "initial-stage", ProbeSource: "preparation", Inputs: "inputs", Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}
	var policies []*admission.ValidatingAdmissionPolicy
	var bindings []*admission.ValidatingAdmissionPolicyBinding
	var ns *core.Namespace
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		for _, binding := range bindings {
			if err := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(cleanup, binding.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &binding.UID}}); err != nil && !apierrors.IsNotFound(err) {
				t.Error(err)
			}
		}
		for _, policy := range policies {
			if err := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(cleanup, policy.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &policy.UID}}); err != nil && !apierrors.IsNotFound(err) {
				t.Error(err)
			}
		}
		if ns == nil {
			return
		}
		if err := api.CoreV1().Namespaces().Delete(cleanup, ns.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &ns.UID}}); err != nil && !apierrors.IsNotFound(err) {
			t.Error(err)
			return
		}
		for cleanup.Err() == nil {
			if _, err := api.CoreV1().Namespaces().Get(cleanup, ns.Name, meta.GetOptions{}); apierrors.IsNotFound(err) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Error("preparation namespace did not delete normally")
	})
	install := func(policy *admission.ValidatingAdmissionPolicy, binding *admission.ValidatingAdmissionPolicyBinding) kube.GuardPin {
		t.Helper()
		policy, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		policies = append(policies, policy)
		binding, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		bindings = append(bindings, binding)
		return kube.GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion}
	}
	installation, request := custodyID(), custodyID()
	creator, err := kube.NewInitialNamespaceCreator(kc, p, installation, request)
	if err != nil {
		t.Fatal(err)
	}
	created, err := creator.CreateNew(ctx)
	// Retain acknowledged identities even if a later create fails. Cleanup
	// cannot adopt or delete an unknown same-named object.
	if created.Guard.PolicyUID != "" {
		policies = append(policies, &admission.ValidatingAdmissionPolicy{ObjectMeta: meta.ObjectMeta{Name: p.Name, UID: types.UID(created.Guard.PolicyUID)}})
	}
	if created.Guard.BindingUID != "" {
		bindings = append(bindings, &admission.ValidatingAdmissionPolicyBinding{ObjectMeta: meta.ObjectMeta{Name: p.Name, UID: types.UID(created.Guard.BindingUID)}})
	}
	if created.Namespace.UID != "" {
		ns = &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: created.Namespace.Name, UID: types.UID(created.Namespace.UID)}}
	}
	if err != nil {
		t.Fatal(err)
	}
	pin := created.Guard
	until := time.Now().Add(15 * time.Second)
	for {
		if err = creator.Resume(ctx, created); err == nil {
			break
		}
		if !time.Now().Before(until) {
			t.Fatal("created resource identities not resumable", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if repeated, err := creator.CreateNew(ctx); err == nil || repeated != (kube.InitialNamespaceResources{}) {
		t.Fatal("existing namespace was adopted", err)
	}
	wrong := created
	wrong.Namespace.UID = custodyID()
	if err := creator.Resume(ctx, wrong); err == nil {
		t.Fatal("replacement namespace accepted")
	}
	other, err := kube.NewInitialNamespaceCreator(kc, p, installation, custodyID())
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Resume(ctx, created); err == nil {
		t.Fatal("another preparation request adopted the namespace")
	}
	// The product derives the public workload plan digest; the fixture still
	// owns installation trust and does not launch this proposed workload.
	workloadPlan := kube.InitialInstallerWorkloadPlan{Namespace: ns.Name, Name: "installer", WriterAccount: "writer", ProbeAccount: "probe", Configuration: p.Inputs, Credentials: "providers", Image: f.WorkerImage, Witness: "witness", FleetSource: "fleet", WitnessGuard: "witness-guard", FleetGuard: "fleet-guard", WorkloadGuard: "workload-guard"}
	planDigest, err := kube.InitialPreparationWorkloadDigest(workloadPlan)
	if err != nil {
		t.Fatal(err)
	}
	journalRef, err := creator.CreateJournal(ctx, created, planDigest)
	if err != nil {
		t.Fatal("initial creation journal", err)
	}
	if _, err := creator.CreateJournal(ctx, created, planDigest); err == nil {
		t.Fatal("initial journal was recreated or adopted")
	}
	for _, name := range []string{p.Inputs} {
		if _, err = api.CoreV1().ConfigMaps(ns.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: name}, Immutable: ptr.To(true), Data: map[string]string{"public": "synthetic preparation marker"}}, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"probe"} {
		if _, err = api.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = api.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "probe"}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{p.ProbeSource, p.Inputs}, Verbs: []string{"get", "update"}},
		{APIGroups: []string{""}, Resources: []string{"pods", "secrets"}, Verbs: []string{"create"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{"writer"}, Verbs: []string{"create"}},
	}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "probe"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: ns.Name, Name: "probe"}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "probe"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := api.CoreV1().Secrets(ns.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "probe-lifetime"}, Immutable: ptr.To(true)}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	token, err := api.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, "probe", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: anchor.Name, UID: anchor.UID}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pc := rest.CopyConfig(kc)
	pc.BearerToken = token.Status.Token
	pc.BearerTokenFile = ""
	pc.CertData = nil
	pc.KeyData = nil
	pc.CertFile = ""
	pc.KeyFile = ""
	probeAPI, err := kubernetes.NewForConfig(pc)
	if err != nil {
		t.Fatal(err)
	}
	cluster := custodyID()
	namespace := cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}
	observer, err := kube.NewPermissionClient(kc, cluster, namespace, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := kube.NewPermissionClient(pc, cluster, namespace, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := kube.NewInitialNamespaceProtection(observer, probe, p, string(ns.UID), pin)
	if err != nil {
		t.Fatal(err)
	}
	until = time.Now().Add(15 * time.Second)
	for {
		if _, err = guard.Current(ctx); err == nil {
			break
		}
		if !time.Now().Before(until) {
			t.Fatal("initial namespace guard not current", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The future installer principal does not exist until independent staging
	// enforcement has been proved. Only the non-authorizing probe precedes it.
	journal, err := kube.NewInitialPreparationJournal(creator, guard, created, journalRef, planDigest)
	if err != nil {
		t.Fatal(err)
	}
	writer := &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "journal-check"}, AutomountServiceAccountToken: ptr.To(false)}
	publicSpec, _ := json.Marshal(writer)
	desired := sha256.Sum256(publicSpec)
	intent := contracts.InitialPreparationCreate{OperationID: custodyID(), Kind: "ServiceAccount", Name: writer.Name, SpecDigest: hex.EncodeToString(desired[:])}
	started := make(chan kube.InitialPreparationStart, 2)
	for range 2 {
		go func() {
			result, _ := journal.Begin(ctx, intent)
			started <- result
		}()
	}
	fresh := 0
	for range 2 {
		if (<-started).Fresh {
			fresh++
		}
	}
	if fresh != 1 {
		t.Fatal("concurrent journal creates did not retain exactly one attempt", fresh)
	}
	if state, err := journal.Read(ctx); err != nil || len(state.Creates) != 1 || state.Creates[0].Receipt != nil {
		t.Fatal("creation intent was not persisted before the effect", err)
	}
	writer, err = api.CoreV1().ServiceAccounts(ns.Name).Create(ctx, writer, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Observe(ctx, intent.OperationID, contracts.InitialPreparationReceipt{UID: string(writer.UID), ResourceVersion: writer.ResourceVersion}); err != nil {
		t.Fatal("record acknowledged creation", err)
	}
	// Reconstruct the product reader with the original persisted input/pins.
	resumed, err := kube.NewInitialPreparationJournal(creator, guard, created, journalRef, planDigest)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := resumed.Begin(ctx, intent); err != nil || v.Fresh || len(v.State.Creates) != 1 || v.State.Creates[0].Receipt == nil || v.State.Creates[0].Receipt.UID != string(writer.UID) {
		t.Fatal("resumption reissued creation or lost the original receipt", err)
	}
	wrongPlan, err := kube.NewInitialPreparationJournal(creator, guard, created, journalRef, artifact.Digest{2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongPlan.Read(ctx); err == nil {
		t.Fatal("journal changed preparation plan")
	}
	producer, err := kube.NewInitialPreparationResources(journal, workloadPlan)
	if err != nil {
		t.Fatal(err)
	}
	clusterRole := "asservat." + ns.Name + ".installer"
	for _, target := range [][2]string{{"ServiceAccount", "writer"}, {"Role", "installer-writer"}, {"Role", "installer-probe"}, {"RoleBinding", "installer-writer"}, {"RoleBinding", "installer-probe"}, {"ClusterRole", clusterRole}, {"ClusterRoleBinding", clusterRole}} {
		ref, err := producer.Ensure(ctx, target[0], target[1])
		if err != nil {
			t.Fatal("product setup creation", target, err)
		}
		if target[0] == "ClusterRole" || target[0] == "ClusterRoleBinding" {
			t.Cleanup(func() {
				cleanup, end := context.WithTimeout(context.Background(), 5*time.Second)
				defer end()
				uid := types.UID(ref.UID)
				options := meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid}}
				var err error
				if target[0] == "ClusterRole" {
					err = api.RbacV1().ClusterRoles().Delete(cleanup, ref.Name, options)
				} else {
					err = api.RbacV1().ClusterRoleBindings().Delete(cleanup, ref.Name, options)
				}
				if err != nil && !apierrors.IsNotFound(err) {
					t.Error(err)
				}
			})
		}
		if again, err := producer.Ensure(ctx, target[0], target[1]); err != nil || again != ref {
			t.Fatal("setup lookup changed identity", target, err)
		}
	}
	if _, err := producer.Ensure(ctx, "Pod", workloadPlan.Name); err == nil {
		t.Fatal("account/RBAC producer launched a workload")
	}
	if state, err := journal.Read(ctx); err != nil || len(state.Creates) != 8 || state.Creates[7].Receipt == nil {
		t.Fatal("setup effects did not retain all receipts", err)
	}
	denied := func(err error, name string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "ValidatingAdmissionPolicy '"+name+"'") {
			t.Fatal("wrong native denial", name, err)
		}
	}
	input, err := api.CoreV1().ConfigMaps(ns.Name).Get(ctx, p.Inputs, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = probeAPI.CoreV1().ConfigMaps(ns.Name).Update(ctx, input.DeepCopy(), meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); err != nil {
		t.Fatal("staging guard masks final input probe", err)
	}
	_, err = probeAPI.CoreV1().ConfigMaps(ns.Name).Update(ctx, input.DeepCopy(), meta.UpdateOptions{})
	denied(err, p.Name)
	_, err = probeAPI.CoreV1().Secrets(ns.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "intruder"}, Data: map[string][]byte{"synthetic": []byte("not evidence")}}, meta.CreateOptions{})
	denied(err, p.Name)
	_, err = probeAPI.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, "writer", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
	denied(err, p.Name)
	w, err := kube.BuildInitialInstallerWorkload(kube.InitialInstallerWorkloadPlan{Namespace: ns.Name, Name: "inert", WriterAccount: "probe", ProbeAccount: "other", Configuration: "inputs", Credentials: "unavailable", Image: f.WorkerImage, Witness: "witness", FleetSource: "fleet", WitnessGuard: "witness", FleetGuard: "fleet", WorkloadGuard: "workload"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = probeAPI.CoreV1().Pods(ns.Name).Create(ctx, w.Pod, meta.CreateOptions{DryRun: []string{meta.DryRunAll}})
	denied(err, p.Name)
	if _, err = probeAPI.CoreV1().Secrets(ns.Name).Get(ctx, anchor.Name, meta.GetOptions{}); !apierrors.IsForbidden(err) {
		t.Fatal("probe can read credentials", err)
	}
	// Add a separate real final-input policy while staging stays active. Its
	// denial must be visible independently; staging must not conceal absence.
	final := cfg.ConfigMapAdministration{Name: "initial-stage-final", SourceName: p.Inputs, ControlNamespace: namespace, Administrators: p.Administrators}
	policy, binding, err := kube.FleetConfigurationAdmission(final)
	if err != nil {
		t.Fatal(err)
	}
	install(policy, binding)
	until = time.Now().Add(15 * time.Second)
	for {
		_, err = probeAPI.CoreV1().ConfigMaps(ns.Name).Update(ctx, input.DeepCopy(), meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		if err != nil && strings.Contains(err.Error(), "ValidatingAdmissionPolicy '"+final.Name+"'") {
			break
		}
		if !time.Now().Before(until) {
			t.Fatal("final input guard not independently visible", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err = guard.Current(ctx); err != nil {
		t.Fatal("final policy broke separate staging proof", err)
	}
	if err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, p.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &bindings[0].UID}}); err != nil {
		t.Fatal(err)
	}
	if _, err = guard.Current(ctx); err == nil {
		t.Fatal("removed staging guard remained current")
	}
	if err = creator.Resume(ctx, created); err == nil {
		t.Fatal("resumption repaired or ignored the removed staging guard")
	}
	if _, err := journal.Read(ctx); err == nil {
		t.Fatal("journal ignored lost staging protection")
	}
	t.Log("product creator, durable journal and account/RBAC producer retain one concurrent create intent, exact receipts and lookup-only resumption; all seven predefined setup resources survive repeated Ensure; plan/guard replacement deny; no Pod, provider credentials or activation")
}
