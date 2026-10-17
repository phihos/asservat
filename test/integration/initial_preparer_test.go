package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// This fixture supplies only the explicitly trusted bootstrap boundary. The
// real producer creates the root/namespace/accounts/RBAC and resumes them. It
// does not qualify Helm packaging, provider credentials, activation or HA API
// propagation. The retained request below models a network-delayed original
// POST and is released only against this owned native API, after retirement.
type delayedPreparationCreate struct {
	mu    sync.Mutex
	next  http.RoundTripper
	path  string
	name  string
	held  *http.Request
	body  []byte
	posts int
}

func (d *delayedPreparationCreate) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodPost || r.URL.Path != d.path {
		return d.next.RoundTrip(r)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.posts++
	b, e := io.ReadAll(r.Body)
	if e != nil {
		return nil, e
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	var object struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if json.Unmarshal(b, &object) != nil {
		return nil, io.ErrUnexpectedEOF
	}
	name := d.name
	if name == "" {
		name = "installer-writer"
	}
	if object.Metadata.Name != name {
		return d.next.RoundTrip(r)
	}
	if d.held == nil {
		d.held = r.Clone(context.Background())
		d.body = append([]byte(nil), b...)
		return &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"ServiceUnavailable","code":503}`)), Request: r}, nil
	}
	if !bytes.Equal(b, d.body) {
		return nil, io.ErrUnexpectedEOF
	}
	return d.next.RoundTrip(r)
}
func (d *delayedPreparationCreate) release(ctx context.Context) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.held == nil {
		return 0, io.ErrUnexpectedEOF
	}
	r := d.held.Clone(ctx)
	r.Body = io.NopCloser(bytes.NewReader(d.body))
	reply, e := d.next.RoundTrip(r)
	if e != nil {
		return 0, e
	}
	defer reply.Body.Close()
	_, e = io.Copy(io.Discard, reply.Body)
	return reply.StatusCode, e
}

func TestInitialPreparationSupervisorWithRealKubernetes(t *testing.T) {
	initialPreparationSupervisorNative(t, false, false)
}
func TestInitialPreparationActivationWithRealKubernetes(t *testing.T) {
	t.Run("healthy", func(t *testing.T) { initialPreparationSupervisorNative(t, true, false) })
	t.Run("uncertain", func(t *testing.T) { initialPreparationSupervisorNative(t, true, true) })
}
func initialPreparationSupervisorNative(t *testing.T, continuation, uncertain bool, hooks ...func(context.Context, *rest.Config, kubernetes.Interface, *kube.PermissionClient, *kube.PermissionClient, contracts.InitialPreparer)) {
	initialPreparationSupervisorNativePlan(t, continuation, uncertain, nil, hooks...)
}
func initialPreparationSupervisorNativePlan(t *testing.T, continuation, uncertain bool, prepare func(context.Context, *rest.Config, kubernetes.Interface, *contracts.InitialPreparationPlan), hooks ...func(context.Context, *rest.Config, kubernetes.Interface, *kube.PermissionClient, *kube.PermissionClient, contracts.InitialPreparer)) {
	initialPreparationSupervisorNativePlanWithin(t, 120*time.Second, continuation, uncertain, prepare, hooks...)
}
func initialPreparationSupervisorNativePlanWithin(t *testing.T, budget time.Duration, continuation, uncertain bool, prepare func(context.Context, *rest.Config, kubernetes.Interface, *contracts.InitialPreparationPlan), hooks ...func(context.Context, *rest.Config, kubernetes.Interface, *kube.PermissionClient, *kube.PermissionClient, contracts.InitialPreparer)) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run owned context-integration fixture")
	}
	var f fixture
	b, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(b, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("fixture unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	kc, e := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if e != nil {
		t.Fatal(e)
	}
	api, e := kubernetes.NewForConfig(kc)
	if e != nil {
		t.Fatal(e)
	}
	who, e := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	bootstrap, e := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "initial-bootstrap-resume", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	plan := contracts.InitialPreparationPlan{InstallationID: custodyID(), RequestID: custodyID(), ClusterID: custodyID(), BootstrapNamespace: contracts.WorkerObjectReference{Name: bootstrap.Name, UID: string(bootstrap.UID)}, RootName: "preparation-root", ProbeName: "continuity-probe", ContinuityName: "initial-resume-continuity", Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: who.Status.UserInfo.Username}}, Workload: contracts.InitialPreparationWorkload{Namespace: "initial-resume-target", Name: "installer", WriterAccount: "writer", ProbeAccount: "probe", Configuration: "inputs", Credentials: "providers", Image: "example.invalid/asservat@sha256:" + strings.Repeat("a", 64), Witness: "witness", FleetSource: "fleet", WitnessGuard: "initial-resume-witness", FleetGuard: "initial-resume-fleet", WorkloadGuard: "initial-resume-workload", StagingGuard: "initial-resume-staging", Journal: "preparation"}}
	if continuation {
		plan.Continuation = contracts.InitialPreparationActivationProtocol
	}
	var finishPodQualification func()
	var policies []*admission.ValidatingAdmissionPolicy
	var bindings []*admission.ValidatingAdmissionPolicyBinding
	var target *core.Namespace
	clusterName := "asservat." + plan.Workload.Namespace + "." + plan.Workload.Name
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		// Fixture teardown is a trusted cluster-administrator action after all
		// retained requests have joined. This is not product retirement behavior.
		for _, v := range bindings {
			if e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(cleanup, v.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &v.UID}}); e != nil && !apierrors.IsNotFound(e) {
				t.Error(e)
			}
		}
		for _, v := range policies {
			if e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(cleanup, v.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &v.UID}}); e != nil && !apierrors.IsNotFound(e) {
				t.Error(e)
			}
		}
		// Policy deletion is acknowledged before every admission cache observes
		// it. Retry only the exact removed policy's explicit no-effect denial,
		// retaining each original object UID and the cleanup deadline. This
		// fixture-only teardown does not relax product continuity protection.
		remove := func(call func() error) error {
			for {
				err := call()
				if err == nil || apierrors.IsNotFound(err) {
					return nil
				}
				if !initialPreparerCleanupDenial(err, plan.ContinuityName) {
					return err
				}
				select {
				case <-cleanup.Done():
					return cleanup.Err()
				case <-time.After(50 * time.Millisecond):
				}
			}
		}
		if v, e := api.RbacV1().ClusterRoleBindings().Get(cleanup, clusterName, meta.GetOptions{}); e == nil && v.Annotations["asservat.io/installation-id"] == plan.InstallationID {
			if e = remove(func() error {
				return api.RbacV1().ClusterRoleBindings().Delete(cleanup, v.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &v.UID}})
			}); e != nil {
				t.Error(e)
			}
		}
		if v, e := api.RbacV1().ClusterRoles().Get(cleanup, clusterName, meta.GetOptions{}); e == nil && v.Annotations["asservat.io/installation-id"] == plan.InstallationID {
			if e = remove(func() error {
				return api.RbacV1().ClusterRoles().Delete(cleanup, v.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &v.UID}})
			}); e != nil {
				t.Error(e)
			}
		}
		if target == nil {
			if v, e := api.CoreV1().Namespaces().Get(cleanup, plan.Workload.Namespace, meta.GetOptions{}); e == nil && v.Annotations["asservat.io/installation-id"] == plan.InstallationID {
				target = v
			}
		}
		for _, ns := range []*core.Namespace{target, bootstrap} {
			if ns == nil {
				continue
			}
			if e := remove(func() error {
				return api.CoreV1().Namespaces().Delete(cleanup, ns.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &ns.UID}})
			}); e != nil {
				t.Error(e)
				continue
			}
			for cleanup.Err() == nil {
				if _, e := api.CoreV1().Namespaces().Get(cleanup, ns.Name, meta.GetOptions{}); apierrors.IsNotFound(e) {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if cleanup.Err() != nil {
				t.Error("owned preparation namespace did not delete normally")
			}
		}
	})
	if prepare != nil {
		prepare(ctx, kc, api, &plan)
	}
	// Bootstrap anchor, probe identity and narrow dry-run-update permission are
	// deliberately fixture-owned trusted inputs, never a claimed product token producer.
	if _, e = api.CoreV1().ConfigMaps(bootstrap.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: plan.ProbeName}, Data: map[string]string{"public": "continuity probe"}}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	bootstrapProbe, e := api.CoreV1().ServiceAccounts(bootstrap.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "probe"}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if plan.Handover == contracts.InitialPreparationHandoverProtocol {
		plan.HistoryProbe = &contracts.WorkerObjectReference{Name: bootstrapProbe.Name, UID: string(bootstrapProbe.UID)}
	}
	if _, e = api.RbacV1().Roles(bootstrap.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "probe"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{plan.ProbeName}, Verbs: []string{"get", "update"}}}}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = api.RbacV1().RoleBindings(bootstrap.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "probe"}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "probe"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "probe", Namespace: bootstrap.Name}}}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	anchor, e := api.CoreV1().Secrets(bootstrap.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "probe-lifetime"}, Immutable: ptr.To(true)}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	token, e := api.CoreV1().ServiceAccounts(bootstrap.Name).CreateToken(ctx, "probe", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: anchor.Name, UID: anchor.UID}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	pc := rest.CopyConfig(kc)
	pc.BearerToken = token.Status.Token
	pc.BearerTokenFile = ""
	pc.CertData = nil
	pc.KeyData = nil
	pc.CertFile = ""
	pc.KeyFile = ""
	install := func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding) contracts.OwnerDeploymentGuard {
		t.Helper()
		p, e = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, p, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		policies = append(policies, p)
		b, e = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, b, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		bindings = append(bindings, b)
		deadline := time.Now().Add(15 * time.Second)
		for {
			observed, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, p.Name, meta.GetOptions{})
			if e != nil {
				t.Fatal(e)
			}
			if observed.Status.ObservedGeneration == p.Generation && observed.Status.TypeChecking != nil {
				if len(observed.Status.TypeChecking.ExpressionWarnings) > 0 {
					t.Fatalf("native CEL warnings: %v", observed.Status.TypeChecking.ExpressionWarnings)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("native policy type checking unavailable")
			}
			time.Sleep(50 * time.Millisecond)
		}
		return contracts.OwnerDeploymentGuard{Name: p.Name, PolicyUID: string(p.UID), PolicyGeneration: p.Generation, BindingUID: string(b.UID), BindingResourceVersion: b.ResourceVersion, Administrators: plan.Administrators}
	}
	cp, cb, e := kube.InitialPreparationContinuityAdmission(plan)
	if e != nil {
		t.Fatal(e)
	}
	continuity := install(cp, cb)
	np := cfg.InitialNamespaceAdministration{Name: plan.Workload.StagingGuard, Namespace: plan.Workload.Namespace, ProbeSource: plan.Workload.Journal, Inputs: plan.Workload.Configuration}
	for _, actor := range plan.Administrators {
		np.Administrators = append(np.Administrators, cfg.KubernetesActor{Kind: actor.Kind, Name: actor.Name})
	}
	sp, sb, e := kube.InitialNamespaceAdmission(np)
	if e != nil {
		t.Fatal(e)
	}
	staging := install(sp, sb)
	delayed := &delayedPreparationCreate{path: "/apis/rbac.authorization.k8s.io/v1/namespaces/" + plan.Workload.Namespace + "/roles"}
	effect := rest.CopyConfig(kc)
	effect.Wrap(func(next http.RoundTripper) http.RoundTripper { delayed.next = next; return delayed })
	namespace := cfg.NamespaceRef{Name: bootstrap.Name, UID: string(bootstrap.UID)}
	observer, e := kube.NewPermissionClient(kc, plan.ClusterID, namespace, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	probe, e := kube.NewPermissionClient(pc, plan.ClusterID, namespace, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	c := contracts.InitialPreparer{Format: contracts.InitialPreparerFormat, Plan: plan, Continuity: continuity, Staging: staging}
	if plan.Handover == contracts.InitialPreparationHandoverProtocol {
		// Actual loader owns every target CREATE and completion. The legacy
		// delayed-CREATE/provisioned-Pod qualification below is a separate test.
		if uncertain || len(hooks) != 1 {
			t.Fatal("handover requires one actual loader hook")
		}
		hooks[0](ctx, kc, api, observer, probe, c)
		return
	}
	fresh := func() *kube.InitialPreparer {
		v, e := kube.NewInitialPreparer(effect, observer, probe, c)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	s := fresh()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, e = s.Open(ctx); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native continuity not current", e)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, e = s.Declare(ctx); e == nil {
		t.Fatal("delayed original role CREATE reported success")
	}
	state, e := fresh().Declare(ctx)
	if e != nil || state.Phase != "declared" || len(state.Creates) != 9 {
		t.Fatalf("resumed declaration: %s %d %v", state.Phase, len(state.Creates), e)
	}
	if continuation {
		finishPodQualification = qualifyInitialGatedPreparation(t, ctx, kc, api, observer, probe, c, install, uncertain)
	}
	for _, hook := range hooks {
		hook(ctx, kc, api, observer, probe, c)
	}
	for _, entry := range state.Creates {
		if entry.Kind == "ValidatingAdmissionPolicy" || entry.Kind == "ValidatingAdmissionPolicyBinding" || entry.Kind == "Secret" || entry.Kind == "Pod" {
			t.Fatalf("unsafe retry kind %s", entry.Kind)
		}
	}
	target, e = api.CoreV1().Namespaces().Get(ctx, plan.Workload.Namespace, meta.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	for _, check := range []struct {
		name string
		call func() error
	}{{"target namespace", func() error {
		return api.CoreV1().Namespaces().Delete(ctx, target.Name, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}})
	}}, {"bootstrap namespace", func() error {
		return api.CoreV1().Namespaces().Delete(ctx, bootstrap.Name, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}})
	}}, {"root", func() error {
		return api.CoreV1().ConfigMaps(bootstrap.Name).Delete(ctx, plan.RootName, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}})
	}}, {"account", func() error {
		return api.CoreV1().ServiceAccounts(target.Name).Delete(ctx, "writer", meta.DeleteOptions{DryRun: []string{meta.DryRunAll}})
	}}, {"cluster role", func() error {
		return api.RbacV1().ClusterRoles().Delete(ctx, clusterName, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}})
	}}} {
		t.Run("deny-delete-"+check.name, func(t *testing.T) {
			e := check.call()
			if e == nil || !strings.Contains(e.Error(), "initial-resume-continuity") {
				t.Fatalf("deletion was not denied by continuity policy: %v", e)
			}
		})
	}
	t.Run("deny-delete-collection", func(t *testing.T) {
		e := api.RbacV1().Roles(target.Name).DeleteCollection(ctx, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}}, meta.ListOptions{})
		if e == nil || !strings.Contains(e.Error(), "initial-resume-continuity") {
			t.Fatalf("collection deletion bypassed continuity: %v", e)
		}
	})
	role, e := api.RbacV1().ClusterRoles().Get(ctx, clusterName, meta.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"aggregation", "owner", "rules", "labels"} {
		t.Run("deny-retirement-widening-"+mode, func(t *testing.T) {
			v := role.DeepCopy()
			v.Rules = nil
			switch mode {
			case "aggregation":
				v.AggregationRule = &rbac.AggregationRule{ClusterRoleSelectors: []meta.LabelSelector{{}}}
			case "owner":
				v.OwnerReferences = []meta.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "other", UID: bootstrap.UID}}
			case "rules":
				v.Rules = []rbac.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}
			case "labels":
				v.Labels = map[string]string{"changed": "true"}
			}
			if _, e := api.RbacV1().ClusterRoles().Update(ctx, v, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); e == nil || !strings.Contains(e.Error(), "initial-resume-continuity") {
				t.Fatalf("widening not denied by continuity: %v", e)
			}
		})
	}
	retired, e := fresh().RetireSetupAuthority(ctx)
	if e != nil || retired.Phase != "retired" || !reflect.DeepEqual(state.Creates, retired.Creates) {
		t.Fatalf("retirement: %s %v", retired.Phase, e)
	}
	t.Run("retired-rules-cannot-refill", func(t *testing.T) {
		current, e := api.RbacV1().ClusterRoles().Get(ctx, clusterName, meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		current.Rules = role.DeepCopy().Rules
		if _, e = api.RbacV1().ClusterRoles().Update(ctx, current, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); e == nil || !strings.Contains(e.Error(), "initial-resume-continuity") {
			t.Fatalf("retired rules refilled: %v", e)
		}
	})
	t.Run("retired-rolebinding-cannot-refill", func(t *testing.T) {
		v, e := api.RbacV1().RoleBindings(target.Name).Get(ctx, "installer-writer", meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		v.Subjects = []rbac.Subject{{Kind: "ServiceAccount", Name: "writer", Namespace: target.Name}}
		if _, e = api.RbacV1().RoleBindings(target.Name).Update(ctx, v, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); e == nil || !strings.Contains(e.Error(), "initial-resume-continuity") {
			t.Fatalf("retired rolebinding refilled: %v", e)
		}
	})
	t.Run("retired-clusterrolebinding-cannot-refill", func(t *testing.T) {
		v, e := api.RbacV1().ClusterRoleBindings().Get(ctx, clusterName, meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		v.Subjects = []rbac.Subject{{Kind: "ServiceAccount", Name: "writer", Namespace: target.Name}}
		if _, e = api.RbacV1().ClusterRoleBindings().Update(ctx, v, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); e == nil || !strings.Contains(e.Error(), "initial-resume-continuity") {
			t.Fatalf("retired clusterrolebinding refilled: %v", e)
		}
	})
	t.Run("retired-role-cannot-refill", func(t *testing.T) {
		v, e := api.RbacV1().Roles(target.Name).Get(ctx, "installer-writer", meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		v.Rules = []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"inputs", "witness", "fleet"}, Verbs: []string{"get"}}}
		if _, e = api.RbacV1().Roles(target.Name).Update(ctx, v, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); e == nil || !strings.Contains(e.Error(), "initial-resume-continuity") {
			t.Fatalf("retired role refilled: %v", e)
		}
	})
	status, e := delayed.release(ctx)
	if e != nil || status != 409 {
		t.Fatalf("late original POST must remain AlreadyExists: %d %v", status, e)
	}
	current, e := api.RbacV1().Roles(target.Name).Get(ctx, "installer-writer", meta.GetOptions{})
	if e != nil || len(current.Rules) != 0 {
		t.Fatalf("late original revived rules: %v", e)
	}
	if _, e = fresh().Declare(ctx); e == nil {
		t.Fatal("retired root reopened")
	}
	if _, e = fresh().RetireSetupAuthority(ctx); e != nil {
		t.Fatal("retirement replay", e)
	}
	// A changed known UID is refused locally; no deletion/recreation is used to
	// make this scenario appear safe. Native deletion was explicitly denied above.
	wrong := c
	wrong.RootUID = custodyID()
	bad, e := kube.NewInitialPreparer(effect, observer, probe, wrong)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = bad.Open(ctx); e == nil {
		t.Fatal("foreign root UID accepted")
	}
	if finishPodQualification != nil {
		finishPodQualification()
	}
}

// Kubernetes VAP defaults to ReasonInvalid/422 while retaining the message
// created by NewForbidden. Only an exact structured cause from this fixture's
// removed policy permits retry; unrelated invalid/forbidden errors do not.
func initialPreparerCleanupDenial(err error, policy string) bool {
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		return false
	}
	s := status.Status()
	if !(s.Code == 422 && s.Reason == meta.StatusReasonInvalid || s.Code == 403 && s.Reason == meta.StatusReasonForbidden) || s.Details == nil {
		return false
	}
	want := "ValidatingAdmissionPolicy '" + policy + "' with binding '" + policy + "' denied request: Asservat preparation identities must remain occupied and may only lose setup authority."
	for _, cause := range s.Details.Causes {
		if cause.Message == want {
			return true
		}
	}
	return false
}
