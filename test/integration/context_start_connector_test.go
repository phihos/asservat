package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	execution "asservat.local/asservat/internal/domain/execution"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
)

// Real controller-created Pod, original Pod-bound token, native policy denial,
// exact mounted-input metadata and status-subresource CAS. The process runs in
// the test host; accepted connector source/CA/registry are explicitly synthetic.
// This is not a deployed regional command or real connector SQL enrollment.
func TestConnectorAPIProcessWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("owned context fixture required")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("fixture unavailable")
	}
	var f fixture
	if json.Unmarshal(raw, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("fixture invalid")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	stats := &contextStartAPIStats{counts: map[string]int{}, elapsed: map[string]time.Duration{}}
	defer func() {
		stats.mu.Lock()
		defer stats.mu.Unlock()
		t.Logf("bounded actual API classes: counts=%v total_roundtrip=%v", stats.counts, stats.elapsed)
	}()
	config, e := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if e != nil {
		t.Fatal(e)
	}
	admin, e := kubernetes.NewForConfig(config)
	if e != nil {
		t.Fatal(e)
	}
	who, e := admin.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	name := "regional-api-" + strings.ReplaceAll(custodyID(), "-", "")[:10]
	ns, e := admin.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		if e := admin.CoreV1().Namespaces().Delete(c, name, meta.DeleteOptions{}); e != nil && !apierrors.IsNotFound(e) {
			t.Error("fixture namespace cleanup", e)
		}
	})
	control := cfg.NamespaceRef{Name: name, UID: string(ns.UID)}
	cluster, installation, epoch, root := custodyID(), custodyID(), custodyID(), custodyID()
	accounts := map[string]*core.ServiceAccount{}
	for _, n := range []string{"connector", "capacity", "probe", "settings-probe"} {
		v, e := admin.CoreV1().ServiceAccounts(name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: n}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		accounts[n] = v
	}
	// This whole object is fixture-installer-owned and dedicated only to the API
	// role. A selected-file mount does not limit its separately approved GET.
	secret, e := admin.CoreV1().Secrets(name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "api-input"}, Immutable: ptr.To(true), Data: map[string][]byte{"sql.json": []byte("synthetic-role-only"), "other-approved-key": []byte("synthetic-same-role")}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = admin.CoreV1().Secrets(name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "foreign-role"}, Data: map[string][]byte{"credential": []byte("synthetic-foreign-role")}}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	imageParts := strings.Split(f.WorkerImage, "@sha256:")
	if len(imageParts) != 2 {
		t.Fatal("owned image lacks digest")
	}
	im, e := hex.DecodeString(imageParts[1])
	if e != nil || len(im) != 32 {
		t.Fatal("image digest")
	}
	var image artifact.Digest
	copy(image[:], im)
	labels := map[string]string{"app": name}
	podSpec := core.PodSpec{ServiceAccountName: "connector", AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), RestartPolicy: core.RestartPolicyAlways, TerminationGracePeriodSeconds: ptr.To(int64(3)), SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Containers: []core.Container{{Name: "connector", Image: f.WorkerImage, ImagePullPolicy: core.PullNever, Command: []string{"/provider-proxy", "http://127.0.0.1:1", "http://127.0.0.1:1", "127.0.0.1:1"}, SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}, Resources: core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("5m"), core.ResourceMemory: resource.MustParse("16Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("64Mi")}}, VolumeMounts: []core.VolumeMount{{Name: "api-input", MountPath: "/run/api-input", ReadOnly: true}, {Name: "public", MountPath: "/run/api-public", ReadOnly: true}, {Name: "token", MountPath: "/run/api-token", ReadOnly: true}}}}, Volumes: []core.Volume{{Name: "api-input", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: secret.Name, Items: []core.KeyToPath{{Key: "sql.json", Path: "sql.json"}}}}}, {Name: "public", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{LocalObjectReference: core.LocalObjectReference{Name: "api-settings"}}}}, {Name: "token", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{Sources: []core.VolumeProjection{{ServiceAccountToken: &core.ServiceAccountTokenProjection{Audience: kube.ConnectorEnrollmentAudience(installation), ExpirationSeconds: ptr.To(int64(600)), Path: "token"}}}}}}}, Tolerations: []core.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}, {Key: "node.kubernetes.io/unreachable", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}}}
	dep, e := admin.AppsV1().Deployments(name).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "connector"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(0)), Selector: &meta.LabelSelector{MatchLabels: labels}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: podSpec}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	template, e := kube.ConnectorAPITemplateDigest(dep.Spec.Template)
	if e != nil {
		t.Fatal("server-defaulted template not qualified", e)
	}
	// The API server's own default audience, as the installer would pin it.
	audienceProbe, e := admin.CoreV1().ServiceAccounts(name).CreateToken(ctx, "connector", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
	if e != nil || len(audienceProbe.Spec.Audiences) < 1 {
		t.Fatal("default API audience", e)
	}
	apiAudience := audienceProbe.Spec.Audiences[0]
	actor := []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}
	plan := cfg.OwnerWorkloadAdministration{Name: name + "-owner", Deployment: dep.Name, DeploymentUID: string(dep.UID), ControlNamespace: control, Administrators: actor, ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: "api-settings", ServiceAccount: "settings-probe"}}, APIContextStarts: &cfg.OwnerAPIContextStarts{CapacityAccount: "capacity", CapacityAccountUID: string(accounts["capacity"].UID), ExecutionAccount: "connector", ExecutionAccountUID: string(accounts["connector"].UID), CapacityAudience: apiAudience}}
	sourcePlan := cfg.ConfigMapAdministration{Name: name + "-settings", ControlNamespace: control, SourceName: "api-settings", Administrators: actor}
	startPlan := cfg.LocalStartAdministration{Name: name + "-start", ControlNamespace: control, CapacityUser: "system:serviceaccount:" + name + ":capacity", ExecutionUser: "system:serviceaccount:" + name + ":connector"}
	install := func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding, e error) kube.GuardPin {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
		p, e = admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, p, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		b, e = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, b, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		pn, bn := p.Name, b.Name
		t.Cleanup(func() {
			c, end := context.WithTimeout(context.Background(), 10*time.Second)
			defer end()
			if e := admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(c, bn, meta.DeleteOptions{}); e != nil && !apierrors.IsNotFound(e) {
				t.Error(e)
			}
			if e := admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(c, pn, meta.DeleteOptions{}); e != nil && !apierrors.IsNotFound(e) {
				t.Error(e)
			}
		})
		return kube.GuardPin{PolicyUID: string(p.UID), PolicyGeneration: p.Generation, BindingUID: string(b.UID), BindingResourceVersion: b.ResourceVersion}
	}
	startPin := install(kube.StartAdmission(startPlan))
	sourcePin := install(kube.ConnectorAPISettingsAdmission(sourcePlan))
	ownerPin := install(kube.OwnerWorkloadAdmission(plan))
	subject := func(n string) rbac.Subject { return rbac.Subject{Kind: "ServiceAccount", Name: n, Namespace: name} }
	role := func(n string, rules []rbac.PolicyRule, subjects ...rbac.Subject) {
		t.Helper()
		if _, e := admin.RbacV1().Roles(name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: n}, Rules: rules}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e := admin.RbacV1().RoleBindings(name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: n}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: n}}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
	}
	role("runtime-reads", []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}, {APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{"connector", "capacity"}, Verbs: []string{"get"}}, {APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"connector"}, Verbs: []string{"get"}}, {APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: []string{"get"}}, {APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"api-settings"}, Verbs: []string{"get"}}, {APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{secret.Name}, Verbs: []string{"get"}}}, subject("connector"))
	role("namespace-probe", []rbac.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{dep.Name}, Verbs: []string{"update"}}}, subject("probe"))
	role("settings-probe", []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"api-settings"}, Verbs: []string{"update"}}}, subject("settings-probe"))
	role("capacity", []rbac.PolicyRule{{APIGroups: []string{"asservat.io"}, Resources: []string{"capacityreservations"}, Verbs: []string{"create", "get"}}, {APIGroups: []string{"asservat.io"}, Resources: []string{"capacityreservations/status"}, Verbs: []string{"update"}}}, subject("capacity"))
	role("capacity-token", []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{"capacity"}, Verbs: []string{"create"}}}, subject("connector"))
	role("execution", []rbac.PolicyRule{{APIGroups: []string{"asservat.io"}, Resources: []string{"capacityreservations"}, Verbs: []string{"get"}}, {APIGroups: []string{"asservat.io"}, Resources: []string{"capacityreservations/status"}, Verbs: []string{"update"}}}, subject("connector"))
	rules := []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{name}, Verbs: []string{"get"}}, {APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{plan.Name, sourcePlan.Name, startPlan.Name}, Verbs: []string{"get"}}, {APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews", "selfsubjectreviews"}, Verbs: []string{"create"}}}
	if _, e = admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: rules}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, Subjects: []rbac.Subject{subject("connector"), subject("capacity"), subject("probe"), subject("settings-probe")}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: name}}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		if e := admin.RbacV1().ClusterRoleBindings().Delete(c, name, meta.DeleteOptions{}); e != nil {
			t.Error(e)
		}
		if e := admin.RbacV1().ClusterRoles().Delete(c, name, meta.DeleteOptions{}); e != nil {
			t.Error(e)
		}
	})
	// The profile is fixed before this guarded Deployment ever creates a Pod.
	// Observation clients use a temporary synthetic observer token only while
	// the installer computes the public guard digest; runtime gets its Pod token.
	tokenConfig := func(n string, pod *core.Pod, audience string) *rest.Config {
		t.Helper()
		spec := auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}
		if audience != "" {
			spec.Audiences = []string{audience}
		}
		if pod != nil {
			spec.BoundObjectRef = &auth.BoundObjectReference{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID}
		}
		v, e := admin.CoreV1().ServiceAccounts(name).CreateToken(ctx, n, &auth.TokenRequest{Spec: spec}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture token", e)
		}
		c := rest.AnonymousClientConfig(config)
		c.BearerToken = v.Status.Token
		c.WrapTransport = stats.wrap
		return c
	}
	client := func(c *rest.Config) *kube.PermissionClient {
		t.Helper()
		v, e := kube.NewPermissionClient(c, cluster, control, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	probe, settingsProbe := client(tokenConfig("probe", nil, "")), client(tokenConfig("settings-probe", nil, ""))
	installerObserver := client(tokenConfig("connector", nil, ""))
	guard, e := kube.NewOwnerWorkloadProtection(installerObserver, probe, plan, ownerPin)
	if e != nil {
		t.Fatal(e)
	}
	var protection artifact.Digest
	if e = wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 10*time.Second, true, func(c context.Context) (bool, error) {
		var err error
		protection, _, err = guard.Current(c)
		return err == nil, nil
	}); e != nil {
		t.Fatal("native owner guard", e)
	}
	ca, ck := connectorSQLCA(t)
	sca, sk := connectorSQLCA(t)
	profile := fleet.ConnectorCredentialProfile{RootID: root, Binding: fleet.PeerBinding{InstallationID: installation, ClusterID: cluster, IssuerEpoch: epoch, PeerID: custodyID(), Role: fleet.ConnectorPeer}, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{3}}, ProtectionDigest: artifact.Digest{4}, ServerName: "synthetic-connector.invalid", ClientIssuerRoots: [][]byte{ca.Raw}, ServerIssuerRoots: [][]byte{sca.Raw}, Deployment: fleet.ConnectorDeployment{Namespace: name, NamespaceUID: string(ns.UID), ServiceAccount: "connector", AccountUID: string(accounts["connector"].UID), Deployment: dep.Name, DeploymentUID: string(dep.UID), ServingSlots: 1, RetainedProcesses: 2}}
	projection := planning.ProjectionDigest()
	hexD := func(d artifact.Digest) string { return hex.EncodeToString(d[:]) }
	settings := contracts.ConnectorAPIContextSettings{Format: contracts.ConnectorAPIContextFormat, RootID: root, InstallationID: installation, ClusterID: cluster, IssuerEpoch: epoch, ConnectorRevision: contracts.APIContextRevision{UID: profile.Revision.UID, Generation: 1, Digest: hexD(profile.Revision.Digest)}, Namespace: name, NamespaceUID: string(ns.UID), Account: "connector", AccountUID: string(accounts["connector"].UID), Deployment: dep.Name, DeploymentUID: string(dep.UID), ImageDigest: hexD(image), TemplateDigest: hexD(template), ProjectionDigest: hexD(projection), WorkloadProtectionDigest: hexD(protection), CapacityAccount: "capacity", CapacityAccountUID: string(accounts["capacity"].UID), Inputs: []contracts.ConnectorAPIInput{{Kind: "Secret", Name: secret.Name, UID: string(secret.UID), ResourceVersion: secret.ResourceVersion, DedicatedToAPI: true}}, StartGuard: contracts.ConnectorAPIStartGuard{Name: startPlan.Name, PolicyUID: startPin.PolicyUID, PolicyGeneration: startPin.PolicyGeneration, BindingUID: startPin.BindingUID, BindingResourceVersion: startPin.BindingResourceVersion}}
	encoded, e := contracts.EncodeConnectorAPIContextSettings(settings)
	if e != nil {
		t.Fatal(e)
	}
	cm, e := admin.CoreV1().ConfigMaps(name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "api-settings"}, Immutable: ptr.To(true), Data: map[string]string{"connector-api-context.json": string(encoded)}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	// Controller status updates may advance resourceVersion while the installer
	// creates the guards/settings. Retry only a definite conflict on this same
	// original spec and UID; a replacement or changed workload is never adopted.
	originalDeployment := dep.DeepCopy()
	if e = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := admin.AppsV1().Deployments(name).Get(ctx, originalDeployment.Name, meta.GetOptions{})
		if err != nil {
			return err
		}
		if current.UID != originalDeployment.UID || !reflect.DeepEqual(current.Spec, originalDeployment.Spec) {
			return errors.New("fixture original Deployment changed before activation")
		}
		current.Spec.Replicas = ptr.To(int32(1))
		updated, err := admin.AppsV1().Deployments(name).Update(ctx, current, meta.UpdateOptions{})
		if err == nil {
			dep = updated
		}
		return err
	}); e != nil {
		t.Fatal(e)
	}
	var pod *core.Pod
	if e = wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true, func(c context.Context) (bool, error) {
		ps, e := admin.CoreV1().Pods(name).List(c, meta.ListOptions{LabelSelector: "app=" + name})
		if e != nil {
			return false, e
		}
		if len(ps.Items) == 1 && ps.Items[0].Status.Phase == core.PodRunning && ps.Items[0].Spec.NodeName != "" {
			pod = ps.Items[0].DeepCopy()
			return true, nil
		}
		return false, nil
	}); e != nil {
		t.Fatal("real guarded Deployment Pod", e)
	}
	runtimeConfig := tokenConfig("connector", pod, "")
	runtime := client(runtimeConfig)
	guard, e = kube.NewOwnerWorkloadProtection(runtime, probe, plan, ownerPin)
	if e != nil {
		t.Fatal(e)
	}
	source, e := kube.NewConnectorAPISettingsProtection(runtime, settingsProbe, sourcePlan, sourcePin)
	if e != nil {
		t.Fatal(e)
	}
	fixtureSource := &contextStartConnectorFixture{profile: profile, clientCA: ca, serverCA: sca, clientKey: ck, serverKey: sk, issued: map[string]fleet.IssuedConnectorCredential{}, origins: map[artifact.Digest]fleet.ConnectorProcessIdentity{}}
	proofToken := tokenConfig("connector", pod, kube.ConnectorEnrollmentAudience(installation))
	attester, e := kube.NewConnectorProcessAttester(runtime, fixtureSource, guard, contextStartPodToken(proofToken.BearerToken))
	if e != nil {
		t.Fatal(e)
	}
	fixtureSource.proof = attester
	credentials, e := mtls.NewConnectorProcessCredentials(ctx, profile, string(pod.UID), fixtureSource, fixtureSource, fixtureSource, fixtureSource, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer credentials.Close()
	if e = credentials.Reconcile(ctx); e != nil {
		t.Fatal("real token/guard process enrollment with synthetic ledger", e)
	}
	protected, e := kube.NewConnectorAPIExecutionProtection(attester, credentials, source, cm.Name, string(cm.UID), cm.ResourceVersion, settings)
	if e != nil {
		t.Fatal(e)
	}
	processCounts := stats.snapshot()
	processStarted := time.Now()
	process, e := kube.NewConnectorAPIExecutionProcess(ctx, protected)
	stats.phase(t, "process-constructor", processStarted, processCounts)
	if e != nil {
		t.Fatalf("actual defaulted Pod API process: elapsed=%s err=%v", time.Since(processStarted), e)
	}
	readCounts := stats.snapshot()
	readStarted := time.Now()
	observed, e := process.ReadAPIProcess(ctx)
	stats.phase(t, "process-read", readStarted, readCounts)
	if e != nil || !observed.Valid(time.Now()) || observed.Binding.PodUID != string(pod.UID) || observed.Binding.ImageDigest != image {
		t.Fatalf("current API process: elapsed=%s err=%v", time.Since(readStarted), e)
	}
	t.Log("actual guarded Deployment/ReplicaSet/Pod defaults, explicit projected token and independently pinned startup inputs accepted")
	previousUntil := observed.ValidUntil
	runtimeAPI, e := kubernetes.NewForConfig(runtimeConfig)
	if e != nil {
		t.Fatal(e)
	}
	t.Run("named-whole-secret-and-foreign-denial", func(t *testing.T) {
		// Explicitly show the grant includes all keys of this approved object. Do
		// not log or compare its credential bytes as an authority claim.
		v, e := runtimeAPI.CoreV1().Secrets(name).Get(ctx, secret.Name, meta.GetOptions{})
		if e != nil || len(v.Data) != 2 {
			t.Fatal("approved whole-object GET", e)
		}
		if _, e = runtimeAPI.CoreV1().Secrets(name).Get(ctx, "foreign-role", meta.GetOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("unrelated credential read not denied", e)
		}
		if _, e = runtimeAPI.CoreV1().Secrets(name).List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("namespace Secret list not denied", e)
		}
		bad := settings
		bad.Inputs = append([]contracts.ConnectorAPIInput(nil), settings.Inputs...)
		bad.Inputs[0].DedicatedToAPI = false
		if _, e = kube.NewConnectorAPIExecutionProtection(attester, credentials, source, cm.Name, string(cm.UID), cm.ResourceVersion, bad); e == nil {
			t.Fatal("unapproved shared Secret accepted")
		}
	})
	t.Run("setup-original-native-bracket", func(t *testing.T) {
		// This is an independent cold setup, not a renewal of the earlier read.
		waitConnectorAPIFixtureObservation(t, ctx, previousUntil)
		call, end := context.WithTimeout(ctx, 5*time.Second)
		defer end()
		before, started := stats.snapshot(), time.Now()
		setup, err := process.BeginAPIContextSetup(call, credentials)
		stats.phase(t, "setup-begin", started, before)
		if err != nil {
			t.Fatal("complete native setup proof", err)
		}
		defer setup.Close()
		before = stats.snapshot()
		first, _, err := setup.ReadAPIProcessConnector(call, credentials)
		if err != nil || !first.Valid(time.Now()) {
			t.Fatal("owned initial proof", err)
		}
		previousUntil = first.ValidUntil
		source, err := setup.Source(call)
		if err != nil || !source.Valid(time.Now()) || source.Observation.FreshUntil.After(first.ValidUntil) {
			t.Fatal("actual closing source frame", err)
		}
		if _, err = setup.Source(call); err == nil {
			t.Fatal("source frame repeated")
		}
		if after := stats.snapshot(); !reflect.DeepEqual(before.counts, after.counts) {
			t.Fatal("local setup reads repeated native API work")
		}
		started = time.Now()
		if err = setup.Finish(call); err != nil {
			t.Fatal("closing native/source checks", err)
		}
		stats.phase(t, "setup-finish", started, before)
		if after := stats.snapshot(); reflect.DeepEqual(before.counts, after.counts) {
			t.Fatal("closing native checks performed no API work")
		}
		last, _, err := setup.ReadAPIProcessConnector(call, credentials)
		if err != nil || !last.CheckedAt.Equal(first.CheckedAt) || last.ValidUntil.After(first.ValidUntil) {
			t.Fatal("setup renewed original proof", err)
		}
		if err = setup.Finish(call); err == nil {
			t.Fatal("closing native work repeated")
		}
		setup.Close()
		if _, _, err = setup.ReadAPIProcessConnector(call, credentials); err == nil {
			t.Fatal("closed setup remained usable")
		}
	})
	t.Run("actual-start-status-under-both-guards", func(t *testing.T) {
		// ADR-175: the connector's own Pod-bound account mints the capacity token.
		tokens, e := kube.NewCapacityTokens(ctx, runtime, "capacity", apiAudience, string(pod.UID))
		if e != nil {
			t.Fatal("capacity token source", e)
		}
		defer tokens.Close()
		minted, e := tokens.Token(ctx)
		if e != nil {
			t.Fatal("admitted capacity TokenRequest", e)
		}
		capacityConfig := rest.AnonymousClientConfig(config)
		capacityConfig.BearerToken = string(minted)
		capacityConfig.WrapTransport = stats.wrap
		previousUntil = qualifyConnectorAPIStart(t, ctx, config, capacityConfig, runtimeConfig, client, process, observed, control, stats, previousUntil)
	})
	t.Run("capacity-token-admission", func(t *testing.T) {
		// RBAC allows the connector to request the capacity token; admission
		// admits only the unbound 600-second shape with the pinned audience,
		// requested by the connector's own Pod-bound credential (ADR-175).
		request := func(api kubernetes.Interface, seconds int64, audiences []string, bound *auth.BoundObjectReference) error {
			_, e := api.CoreV1().ServiceAccounts(name).CreateToken(ctx, "capacity", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(seconds), Audiences: audiences, BoundObjectRef: bound}}, meta.CreateOptions{})
			return e
		}
		if e := request(runtimeAPI, 600, []string{apiAudience}, nil); e != nil {
			capacityTokenConditionDiagnostic(t, ctx, admin, runtimeConfig, name, string(accounts["connector"].UID), apiAudience)
			t.Fatal("exact capacity TokenRequest denied", e)
		}
		unbound, e := kubernetes.NewForConfig(tokenConfig("connector", nil, ""))
		if e != nil {
			t.Fatal(e)
		}
		secretBound := &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: secret.Name, UID: secret.UID}
		for reason, e := range map[string]error{
			"longer lifetime":         request(runtimeAPI, 3600, []string{apiAudience}, nil),
			"other audience":          request(runtimeAPI, 600, []string{"https://elsewhere.invalid"}, nil),
			"bound to a Secret":       request(runtimeAPI, 600, []string{apiAudience}, secretBound),
			"requester not Pod-bound": request(unbound, 600, []string{apiAudience}, nil),
		} {
			if !apierrors.IsForbidden(e) && !apierrors.IsInvalid(e) {
				t.Fatal("capacity TokenRequest admitted:", reason, e)
			}
		}
		if _, e := runtimeAPI.CoreV1().ServiceAccounts(name).CreateToken(ctx, "probe", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600)), Audiences: []string{apiAudience}}}, meta.CreateOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("token for another account minted", e)
		}
	})
	t.Run("changed-input-metadata", func(t *testing.T) {
		waitConnectorAPIFixtureObservation(t, ctx, previousUntil)
		setup, err := process.BeginAPIContextSetup(ctx, credentials)
		if err != nil {
			t.Fatal("opening before independent input change", err)
		}
		defer setup.Close()
		opened, err := setup.Source(ctx)
		if err != nil {
			t.Fatal("initial source before input change", err)
		}
		v, e := admin.CoreV1().Secrets(name).Get(ctx, secret.Name, meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		v.Annotations = map[string]string{"synthetic-revision": "changed"}
		if _, e = admin.CoreV1().Secrets(name).Update(ctx, v, meta.UpdateOptions{}); e != nil {
			t.Fatal(e)
		}
		if err = setup.Finish(ctx); err == nil {
			t.Fatal("closing setup accepted changed input RV")
		}
		if ctx.Err() != nil || !time.Now().Before(opened.Observation.FreshUntil) {
			t.Fatal("input-change refusal was obscured by original expiry")
		}
		if _, _, err = setup.ReadAPIProcessConnector(ctx, credentials); err == nil {
			t.Fatal("failed closing setup returned its opening proof")
		}
		if _, e = process.ReadAPIProcess(ctx); e == nil {
			t.Fatal("changed input RV accepted")
		}
	})
}

// Independent fixture phases must not accidentally inherit a nearly spent
// proof. Wait for the previous phase's actual original end before beginning a
// different operation. No in-flight operation waits, refreshes or retries.
func waitConnectorAPIFixtureObservation(t *testing.T, ctx context.Context, until time.Time) {
	t.Helper()
	if delay := time.Until(until); delay > 0 {
		t.Logf("independent fixture phase waits for previous original observation: %s", delay)
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func qualifyConnectorAPIStart(t *testing.T, ctx context.Context, adminConfig, capacityConfig, runtimeConfig *rest.Config, client func(*rest.Config) *kube.PermissionClient, process *kube.ConnectorAPIExecutionProcess, observed execution.APIProcessObservation, control cfg.NamespaceRef, stats *contextStartAPIStats, previousUntil time.Time) time.Time {
	t.Helper()
	dc, e := dynamic.NewForConfig(adminConfig)
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile("../../charts/asservat/crds/capacityreservations.yaml")
	if e != nil {
		t.Fatal(e)
	}
	var crd unstructured.Unstructured
	if json.Unmarshal(data, &crd.Object) != nil {
		t.Fatal("shipped CRD invalid")
	}
	crds := dc.Resource(schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"})
	if _, e = crds.Create(ctx, &crd, meta.CreateOptions{}); e != nil && !apierrors.IsAlreadyExists(e) {
		t.Fatal(e)
	}
	if e = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(c context.Context) (bool, error) {
		v, e := crds.Get(c, crd.GetName(), meta.GetOptions{})
		if e != nil {
			return false, e
		}
		conditions, _, _ := unstructured.NestedSlice(v.Object, "status", "conditions")
		for _, r := range conditions {
			m, _ := r.(map[string]any)
			if m["type"] == "Established" && m["status"] == "True" {
				return true, nil
			}
		}
		return false, nil
	}); e != nil {
		t.Fatal(e)
	}
	// Established does not mean admission already serves the new resource; the
	// chart installs this CRD long before any start. A dry-run CREATE as the
	// capacity account runs both guards and stores nothing; keep it out of the
	// timed phase and log each refusal.
	probe, e := dynamic.NewForConfig(capacityConfig)
	if e != nil {
		t.Fatal(e)
	}
	ready := time.Now()
	if e = wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(c context.Context) (bool, error) {
		n := time.Now().UTC().Truncate(time.Microsecond)
		pb := execution.Binding{ExecutionClass: artifact.ContextAPIExecution, OperationID: custodyID(), CaptureID: custodyID(), ActionID: "pod-status", AttemptID: custodyID(), ClusterID: observed.Binding.ClusterID, IssuerEpoch: observed.Binding.IssuerEpoch, PodUID: custodyID(), ExecutorPodUID: observed.Binding.PodUID, ExecutorAccountUID: observed.Binding.AccountUID, CollectorEpoch: observed.Binding.ProcessEpoch, ScopeDigest: artifact.Digest{1}, AuthorityDigest: artifact.Digest{2}, BudgetDigest: artifact.Digest{3}, AuditDigest: artifact.Digest{4}, NativeBytes: artifact.MaxContextBytes, NotBefore: n, NotAfter: n.Add(5 * time.Second)}
		e := connectorAPIStartCreate(c, probe, control.Name, pb, true)
		if e != nil {
			var status apierrors.APIStatus
			if errors.As(e, &status) {
				t.Logf("start readiness: dry-run CREATE refused after %s: code=%d reason=%s message=%q", time.Since(ready), status.Status().Code, status.Status().Reason, status.Status().Message)
			} else {
				t.Logf("start readiness: dry-run CREATE failed after %s: %v", time.Since(ready), e)
			}
		}
		return e == nil, nil
	}); e != nil {
		t.Fatal("capacity reservations not admitted", e)
	}
	t.Logf("start readiness: dry-run CREATE admitted after %s", time.Since(ready))
	waitConnectorAPIFixtureObservation(t, ctx, previousUntil)
	preparer, e := kube.NewConnectorAPIStartPreparer(process, client(capacityConfig))
	if e != nil {
		t.Fatal(e)
	}
	journal, e := kube.NewStartJournal(runtimeConfig, observed.Binding.ClusterID, control, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	// ADR-173 order of one work: the first process read (here a cold, complete
	// proof) is the work's observation; every start step reuses it and must
	// finish within its original interval.
	readCounts := stats.snapshot()
	n := time.Now().UTC().Truncate(time.Microsecond)
	work, e := process.ReadAPIProcess(ctx)
	stats.phase(t, "work-process-read", n, readCounts)
	if e != nil || work.Binding != observed.Binding {
		t.Fatal("work process observation", e)
	}
	// Bindings carry canonical UTC microsecond times, as SQL preparation writes them.
	n = work.CheckedAt.UTC().Truncate(time.Microsecond)
	b := execution.Binding{ExecutionClass: artifact.ContextAPIExecution, OperationID: custodyID(), CaptureID: custodyID(), ActionID: "pod-status", AttemptID: custodyID(), ClusterID: work.Binding.ClusterID, IssuerEpoch: work.Binding.IssuerEpoch, PodUID: custodyID(), ExecutorPodUID: work.Binding.PodUID, ExecutorAccountUID: work.Binding.AccountUID, CollectorEpoch: work.Binding.ProcessEpoch, ScopeDigest: artifact.Digest{1}, AuthorityDigest: artifact.Digest{2}, BudgetDigest: artifact.Digest{3}, AuditDigest: artifact.Digest{4}, NativeBytes: artifact.MaxContextBytes, NotBefore: n, NotAfter: work.ValidUntil.UTC().Truncate(time.Microsecond)}
	// Fixture-only acknowledged preparation grant. It is not a real SQL prepare.
	prepareCounts, prepareStarted := stats.snapshot(), time.Now()
	p, e := preparer.PrepareObservedStart(ctx, execution.PreparationCheck{Binding: b, CheckedAt: n, ValidUntil: b.NotAfter, MayCreate: true}, work)
	stats.phase(t, "prepare-start", prepareStarted, prepareCounts)
	if e != nil {
		connectorAPIStartDiagnostic(t, ctx, dc, control.Name, "start-"+b.AttemptID)
		connectorAPIStartReplay(t, ctx, capacityConfig, control.Name, b)
		t.Fatalf("actual capacity CREATE elapsed=%s original_remaining=%s err=%v", time.Since(n), time.Until(b.NotAfter), e)
	}
	request := execution.Request{Binding: b, ObjectUID: p.ObjectUID, CheckedAt: n, ValidUntil: b.NotAfter}
	readyCounts, readyStarted := stats.snapshot(), time.Now()
	_, e = preparer.ReadyObservedStart(ctx, request, work)
	stats.phase(t, "ready-start", readyStarted, readyCounts)
	if e != nil {
		t.Fatalf("actual capacity status Ready elapsed=%s original_remaining=%s err=%v", time.Since(n), time.Until(b.NotAfter), e)
	}
	consumeCounts, consumeStarted := stats.snapshot(), time.Now()
	got, e := journal.ConsumeStart(ctx, request)
	stats.phase(t, "consume-start", consumeStarted, consumeCounts)
	if e != nil || !got.MayStart {
		t.Fatalf("actual executor status StartCommitted elapsed=%s original_remaining=%s err=%v", time.Since(n), time.Until(b.NotAfter), e)
	}
	replay, e := journal.ConsumeStart(ctx, request)
	if e != nil || replay.MayStart {
		t.Fatal("consumed local start replay", e)
	}
	t.Logf("work process read, actual CREATE, Ready /status and one StartCommitted /status within the work observation's original interval: %s of %s", time.Since(n), work.ValidUntil.Sub(n))
	return work.ValidUntil
}

// Static operation classes only: never paths, request bodies, source identities,
// tokens, Secret contents or raw provider errors. Rate limiter waits are outside
// RoundTrip, so phase elapsed and these measured I/O totals remain distinct.
type contextStartAPIStats struct {
	mu      sync.Mutex
	counts  map[string]int
	elapsed map[string]time.Duration
}

func (s *contextStartAPIStats) wrap(next http.RoundTripper) http.RoundTripper {
	return ownerProbeRoundTripper(func(r *http.Request) (*http.Response, error) {
		class := "other"
		for _, v := range []string{"tokenreviews", "selfsubjectreviews", "validatingadmissionpolicies", "validatingadmissionpolicybindings", "capacityreservations", "deployments", "replicasets", "pods", "configmaps", "secrets", "serviceaccounts"} {
			if strings.Contains(r.URL.Path, "/"+v) {
				class = v
				break
			}
		}
		if strings.HasSuffix(r.URL.Path, "/status") {
			class += "/status"
		}
		if r.URL.Query().Get("dryRun") == "All" {
			class += "/dry-run"
		}
		class = r.Method + " " + class
		n := time.Now()
		response, e := next.RoundTrip(r)
		s.mu.Lock()
		s.counts[class]++
		s.elapsed[class] += time.Since(n)
		s.mu.Unlock()
		return response, e
	})
}

// Static per-phase deltas distinguish limiter/proof work from API round trips.
// The snapshot never includes paths, objects, credentials or response bodies.
type contextStartAPIPhase struct {
	counts  map[string]int
	elapsed map[string]time.Duration
}

func (s *contextStartAPIStats) snapshot() contextStartAPIPhase {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := contextStartAPIPhase{counts: map[string]int{}, elapsed: map[string]time.Duration{}}
	for k, v := range s.counts {
		out.counts[k] = v
	}
	for k, v := range s.elapsed {
		out.elapsed[k] = v
	}
	return out
}
func (s *contextStartAPIStats) phase(t *testing.T, name string, started time.Time, before contextStartAPIPhase) {
	t.Helper()
	after := s.snapshot()
	for k, v := range before.counts {
		after.counts[k] -= v
	}
	for k, v := range before.elapsed {
		after.elapsed[k] -= v
	}
	for k, v := range after.counts {
		if v == 0 {
			delete(after.counts, k)
			delete(after.elapsed, k)
		}
	}
	t.Logf("bounded phase=%s elapsed=%s API_counts=%v API_roundtrip=%v", name, time.Since(started), after.counts, after.elapsed)
}

// connectorAPIStartDiagnostic distinguishes a refused CREATE from a refused
// response: it reports only the stored object's shape (synthetic values).
func connectorAPIStartDiagnostic(t *testing.T, ctx context.Context, dc dynamic.Interface, namespace, name string) {
	t.Helper()
	v, e := dc.Resource(schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "capacityreservations"}).Namespace(namespace).Get(ctx, name, meta.GetOptions{})
	if e != nil {
		t.Logf("start diagnostic: stored object absent or unreadable: %v", e)
		return
	}
	raw, _ := json.Marshal(v.Object)
	tokens := 0
	for d := json.NewDecoder(bytes.NewReader(raw)); ; tokens++ {
		if _, e := d.Token(); e != nil {
			break
		}
	}
	keys := func(m map[string]any) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	spec, _, _ := unstructured.NestedMap(v.Object, "spec")
	metadata, _, _ := unstructured.NestedMap(v.Object, "metadata")
	_, status := v.Object["status"]
	managed, _, _ := unstructured.NestedSlice(v.Object, "metadata", "managedFields")
	t.Logf("start diagnostic: stored bytes=%d json_tokens=%d top=%v metadata=%v spec=%v status=%t generation=%d managedFields=%d", len(raw), tokens, keys(v.Object), keys(metadata), keys(spec), status, v.GetGeneration(), len(managed))
}

// connectorAPIStartReplay repeats the refused CREATE as the capacity account to
// log the server's status. A refused request has no effect.
func connectorAPIStartReplay(t *testing.T, ctx context.Context, capacityConfig *rest.Config, namespace string, b execution.Binding) {
	t.Helper()
	dc, e := dynamic.NewForConfig(capacityConfig)
	if e != nil {
		t.Logf("start replay: client: %v", e)
		return
	}
	e = connectorAPIStartCreate(ctx, dc, namespace, b, false)
	var status apierrors.APIStatus
	if errors.As(e, &status) {
		t.Logf("start replay: code=%d reason=%s message=%q", status.Status().Code, status.Status().Reason, status.Status().Message)
		return
	}
	t.Logf("start replay: err=%v", e)
}

func connectorAPIStartCreate(ctx context.Context, dc dynamic.Interface, namespace string, b execution.Binding, dryRun bool) error {
	spec, e := kube.LocalStartSpec(b)
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(spec)
	var fields map[string]any
	if e = json.Unmarshal(raw, &fields); e != nil {
		return e
	}
	object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "CapacityReservation", "metadata": map[string]any{"name": "start-" + b.AttemptID, "namespace": namespace}, "spec": fields}}
	options := meta.CreateOptions{}
	if dryRun {
		options.DryRun = []string{meta.DryRunAll}
	}
	_, e = dc.Resource(schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "capacityreservations"}).Namespace(namespace).Create(ctx, object, options)
	return e
}

type capacityTokenWarnings struct {
	mu   sync.Mutex
	seen []string
}

func (w *capacityTokenWarnings) HandleWarningHeader(_ int, _ string, message string) {
	w.mu.Lock()
	w.seen = append(w.seen, message)
	w.mu.Unlock()
}

// capacityTokenConditionDiagnostic evaluates each condition of the ADR-175
// clause as a separate Warn-only policy on the real API server and logs the
// conditions that evaluate false for the connector's exact request.
func capacityTokenConditionDiagnostic(t *testing.T, ctx context.Context, admin kubernetes.Interface, runtime *rest.Config, namespace, connectorUID, audience string) {
	t.Helper()
	quote := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	conditions := map[string]string{
		"operation":   "request.operation == 'CREATE'",
		"group":       "(has(request.resource.group) ? request.resource.group : '') == ''",
		"resource":    "request.resource.resource == 'serviceaccounts'",
		"subresource": "(has(request.subResource) ? request.subResource : '') == 'token'",
		"name":        "request.name == 'capacity'",
		"username":    "request.userInfo.username == " + quote("system:serviceaccount:"+namespace+":connector"),
		"uid":         "request.userInfo.uid == " + quote(connectorUID),
		"pod-extra":   "has(request.userInfo.extra) && 'authentication.kubernetes.io/pod-uid' in request.userInfo.extra && size(request.userInfo.extra['authentication.kubernetes.io/pod-uid']) == 1",
		"spec":        "has(object.spec)",
		"audiences":   "has(object.spec.audiences) && object.spec.audiences == [" + quote(audience) + "]",
		"expiration":  "has(object.spec.expirationSeconds) && object.spec.expirationSeconds == 600",
		"unbound":     kube.CapacityTokenUnboundCondition,
		"sentinel":    "false",
	}
	fail, equivalent := admission.Fail, admission.Equivalent
	var names []string
	for label, expression := range conditions {
		n := "diag-capacity-" + label
		policy := &admission.ValidatingAdmissionPolicy{ObjectMeta: meta.ObjectMeta{Name: n}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create}, Rule: admission.Rule{APIGroups: []string{""}, APIVersions: []string{"*"}, Resources: []string{"serviceaccounts/token"}}}}}}, MatchConditions: []admission.MatchCondition{{Name: "namespace", Expression: "request.namespace == " + quote(namespace)}}, Validations: []admission.Validation{{Expression: expression, Message: "condition false: " + label, MessageExpression: "'condition false: " + label + " bound=' + (has(object.spec.boundObjectRef) ? ((has(object.spec.boundObjectRef.kind) ? object.spec.boundObjectRef.kind : '-') + '/' + (has(object.spec.boundObjectRef.name) ? object.spec.boundObjectRef.name : '-')) : 'absent')"}}}}
		if _, e := admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{}); e != nil {
			t.Logf("diagnostic policy %s: %v", label, e)
			continue
		}
		binding := &admission.ValidatingAdmissionPolicyBinding{ObjectMeta: meta.ObjectMeta{Name: n}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: n, ValidationActions: []admission.ValidationAction{admission.Warn}}}
		if _, e := admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{}); e != nil {
			t.Logf("diagnostic binding %s: %v", label, e)
		}
		names = append(names, n)
	}
	defer func() {
		for _, n := range names {
			_ = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(context.Background(), n, meta.DeleteOptions{})
			_ = admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(context.Background(), n, meta.DeleteOptions{})
		}
	}()
	warnings := &capacityTokenWarnings{}
	c := rest.CopyConfig(runtime)
	c.WarningHandler = warnings
	api, e := kubernetes.NewForConfig(c)
	if e != nil {
		t.Logf("diagnostic client: %v", e)
		return
	}
	// Policies load asynchronously; the always-false sentinel shows they apply.
	for range 40 {
		warnings.mu.Lock()
		warnings.seen = nil
		warnings.mu.Unlock()
		_, e = api.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, "capacity", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600)), Audiences: []string{audience}}}, meta.CreateOptions{})
		warnings.mu.Lock()
		seen := slices.Clone(warnings.seen)
		warnings.mu.Unlock()
		if slices.ContainsFunc(seen, func(m string) bool { return strings.Contains(m, "condition false: sentinel") }) {
			t.Logf("capacity TokenRequest diagnostic: request error=%v warnings=%q", e, seen)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Log("capacity TokenRequest diagnostic: policies never applied")
}
