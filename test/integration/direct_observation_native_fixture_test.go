package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	admission "k8s.io/api/admissionregistration/v1"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// This resource setup is deliberately outside any measured operation. It
// supplies synthetic installer acceptance over real original API identities;
// it never claims an acknowledged installed v2 backend or namespace history.
type directNativeCluster struct {
	api         kubernetes.Interface
	config      *rest.Config
	kubeconfig  string
	id          string
	namespace   *core.Namespace
	accounts    map[string]*core.ServiceAccount
	deployments map[string]*apps.Deployment
	pods        map[string]*core.Pod
	inputUntil  map[string]time.Time
	plan        cfg.OwnerWorkloadAdministration
	guard       kube.GuardPin
	protection  artifact.Digest
	probeToken  string
	service     *core.Service
	dial        string
	lifecycle   string
	product     bool
	image       artifact.Digest
}

// newDirectNativeCluster prepares one owned cluster. product, when set,
// replaces the fixture helper Pod spec with an actual product process spec.
func newDirectNativeCluster(t *testing.T, ctx context.Context, f fixture, index int, installation string, product ...func(mode string) core.PodSpec) *directNativeCluster {
	t.Helper()
	if index < 0 || index >= len(f.Clusters) || f.WorkerImage == "" {
		t.Fatal("fixed native fixture cluster/image missing")
	}
	parts := strings.Split(f.WorkerImage, "@sha256:")
	if len(parts) != 2 {
		t.Fatal("native helper image lacks exact digest")
	}
	digest, e := hex.DecodeString(parts[1])
	if e != nil || len(digest) != 32 {
		t.Fatal("native helper image digest invalid")
	}
	config, e := clientcmd.BuildConfigFromFlags("", f.Clusters[index].Config)
	if e != nil {
		t.Fatal("native API config unavailable")
	}
	api, e := kubernetes.NewForConfig(config)
	if e != nil {
		t.Fatal("native API client unavailable")
	}
	id := custodyID()
	name := "direct-observation-" + id[len(id)-10:]
	ns, e := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted", "native-team": "test"}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal("native namespace create", e)
	}
	x := &directNativeCluster{api: api, config: config, kubeconfig: f.Clusters[index].Config, id: custodyID(), namespace: ns, accounts: map[string]*core.ServiceAccount{}, deployments: map[string]*apps.Deployment{}, pods: map[string]*core.Pod{}, inputUntil: map[string]time.Time{}}
	copy(x.image[:], digest)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := api.CoreV1().Namespaces().Delete(c, name, meta.DeleteOptions{}); e != nil && !apierrors.IsNotFound(e) {
			t.Error("native namespace cleanup", e)
		}
	})
	modes := []string{"owner", "hwork"}
	guardDeployment := "owner"
	if index == 1 {
		modes = []string{"regional"}
		guardDeployment = "regional"
	}
	for _, account := range append(append([]string{}, modes...), "probe", "setup-observer") {
		a, e := api.CoreV1().ServiceAccounts(name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: account}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("native account create", e)
		}
		x.accounts[account] = a
	}
	for _, mode := range modes {
		labels := map[string]string{"app": name, "fixture-role": mode}
		var audience, tokenFile string
		switch mode {
		case "owner":
			audience = kube.OwnerEnrollmentAudience(installation)
			tokenFile = "owner.token"
		case "hwork":
			audience = value.ClusterObservationAudience(installation)
			tokenFile = "caller.token"
		case "regional":
			audience = kube.ConnectorEnrollmentAudience(installation)
			tokenFile = "connector.token"
		}
		projection := []core.VolumeProjection{{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: mode + "-inputs"}, Optional: ptr.To(false)}}, {ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "observer.token", ExpirationSeconds: ptr.To(int64(600))}}, {ServiceAccountToken: &core.ServiceAccountTokenProjection{Audience: audience, Path: tokenFile, ExpirationSeconds: ptr.To(int64(600))}}}
		spec := core.PodSpec{ServiceAccountName: mode, AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), RestartPolicy: core.RestartPolicyAlways, TerminationGracePeriodSeconds: ptr.To(int64(10)), SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Volumes: []core.Volume{{Name: "fixture", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0400)), Sources: projection}}}, {Name: "state", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{Medium: core.StorageMediumMemory, SizeLimit: ptr.To(resource.MustParse("8Mi"))}}}}, Containers: []core.Container{{Name: "fixture", Image: f.WorkerImage, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/observation-native", mode}, Env: []core.EnvVar{{Name: "POD_UID", ValueFrom: &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.uid"}}}}, VolumeMounts: []core.VolumeMount{{Name: "fixture", MountPath: "/fixture", ReadOnly: true}, {Name: "state", MountPath: "/state"}}, SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}, Resources: core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("64Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("500m"), core.ResourceMemory: resource.MustParse("256Mi")}}}}, Tolerations: []core.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}, {Key: "node.kubernetes.io/unreachable", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}}}
		if len(product) == 1 {
			spec = product[0](mode)
		}
		d, e := api.AppsV1().Deployments(name).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: mode}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Selector: &meta.LabelSelector{MatchLabels: labels}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: spec}}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("native helper Deployment create", e)
		}
		x.deployments[mode] = d
	}
	if index == 0 {
		ports := []core.ServicePort{{Name: "owner", Port: 9443, TargetPort: intstr.FromInt(9443), Protocol: core.ProtocolTCP}, {Name: "observation", Port: 9444, TargetPort: intstr.FromInt(9444), Protocol: core.ProtocolTCP}, {Name: "public", Port: 9445, TargetPort: intstr.FromInt(9445), Protocol: core.ProtocolTCP}}
		selected := map[string]string{"app": name, "fixture-role": "owner"}
		x.service, e = api.CoreV1().Services(name).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: "owner"}, Spec: core.ServiceSpec{Selector: selected, Ports: ports}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("original native Service create", e)
		}
		reachable, e := api.CoreV1().Services(name).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: "fixture-regional-dial"}, Spec: core.ServiceSpec{Type: core.ServiceTypeNodePort, Selector: selected, Ports: []core.ServicePort{{Name: "fixture-observation", Port: 9444, TargetPort: intstr.FromInt(9444), Protocol: core.ProtocolTCP}, {Name: "fixture-lifecycle", Port: 9446, TargetPort: intstr.FromInt(9446), Protocol: core.ProtocolTCP}}}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture reachability Service create", e)
		}
		nodes, e := api.CoreV1().Nodes().List(ctx, meta.ListOptions{})
		if e != nil {
			t.Fatal("owned node address", e)
		}
		for _, node := range nodes.Items {
			if string(node.UID) != f.Clusters[index].NodeUID {
				continue
			}
			for _, address := range node.Status.Addresses {
				if address.Type == core.NodeInternalIP && net.ParseIP(address.Address) != nil {
					x.dial = net.JoinHostPort(address.Address, fmt.Sprint(reachable.Spec.Ports[0].NodePort))
					x.lifecycle = net.JoinHostPort(address.Address, fmt.Sprint(reachable.Spec.Ports[1].NodePort))
				}
			}
		}
		if x.dial == "" {
			t.Fatal("original owned node address missing")
		}
	}
	who, e := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if e != nil {
		t.Fatal("fixture administrator identity", e)
	}
	x.plan = cfg.OwnerWorkloadAdministration{Name: name, ControlNamespace: cfg.NamespaceRef{Name: name, UID: string(ns.UID)}, Deployment: guardDeployment, DeploymentUID: string(x.deployments[guardDeployment].UID), Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}
	if index == 1 {
		x.plan.ConfigurationProbes = []cfg.OwnerConfigurationProbe{{ServiceAccount: "probe", ConfigMap: "connector-identity"}}
		if len(product) == 1 {
			// A product process probes with its own account, like the owner.
			x.product = true
			x.plan.ConfigurationProbes = []cfg.OwnerConfigurationProbe{{ServiceAccount: "regional", ConfigMap: "connector-identity"}}
			// ADR-193: the connector CAS-writes its own credential Secret.
			x.plan.CredentialSecrets = []cfg.OwnerCredentialSecret{{Secret: "cluster-credential", ServiceAccount: "regional"}}
		}
	}
	x.installAccess(t, ctx, modes, installation)
	policy, binding, e := kube.OwnerWorkloadAdmission(x.plan)
	if e != nil {
		t.Fatal("native namespace guard plan", e)
	}
	x.guard = x.installGuard(t, ctx, policy, binding)
	for _, mode := range modes {
		x.waitPodIdentity(t, ctx, mode)
	}
	t.Cleanup(func() {
		if t.Failed() {
			for _, mode := range modes {
				x.closedDiagnostics(t, mode)
			}
		}
	})
	observer, probe := x.clients(t)
	guard, e := kube.NewOwnerWorkloadProtection(observer, probe, x.plan, x.guard)
	if e != nil {
		t.Fatal("native namespace guard reader", e)
	}
	// Admission propagation retry is setup only, before any credential/query.
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end); {
		x.protection, _, e = guard.Current(ctx)
		if e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("native guard setup cancelled")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if e != nil {
		t.Fatal("native namespace guard unavailable", e)
	}
	return x
}

func (x *directNativeCluster) installGuard(t *testing.T, ctx context.Context, p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding) kube.GuardPin {
	t.Helper()
	p, e := x.api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, p, meta.CreateOptions{})
	if e != nil {
		t.Fatal("native policy create", e)
	}
	b, e = x.api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, b, meta.CreateOptions{})
	if e != nil {
		t.Fatal("native binding create", e)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, e := range []error{x.api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(c, b.Name, meta.DeleteOptions{}), x.api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(c, p.Name, meta.DeleteOptions{})} {
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("native guard cleanup", e)
			}
		}
	})
	return kube.GuardPin{PolicyUID: string(p.UID), PolicyGeneration: p.Generation, BindingUID: string(b.UID), BindingResourceVersion: b.ResourceVersion}
}

// Retain identity before the required Secret permits any container startup.
// Pending is a fixture setup state, never a peer/readiness/authority proof.
func (x *directNativeCluster) waitPodIdentity(t *testing.T, ctx context.Context, mode string) {
	t.Helper()
	for ctx.Err() == nil {
		list, e := x.api.CoreV1().Pods(x.namespace.Name).List(ctx, meta.ListOptions{LabelSelector: "fixture-role=" + mode})
		if e != nil {
			t.Fatal("native helper Pod lookup", e)
		}
		if len(list.Items) > 1 {
			t.Fatal("native helper original Pod ambiguous")
		}
		if len(list.Items) == 1 {
			p := list.Items[0]
			if p.Status.Phase == "" && p.UID != "" && p.DeletionTimestamp == nil && !directNativeContainerStarted(&p) {
				select {
				case <-ctx.Done():
				case <-time.After(100 * time.Millisecond):
				}
				continue
			}
			if p.UID == "" || p.DeletionTimestamp != nil || p.Status.Phase != core.PodPending || directNativeContainerStarted(&p) {
				t.Fatal("native helper ran before required inputs")
			}
			owner, ok := directNativeController(p.OwnerReferences, "ReplicaSet")
			if !ok {
				t.Fatal("native original Pod controller missing")
			}
			rs, e := x.api.AppsV1().ReplicaSets(x.namespace.Name).Get(ctx, owner.Name, meta.GetOptions{})
			if e != nil {
				t.Fatal("native original ReplicaSet unavailable", e)
			}
			d, e := x.api.AppsV1().Deployments(x.namespace.Name).Get(ctx, mode, meta.GetOptions{})
			if e != nil {
				t.Fatal("native original Deployment unavailable", e)
			}
			original := x.deployments[mode]
			before, eb := kube.ConnectorAPITemplateDigest(original.Spec.Template)
			after, ea := kube.ConnectorAPITemplateDigest(d.Spec.Template)
			if !directNativePendingChain(&p, rs, d) || original.UID != d.UID || eb != nil || ea != nil || before != after {
				t.Fatal("native original Pending chain changed")
			}
			x.pods[mode] = p.DeepCopy()
			x.deployments[mode] = d
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("native helper identity setup expired")
}

func directNativeController(refs []meta.OwnerReference, kind string) (meta.OwnerReference, bool) {
	if len(refs) != 1 {
		return meta.OwnerReference{}, false
	}
	o := refs[0]
	return o, o.APIVersion == "apps/v1" && o.Kind == kind && o.Name != "" && o.UID != "" && o.Controller != nil && *o.Controller
}

func directNativeContainerStarted(p *core.Pod) bool {
	for _, s := range append(append([]core.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		if s.RestartCount != 0 || s.ContainerID != "" || s.State.Running != nil || s.State.Terminated != nil || s.LastTerminationState.Terminated != nil || (s.Started != nil && *s.Started) {
			return true
		}
	}
	return false
}

func directNativePendingChain(p *core.Pod, rs *apps.ReplicaSet, d *apps.Deployment) bool {
	if p == nil || rs == nil || d == nil || p.UID == "" || rs.UID == "" || d.UID == "" || p.Name == "" || p.Namespace == "" || rs.Name == "" || d.Name == "" || p.DeletionTimestamp != nil || rs.DeletionTimestamp != nil || d.DeletionTimestamp != nil || p.Namespace != rs.Namespace || rs.Namespace != d.Namespace || p.Status.Phase != core.PodPending || directNativeContainerStarted(p) {
		return false
	}
	po, ok := directNativeController(p.OwnerReferences, "ReplicaSet")
	ro, rok := directNativeController(rs.OwnerReferences, "Deployment")
	return ok && rok && po.UID == rs.UID && po.Name == rs.Name && ro.UID == d.UID && ro.Name == d.Name
}

// This wait owns only the original setup deadline fixed before input creation.
// It never reselects a replacement or restarts enrollment/authority work.
func (x *directNativeCluster) waitPodRunning(t *testing.T, ctx context.Context, mode string) {
	t.Helper()
	until := x.inputUntil[mode]
	original := x.pods[mode]
	if original == nil || until.IsZero() || !time.Now().Before(until) {
		t.Fatal("native original input setup expired", mode)
	}
	setup, stop := context.WithDeadline(ctx, until)
	defer stop()
	for setup.Err() == nil {
		p, e := x.api.CoreV1().Pods(x.namespace.Name).Get(setup, original.Name, meta.GetOptions{})
		if setup.Err() != nil || !time.Now().Before(until) {
			break
		}
		if e != nil {
			x.closedDiagnostics(t, mode)
			t.Fatal("native original input Pod unavailable", mode)
		}
		if p.UID != original.UID || p.DeletionTimestamp != nil || !reflect.DeepEqual(p.OwnerReferences, original.OwnerReferences) {
			t.Fatal("native original input Pod changed", mode)
		}
		for _, s := range p.Status.ContainerStatuses {
			if s.RestartCount != 0 || s.State.Terminated != nil || s.LastTerminationState.Terminated != nil {
				x.closedDiagnostics(t, mode)
				t.Fatal("native helper failed original startup", mode)
			}
		}
		if p.Status.Phase == core.PodRunning && p.Status.PodIP != "" {
			x.pods[mode] = p.DeepCopy()
			return
		}
		if p.Status.Phase != core.PodPending {
			t.Fatal("native original input Pod phase changed", mode)
		}
		select {
		case <-setup.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	x.closedDiagnostics(t, mode)
	t.Fatal("native original input materialization expired", mode)
}

func (x *directNativeCluster) installInput(t *testing.T, ctx context.Context, mode string, in Input) {
	t.Helper()
	// Start once before the API create. A slow or unknown create cannot renew
	// this setup interval; the same deadline also bounds the subsequent wait.
	setup, stop := context.WithTimeout(ctx, 2*time.Minute)
	defer stop()
	if _, exists := x.inputUntil[mode]; exists {
		t.Fatal("native input create attempt already retained")
	}
	x.inputUntil[mode], _ = setup.Deadline()
	if in.PodUID != string(x.pods[mode].UID) || in.Mode != mode {
		t.Fatal("native input original Pod mismatch")
	}
	raw, e := json.Marshal(in)
	if e != nil || len(raw) > 512<<10 {
		t.Fatal("native input encode")
	}
	defer clear(raw)
	_, e = x.api.CoreV1().Secrets(x.namespace.Name).Create(setup, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: mode + "-inputs"}, Immutable: ptr.To(true), Data: map[string][]byte{"input.json": raw, "probe.token": []byte(x.probeToken)}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal("native immutable input create", e)
	}
}

func (x *directNativeCluster) control(ctx context.Context, mode string, q ControlRequest) (ControlResult, error) {
	var zero ControlResult
	if x.pods[mode] == nil || ctx.Err() != nil {
		return zero, fmt.Errorf("native original helper unavailable")
	}
	until, ok := ctx.Deadline()
	if !ok || !time.Now().Before(until) {
		return zero, fmt.Errorf("native control requires original deadline")
	}
	q.Until = until
	raw, e := json.Marshal(q)
	if e != nil {
		return zero, e
	}
	command := exec.CommandContext(ctx, "kubectl", "--kubeconfig", x.kubeconfig, "--request-timeout=35s", "exec", "-i", "-n", x.namespace.Name, x.pods[mode].Name, "--", "/observation-native", "control")
	command.Stdin = strings.NewReader(string(raw))
	output, e := command.Output()
	if e != nil {
		return zero, fmt.Errorf("native fixed control transport unavailable")
	}
	if len(output) > 64<<10 || json.Unmarshal(output, &zero) != nil {
		return ControlResult{}, fmt.Errorf("native fixed control response invalid")
	}
	return zero, nil
}

func (x *directNativeCluster) template(t *testing.T, mode string) artifact.Digest {
	t.Helper()
	digest, e := kube.ConnectorAPITemplateDigest(x.deployments[mode].Spec.Template)
	if e != nil {
		t.Fatal("native full template digest", e)
	}
	return digest
}

// Shutdown is restrictive fixture control only. A closed/unknown control reply
// is never considered joined; the exact original Pod must expose the marker
// written after all admitted handlers, native I/O and SQL pools have closed.
func (x *directNativeCluster) shutdown(t *testing.T, mode string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	_, _ = x.control(call, mode, ControlRequest{Command: "shutdown"})
	stop()
	for ctx.Err() == nil {
		command := exec.CommandContext(ctx, "kubectl", "--kubeconfig", x.kubeconfig, "--request-timeout=5s", "exec", "-n", x.namespace.Name, x.pods[mode].Name, "--", "/observation-native", "joined")
		output, e := command.Output()
		if e == nil && string(output) == "joined\n" {
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Error("native original helper did not positively join", mode)
}

func (x *directNativeCluster) closedDiagnostics(t *testing.T, mode string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	original := x.pods[mode]
	if original == nil {
		return
	}
	pod, e := x.api.CoreV1().Pods(x.namespace.Name).Get(ctx, original.Name, meta.GetOptions{})
	if e != nil || pod.UID != original.UID {
		t.Log("native helper diagnostics unavailable", mode)
		return
	}
	phase := string(pod.Status.Phase)
	if !slices.Contains([]string{"Pending", "Running", "Succeeded", "Failed", "Unknown"}, phase) {
		phase = "other"
	}
	t.Logf("native original helper Pod mode=%s original=true phase=%s status-count=%d", mode, phase, len(pod.Status.ContainerStatuses))
	for _, s := range pod.Status.ContainerStatuses {
		if s.Name != "fixture" {
			continue
		}
		waiting := "none"
		if s.State.Waiting != nil {
			waiting = s.State.Waiting.Reason
			if !slices.Contains([]string{"ContainerCreating", "PodInitializing", "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError", "CreateContainerError", "RunContainerError", "StartError"}, waiting) {
				waiting = "other"
			}
		}
		exit := int32(0)
		if s.State.Terminated != nil {
			exit = s.State.Terminated.ExitCode
		}
		t.Logf("native original helper state mode=%s original=true phase=%s ready=%t restarts=%d waiting=%s terminated=%t exit=%d", mode, phase, s.Ready, s.RestartCount, waiting, s.State.Terminated != nil, exit)
	}
	previous := false
	for _, s := range pod.Status.ContainerStatuses {
		if s.RestartCount > 0 {
			previous = true
		}
	}
	for _, prior := range []bool{false, true} {
		if prior && !previous {
			continue
		}
		stream, e := x.api.CoreV1().Pods(x.namespace.Name).GetLogs(original.Name, &core.PodLogOptions{Container: "fixture", Previous: prior, TailLines: ptr.To(int64(32)), LimitBytes: ptr.To(int64(16384))}).Stream(ctx)
		if e != nil {
			continue
		}
		raw, e := io.ReadAll(io.LimitReader(stream, 16385))
		_ = stream.Close()
		if e != nil || len(raw) > 16384 {
			clear(raw)
			continue
		}
		for _, line := range bytes.Split(raw, []byte{'\n'}) {
			v, ok := directNativeDiagnosticLine(line)
			if !ok {
				continue
			}
			if v.Format == "" {
				t.Logf("native helper closed failure mode=%s phase=%s category=%s previous=%t", mode, v.Phase, v.Category, prior)
			} else {
				t.Logf("native helper setup mode=%s phase=%s event=%s elapsed=%s category=%s previous=%t", mode, v.Phase, v.Event, time.Duration(v.ElapsedNanos), v.Category, prior)
			}
		}
		clear(raw)
	}
}

// Accept only fixed labels and bounded numeric durations. Unknown stdout,
// error text, object identities and payload fields never reach the test log.
type directNativeDiagnostic struct {
	Format, Phase, Event, Category string
	ElapsedNanos                   int64
}

func directNativeDiagnosticLine(line []byte) (directNativeDiagnostic, bool) {
	var v directNativeDiagnostic
	if len(line) == 0 || len(line) > 16384 || json.Unmarshal(line, &v) != nil {
		return directNativeDiagnostic{}, false
	}
	phases := []string{"inputs", "inputs-projection-missing", "composition", "failed-composition-join", "shutdown", "native-clients", "owner-read-constructor", "owner-composition", "owner-enrollment", "owner-backend", "regional-composition", "regional-source", "regional-enrollment", "regional-backend", "native-listener", "lifecycle-listener", "regional-credential", "regional-lifecycle-tls", "lifecycle-present", "lifecycle-enroll", "lifecycle-issue", "lifecycle-registration", "lifecycle-stage", "lifecycle-fence", "regional-local-begin", "regional-local-read", "regional-local-source", "regional-local-configuration", "control", "sql-owner-read", "sql-owner-write", "sql-owner-ack", "sql-owner-activate", "sql-connector-read", "sql-connector-journal", "sql-connector-ack", "sql-connector-source", "sql-cluster-credential", "sql-recovery-read"}
	if !slices.Contains(phases, v.Phase) || !slices.Contains([]string{"none", "deadline", "cancelled", "invalid", "denied", "changed", "unavailable"}, v.Category) {
		return directNativeDiagnostic{}, false
	}
	if v.Format == "" && v.Event == "" && v.ElapsedNanos == 0 {
		return v, true
	}
	if v.Format != "observation-native-phase/v1" || !slices.Contains([]string{"begin", "end", "wait"}, v.Event) || v.ElapsedNanos < 0 || v.ElapsedNanos > int64(20*time.Minute) {
		return directNativeDiagnostic{}, false
	}
	return v, true
}
