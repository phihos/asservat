package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// This continuation owns no worker constructor, Pod token or source writer.
// Only the actual installed command in its original generated Pod can observe
// and acknowledge SQL29. The host witnesses through a separate read facet.
func qualifyProviderWorkerRuntime(t *testing.T, ctx context.Context, api kubernetes.Interface, config *pgx.ConnConfig, inputs *kube.ConfigurationWorkerInputs, inventory kube.InitialRuntimeResourceInventory, input contracts.HubWorkerDeployment, providers *initialRuntimeNativeProviders, owner *initialRuntimeOwnerContinuation) {
	t.Helper()
	original, err := api.AppsV1().Deployments(inventory.Namespace.Name).Get(ctx, inventory.WorkerDeployment.Name, meta.GetOptions{})
	if err != nil || string(original.UID) != inventory.WorkerDeployment.UID || original.Spec.Replicas == nil || *original.Spec.Replicas != 0 {
		t.Fatal("original inert worker unavailable", err)
	}
	// Register cleanup before the one permitted launch. It uses normal foreground
	// GC under the existing guard, with original UID and no finalizer removal.
	defer providerWorkerNativeCleanup(t, api, original)
	expected := providerWorkerExpectedOwner(t, ctx, api, inventory, input)
	witness := newProviderWorkerWitness(t, ctx, config, input, providers)
	defer witness.close()
	finish := providers.trace.phase(t, "actual-provider-worker-complete-launch")
	launched, err := inputs.CompleteLaunch(ctx)
	finish()
	if err != nil || launched.Progress != kube.ConfigurationWorkerLaunchAcknowledged || launched.Snapshot.State.Launch == nil || launched.Snapshot.State.Launch.Receipt == nil {
		t.Fatal("single original worker launch did not acknowledge", err)
	}
	launch := launched.Snapshot.State.Launch
	if launch.Sources.DeploymentUID != inventory.WorkerDeployment.UID {
		t.Fatal("launch receipt changed original worker")
	}
	current, err := api.AppsV1().Deployments(original.Namespace).Get(ctx, original.Name, meta.GetOptions{})
	want := original.DeepCopy()
	want.Spec.Replicas = ptr.To(int32(1))
	if err != nil || current.UID != original.UID || !reflect.DeepEqual(current.Spec, want.Spec) || current.Generation != original.Generation+1 {
		t.Fatal("actual one-use launch changed original template", err)
	}
	pin, err := kube.ConnectorAPITemplateDigest(original.Spec.Template)
	if err != nil {
		t.Fatal("original full worker template", err)
	}
	selector := labels.SelectorFromSet(original.Spec.Selector.MatchLabels).String()
	var pod *core.Pod
	var replica types.UID
	var imageID string
	awaitProviderWorker(t, ctx, 45*time.Second, "original runtime process", func(call context.Context) bool {
		list, e := api.CoreV1().Pods(original.Namespace).List(call, meta.ListOptions{LabelSelector: selector, Limit: 3})
		if e != nil {
			return false
		}
		if list.Continue != "" || len(list.Items) > 1 {
			t.Fatal("worker acquired unexpected Pod population")
		}
		if len(list.Items) != 1 {
			return false
		}
		v := &list.Items[0]
		if pod != nil && v.UID != pod.UID {
			t.Fatal("worker replaced original admitted Pod")
		}
		owner := meta.GetControllerOf(v)
		if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != apps.SchemeGroupVersion.String() {
			t.Fatal("worker Pod has no exact ReplicaSet")
		}
		rs, e := api.AppsV1().ReplicaSets(original.Namespace).Get(call, owner.Name, meta.GetOptions{})
		if e != nil {
			return false
		}
		controller := meta.GetControllerOf(rs)
		if rs.UID != owner.UID || controller == nil || controller.UID != original.UID || controller.Name != original.Name || controller.Kind != "Deployment" || controller.APIVersion != apps.SchemeGroupVersion.String() {
			t.Fatal("worker controller chain changed")
		}
		if replica != "" && replica != rs.UID {
			t.Fatal("worker replaced original ReplicaSet")
		}
		template := rs.Spec.Template.DeepCopy()
		hash := template.Labels[apps.DefaultDeploymentUniqueLabelKey]
		if hash == "" || v.Labels[apps.DefaultDeploymentUniqueLabelKey] != hash || !maps.Equal(v.Annotations, template.Annotations) || !maps.Equal(v.Labels, template.Labels) {
			t.Fatal("worker Pod metadata changed")
		}
		delete(template.Labels, apps.DefaultDeploymentUniqueLabelKey)
		got, e := kube.ConnectorAPITemplateDigest(*template)
		if e != nil || got != pin {
			t.Fatal("worker ReplicaSet template changed", e)
		}
		// Clear only actual scheduler placement; the maintained digest validates all
		// original security fields and its three documented Pod scalar defaults.
		native := core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: maps.Clone(v.Labels), Annotations: maps.Clone(v.Annotations)}, Spec: *v.Spec.DeepCopy()}
		delete(native.Labels, apps.DefaultDeploymentUniqueLabelKey)
		native.Spec.NodeName = ""
		got, e = kube.ConnectorAPITemplateDigest(native)
		if e != nil || got != pin {
			t.Fatal("worker Pod template changed", e)
		}
		account, e := api.CoreV1().ServiceAccounts(original.Namespace).Get(call, v.Spec.ServiceAccountName, meta.GetOptions{})
		if e != nil || string(account.UID) != inventory.WorkerAccount.UID || account.Name != inventory.WorkerAccount.Name {
			t.Fatal("worker account replaced", e)
		}
		pod, replica = v.DeepCopy(), rs.UID
		if len(v.Status.ContainerStatuses) != 1 {
			return false
		}
		status := v.Status.ContainerStatuses[0]
		if status.RestartCount != 0 || status.State.Terminated != nil {
			t.Fatal("original worker process exited before acceptance", status.RestartCount, status.State.Terminated)
		}
		if status.State.Running == nil || status.ImageID == "" {
			return false
		}
		if !strings.Contains(original.Spec.Template.Spec.Containers[0].Image, "@sha256:") || !strings.HasSuffix(status.ImageID, "sha256:"+strings.Split(original.Spec.Template.Spec.Containers[0].Image, "@sha256:")[1]) {
			t.Fatal("worker imageID differs from compiled original image")
		}
		imageID = status.ImageID
		return true
	})
	t.Logf("original worker deployment=%s replicaSet=%s pod=%s imageID=%s template=%s", original.UID, replica, pod.UID, imageID, hex.EncodeToString(pin[:]))
	var observations []fleet.OwnerConfigurationObservation
	var latest fleet.OwnerConfigurationObservation
	awaitProviderWorker(t, ctx, 45*time.Second, "three independently advancing accepted observations", func(call context.Context) bool {
		providerWorkerRequireRunning(t, call, api, pod, imageID)
		v, e := witness.reader.ReadOwnerConfiguration(call)
		if e != nil {
			return false
		}
		if !v.Configuration.Equal(expected) || !v.Valid(time.Now()) {
			t.Fatal("accepted owner source changed original configuration")
		}
		if !latest.ObservedAt.IsZero() && !v.ObservedAt.After(latest.ObservedAt) {
			return false
		}
		if err := witness.verifyAudit(call, v.Configuration); err != nil {
			t.Fatal("original versioned encrypted audit readback", err)
		}
		providerWorkerRequireRunning(t, call, api, pod, imageID)
		if !v.Valid(time.Now()) {
			t.Fatal("accepted observation expired through independent audit readback and process check")
		}
		latest = v
		observations = append(observations, v)
		t.Logf("accepted owner observed=%s until=%s remaining=%s", v.ObservedAt.Format(time.RFC3339Nano), v.FreshUntil.Format(time.RFC3339Nano), time.Until(v.FreshUntil))
		return len(observations) == 3
	})
	providerWorkerRequireRunning(t, ctx, api, pod, imageID)
	if owner != nil {
		defer owner.cleanup(t, api)
		owner.qualify(t, ctx, api, config, inventory, input, launched.Snapshot, providers, witness, pod, imageID)
		providerWorkerRequireRunning(t, ctx, api, pod, imageID)
	}
	before, err := witness.history(ctx)
	if err != nil {
		t.Fatal("exact pre-failure history", err)
	}
	binding, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, input.OwnerGuard.Name, meta.GetOptions{})
	if err != nil || string(binding.UID) != input.OwnerGuard.BindingUID {
		t.Fatal("original source binding unavailable", err)
	}
	if err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, binding.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &binding.UID}}); err != nil {
		t.Fatal("source-unavailable injection", err)
	}
	// This waits only for expiry of the already observed original interval.
	// No API source update or renewed observation is supplied by the host.
	awaitProviderWorker(t, ctx, 8*time.Second, "original accepted source expired", func(call context.Context) bool {
		if time.Now().Before(latest.FreshUntil) {
			return false
		}
		_, e := witness.reader.ReadOwnerConfiguration(call)
		return e != nil
	})
	after, err := witness.history(ctx)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("source loss changed original audit history", err)
	}
	// Source unavailability normally leaves observation loops alive. Another
	// independently failed child can stop the process first. Observe that state
	// before deleting the Lease, and never attribute an earlier exit to it.
	prior := providerWorkerOriginalExit(t, ctx, api, pod, imageID)
	if prior != nil {
		if prior.ExitCode == 0 {
			t.Fatal("unavailable runtime reported successful process exit")
		}
		t.Logf("original worker exited before Lease injection: exit=%d reason=%s finished=%s; Lease-loss exit not qualified", prior.ExitCode, prior.Reason, prior.FinishedAt.UTC().Format(time.RFC3339Nano))
	} else {
		lease, err := api.CoordinationV1().Leases(original.Namespace).Get(ctx, input.LeaderLease.Name, meta.GetOptions{})
		if err != nil || string(lease.UID) != input.LeaderLease.UID {
			t.Fatal("original scheduling Lease unavailable", err)
		}
		injectedAt := time.Now()
		if err = api.CoordinationV1().Leases(original.Namespace).Delete(ctx, lease.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &lease.UID}}); err != nil {
			t.Fatal("original Lease loss", err)
		}
		awaitProviderWorker(t, ctx, 20*time.Second, "original process exit after Lease deletion", func(call context.Context) bool {
			state := providerWorkerOriginalExit(t, call, api, pod, imageID)
			if state == nil {
				return false
			}
			if state.ExitCode == 0 {
				t.Fatal("unavailable runtime reported successful process exit")
			}
			// Kubernetes timestamps may have only second precision. They cannot
			// identify which child failed; report the observed ordering explicitly.
			t.Logf("original worker exit observed after Lease deletion: exit=%d reason=%s finished=%s deletion-start=%s; no internal cause attribution", state.ExitCode, state.Reason, state.FinishedAt.UTC().Format(time.RFC3339Nano), injectedAt.UTC().Format(time.RFC3339Nano))
			return true
		})
		if _, err = api.CoordinationV1().Leases(original.Namespace).Get(ctx, lease.Name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatal("worker recreated missing original Lease", err)
		}
	}
	t.Log("actual original product Pod and one-use launch, three advancing SQL29 observations with pinned encrypted audit; source loss expired authority without changing history; exact nonzero process exit observed separately; no host runtime token, SQL acceptance write, owner launch or active capacity/cleanup qualification")
}

// This reads only the originally admitted Pod. A replacement or a later process
// is never accepted as proof for it. LastTerminationState is used solely to
// witness the first original exit when kubelet has already scheduled a restart.
func providerWorkerOriginalExit(t *testing.T, ctx context.Context, api kubernetes.Interface, original *core.Pod, imageID string) *core.ContainerStateTerminated {
	t.Helper()
	v, err := api.CoreV1().Pods(original.Namespace).Get(ctx, original.Name, meta.GetOptions{})
	if err != nil || v.UID != original.UID || len(v.Status.ContainerStatuses) != 1 {
		t.Fatal("original worker process status unavailable", err)
	}
	status := v.Status.ContainerStatuses[0]
	if status.Name != original.Spec.Containers[0].Name || status.ImageID != imageID || status.RestartCount > 1 {
		t.Fatal("original worker process identity unavailable")
	}
	if status.RestartCount == 1 {
		if status.LastTerminationState.Terminated == nil {
			t.Fatal("first original worker exit unavailable after restart")
		}
		return status.LastTerminationState.Terminated.DeepCopy()
	}
	if status.State.Terminated != nil {
		return status.State.Terminated.DeepCopy()
	}
	if status.State.Running == nil {
		t.Fatal("original worker stopped without a retained exit")
	}
	return nil
}

func providerWorkerRequireRunning(t *testing.T, ctx context.Context, api kubernetes.Interface, original *core.Pod, imageID string) {
	t.Helper()
	if state := providerWorkerOriginalExit(t, ctx, api, original, imageID); state != nil {
		t.Fatal("original worker exited before accepted-source qualification", state.ExitCode, state.Reason)
	}

}

func providerWorkerExpectedOwner(t *testing.T, ctx context.Context, api kubernetes.Interface, inventory kube.InitialRuntimeResourceInventory, input contracts.HubWorkerDeployment) fleet.OwnerConfiguration {
	t.Helper()
	source, err := api.CoreV1().ConfigMaps(inventory.Namespace.Name).Get(ctx, inventory.OwnerSource.Name, meta.GetOptions{})
	if err != nil || string(source.UID) != inventory.OwnerSource.UID || len(source.Data) != 1 {
		t.Fatal("original source value", err)
	}
	raw := []byte(source.Data["owner-pool.json"])
	var wire contracts.OwnerConfiguration
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || wire.Format != contracts.OwnerConfigurationFormat || wire.InstallationID != input.InstallationID || wire.ClusterID != input.ClusterID || wire.Namespace != input.Namespace {
		t.Fatal("original owner source body invalid")
	}
	canonical := jsontext.Value(raw)
	if canonical.Canonicalize() != nil {
		t.Fatal("original owner source canonicalization")
	}
	pool := fleet.OwnerPool{InstallationID: wire.InstallationID, ClusterID: wire.ClusterID, IssuerEpoch: wire.IssuerEpoch, Namespace: wire.Namespace.Name, NamespaceUID: wire.Namespace.UID, Service: wire.Service.Name, ServiceUID: wire.Service.UID, Deployment: wire.Deployment.Name, DeploymentUID: wire.Deployment.UID, ServiceAccount: wire.ServiceAccount.Name, AccountUID: wire.ServiceAccount.UID, Port: wire.Port, NativePort: wire.NativePort, NativeBootstrap: wire.NativeBootstrap, NativeCandidateLimit: wire.NativeCandidateLimit, OperationPort: wire.OperationPort}
	g := input.OwnerGuard
	plan := cfg.ConfigMapAdministration{Name: g.Name, SourceName: input.OwnerSource.Name, ControlNamespace: cfg.NamespaceRef{Name: input.Namespace.Name, UID: input.Namespace.UID}, Administrators: inventory.BridgeAdministration.Owner.Administrators}
	bound, err := json.Marshal(struct {
		Cluster string
		Plan    cfg.ConfigMapAdministration
		Pin     kube.GuardPin
	}{input.ClusterID, plan, kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}})
	if err != nil {
		t.Fatal(err)
	}
	result := fleet.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: input.OwnerSource.UID, Generation: wire.Revision, Digest: sha256.Sum256(canonical)}, ProtectionDigest: artifact.Digest(sha256.Sum256(bound)), Suspended: wire.Suspended, IssuerRoots: wire.IssuerRoots}
	if !result.Valid() || result.Suspended {
		t.Fatal("original complete owner value invalid")
	}
	return result
}

// Polling is solely fixture observation, after original product operations; it
// never retries a CREATE/launch or fills a product limiter before an effect.
func awaitProviderWorker(t *testing.T, parent context.Context, bound time.Duration, label string, check func(context.Context) bool) {
	t.Helper()
	ctx, end := context.WithTimeout(parent, bound)
	defer end()
	for ctx.Err() == nil {
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		ok := check(call)
		cancel()
		if ok {
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal(label, ctx.Err())
}

func providerWorkerNativeCleanup(t *testing.T, api kubernetes.Interface, original *apps.Deployment) {
	t.Helper()
	providerWorkerNativeCleanupAs(t, api, api, original)
}

func providerWorkerNativeCleanupAs(t *testing.T, api, actor kubernetes.Interface, original *apps.Deployment) {
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 60*time.Second)
	defer end()
	err := actor.AppsV1().Deployments(original.Namespace).Delete(ctx, original.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &original.UID}, PropagationPolicy: ptr.To(meta.DeletePropagationForeground)})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Error("original worker foreground deletion", err)
		return
	}
	selector := labels.SelectorFromSet(original.Spec.Selector.MatchLabels).String()
	for ctx.Err() == nil {
		_, de := api.AppsV1().Deployments(original.Namespace).Get(ctx, original.Name, meta.GetOptions{})
		pods, pe := api.CoreV1().Pods(original.Namespace).List(ctx, meta.ListOptions{LabelSelector: selector, Limit: 3})
		replicas, re := api.AppsV1().ReplicaSets(original.Namespace).List(ctx, meta.ListOptions{LabelSelector: selector, Limit: 3})
		if apierrors.IsNotFound(de) && pe == nil && re == nil && len(pods.Items) == 0 && pods.Continue == "" && len(replicas.Items) == 0 && replicas.Continue == "" {
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Error("original guarded worker GC did not join", ctx.Err())
}
