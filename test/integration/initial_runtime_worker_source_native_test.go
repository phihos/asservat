package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

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
