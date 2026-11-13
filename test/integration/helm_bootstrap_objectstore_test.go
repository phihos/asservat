package integration

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

type helmOriginalStorage struct {
	installation string
	request      string
	seedUID      types.UID
	credential   contracts.OwnerStorageCredential
	err          error
}

type helmBundledObjectStore struct {
	plan                         contracts.SmallSeaweedPlan
	storage                      chan helmOriginalStorage
	stateUID, iamUID, bindingUID types.UID
	seedUID                      types.UID
	installation                 string
	iamVersion, bindingVersion   string
	iamData                      []byte
	bindingData                  string
}

// This is fixture storage administration inside the owned Kind node only. A
// static local PV avoids installing another storage operator. Its advertised
// size is configuration, not a measured capacity or durability guarantee.
func newHelmBundledObjectStore(t *testing.T, ctx context.Context, api kubernetes.Interface, d contracts.InitialBootstrap, x helmBootstrapFixture) *helmBundledObjectStore {
	t.Helper()
	p := contracts.SmallSeaweedPlan{Format: contracts.SmallSeaweedFormat, Namespace: d.BootstrapNamespace, Name: d.Name, Image: x.ObjectStoreImage}
	if !p.Valid() {
		t.Fatal("selected actual chart object-store image unavailable")
	}
	node, err := api.CoreV1().Nodes().Get(ctx, x.NodeA, meta.GetOptions{})
	if err != nil || string(node.UID) != x.NodeAUID || node.Labels[core.LabelHostname] == "" {
		t.Fatal("owned PV node changed", err)
	}
	directory := "/var/local/asservat-bundled-s3/" + p.Namespace + "/" + p.Name
	output, err := exec.CommandContext(ctx, "docker", "exec", x.NodeA, "install", "-d", "-m", "0700", "-o", "65532", "-g", "65532", directory).CombinedOutput()
	if err != nil {
		t.Fatalf("owned node backing directory: %v %s", err, output)
	}
	pvName := p.Namespace + "-objectstore"
	volume, err := api.CoreV1().PersistentVolumes().Create(ctx, &core.PersistentVolume{ObjectMeta: meta.ObjectMeta{Name: pvName, Labels: map[string]string{"asservat.test.owner": p.Namespace}}, Spec: core.PersistentVolumeSpec{Capacity: core.ResourceList{core.ResourceStorage: resource.MustParse("32Gi")}, AccessModes: []core.PersistentVolumeAccessMode{core.ReadWriteOnce}, PersistentVolumeReclaimPolicy: core.PersistentVolumeReclaimRetain, StorageClassName: "asservat-owned-local", ClaimRef: &core.ObjectReference{Namespace: p.Namespace, Name: p.DataPVCName()}, PersistentVolumeSource: core.PersistentVolumeSource{Local: &core.LocalVolumeSource{Path: directory}}, NodeAffinity: &core.VolumeNodeAffinity{Required: &core.NodeSelector{NodeSelectorTerms: []core.NodeSelectorTerm{{MatchExpressions: []core.NodeSelectorRequirement{{Key: core.LabelHostname, Operator: core.NodeSelectorOpIn, Values: []string{node.Labels[core.LabelHostname]}}}}}}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("owned empty static local PV", err)
	}
	t.Cleanup(func() {
		if keepFailedFixture(t) {
			return
		}
		cleanup, end := context.WithTimeout(context.Background(), 60*time.Second)
		defer end()
		got, e := api.CoreV1().PersistentVolumes().Get(cleanup, pvName, meta.GetOptions{})
		if apierrors.IsNotFound(e) {
			return
		}
		if e != nil || got.UID != volume.UID || got.Labels["asservat.test.owner"] != p.Namespace {
			t.Error("owned local PV cleanup identity", e)
			return
		}
		if e = api.CoreV1().PersistentVolumes().Delete(cleanup, pvName, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &volume.UID}}); e != nil && !apierrors.IsNotFound(e) {
			t.Error("owned local PV cleanup", e)
		}
	})
	b := &helmBundledObjectStore{plan: p, storage: make(chan helmOriginalStorage, 1)}
	observer, cancel := context.WithCancel(ctx)
	list, err := api.CoreV1().Secrets(p.Namespace).List(observer, meta.ListOptions{FieldSelector: "metadata.name=" + p.Name + "-bootstrap-state", Limit: 2})
	if err != nil || len(list.Items) != 0 || list.ResourceVersion == "" {
		cancel()
		t.Fatal("original generated-key observation requires fresh absence", err)
	}
	stream, err := api.CoreV1().Secrets(p.Namespace).Watch(observer, meta.ListOptions{FieldSelector: "metadata.name=" + p.Name + "-bootstrap-state", ResourceVersion: list.ResourceVersion})
	if err != nil {
		cancel()
		t.Fatal("original generated-key watch", err)
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		defer stream.Stop()
		for events := 0; events < 128; events++ {
			select {
			case <-observer.Done():
				return
			case event, ok := <-stream.ResultChan():
				if !ok || event.Type == watch.Error || event.Type == watch.Deleted {
					b.storage <- helmOriginalStorage{err: errors.New("original generated-key event unavailable")}
					return
				}
				secret, ok := event.Object.(*core.Secret)
				if !ok {
					continue
				}
				state, e := contracts.DecodeInitialBootstrapState(bytes.NewReader(secret.Data["state.json"]))
				for _, raw := range secret.Data {
					clear(raw)
				}
				if e != nil {
					b.storage <- helmOriginalStorage{err: errors.New("original generated-key state invalid")}
					return
				}
				if state.Material == nil || state.Material.Storage.AccessKeyID == "" {
					continue
				}
				c := state.Material.Storage
				bound := contracts.SeaweedCredential{Principal: contracts.SeaweedPrincipalKey{Purpose: "initial-audit", ScopeID: state.InstallationID}, AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey}
				if c.SessionToken != "" || providerconfig.ValidateSeaweedCredential(bound) != nil {
					b.storage <- helmOriginalStorage{err: errors.New("original stored credential was not generated and scoped")}
					return
				}
				b.storage <- helmOriginalStorage{installation: state.InstallationID, request: state.RequestID, seedUID: secret.UID, credential: c}
				return
			}
		}
		b.storage <- helmOriginalStorage{err: errors.New("original generated-key event bound exhausted")}
	}()
	t.Cleanup(func() { cancel(); stream.Stop(); <-joined; clear(b.iamData) })
	return b
}

func (b *helmBundledObjectStore) Values(values map[string]any) {
	services, ok := values["services"].(map[string]any)
	if !ok {
		services = map[string]any{}
		values["services"] = services
	}
	services["objectStore"] = map[string]any{"provider": "seaweedfs", "seaweedfs": map[string]any{"image": b.plan.Image, "persistence": map[string]any{"storageClass": "asservat-owned-local", "size": "32Gi"}}}
}
