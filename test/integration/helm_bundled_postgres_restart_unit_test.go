package integration

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Exercise the actual client, metadata negotiation and UID-preconditioned DELETE
// on a private TLS API. No SQL responder pretends to prove product reactivation.
func TestHelmBundledPostgresRestartReadsPinsAndDeletesOnlyOriginalPod(t *testing.T) {
	f := newBundledPostgresRestartAPI(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	before, err := readBundledPostgresKubernetes(ctx, f.api, f.plan, f.image)
	if err != nil {
		t.Fatal(err)
	}
	if before.PodUID != "original-pod" || before.StateSecretUID != "original-state" || before.DataPVCUID != "original-data" || before.BackupPVCUID != "original-backup" {
		t.Fatal("missing original retained UIDs")
	}
	if err = deleteBundledPostgresPod(ctx, f.api, before); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	deletes := f.deletes
	f.pod.UID = "replacement-pod"
	f.mu.Unlock()
	after, err := readBundledPostgresKubernetes(ctx, f.api, f.plan, f.image)
	if err != nil || unchangedBundledPostgresKubernetes(before, after) != nil || after.PodUID == before.PodUID || deletes != 1 {
		t.Fatal("same StatefulSet replacement was not distinguished", err, deletes)
	}
	f.mu.Lock()
	f.state.UID = "replacement-state"
	f.mu.Unlock()
	changed, err := readBundledPostgresKubernetes(ctx, f.api, f.plan, f.image)
	if err != nil || unchangedBundledPostgresKubernetes(before, changed) == nil {
		t.Fatal("replaced original private state accepted", err)
	}
}

func TestHelmBundledPostgresRestartRejectsRetainedSourceChangesBeforeDeletion(t *testing.T) {
	for _, change := range []string{"owner", "image", "data-volume", "secret-reference", "state-missing", "pvc-missing", "pvc-replaced"} {
		t.Run(change, func(t *testing.T) {
			f := newBundledPostgresRestartAPI(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			before, err := readBundledPostgresKubernetes(ctx, f.api, f.plan, f.image)
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			switch change {
			case "owner":
				f.pod.OwnerReferences[0].UID = "foreign-controller"
			case "image":
				f.pod.Spec.Containers[0].Image = "other-image"
			case "data-volume":
				f.sts.Spec.Template.Spec.Volumes[0].PersistentVolumeClaim.ClaimName = "other-pvc"
			case "secret-reference":
				f.pod.Spec.Volumes[2].Secret.SecretName = "other-secret"
			case "state-missing":
				f.missing = "/secrets/" + f.plan.StateSecretName()
			case "pvc-missing":
				f.missing = "/persistentvolumeclaims/" + f.plan.DataPVCName()
			case "pvc-replaced":
				f.pvcs[f.plan.DataPVCName()].UID = "replacement-data"
			}
			f.mu.Unlock()
			after, err := readBundledPostgresKubernetes(ctx, f.api, f.plan, f.image)
			if err == nil && unchangedBundledPostgresKubernetes(before, after) == nil {
				t.Fatal("changed retained source accepted")
			}
			if errors.Is(err, errBundledPostgresPodPending) {
				t.Fatal("changed source classified as temporary Pod readiness")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.deletes != 0 {
				t.Fatal("observation mutated resources")
			}
		})
	}
}

func TestHelmBundledPostgresRestartUnknownDeleteIsNotReplayed(t *testing.T) {
	f := newBundledPostgresRestartAPI(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	before, err := readBundledPostgresKubernetes(ctx, f.api, f.plan, f.image)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.deleteUnknown = true
	f.mu.Unlock()
	if deleteBundledPostgresPod(ctx, f.api, before) == nil {
		t.Fatal("unknown deletion reported acknowledged")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deletes != 1 {
		t.Fatal("unknown mutation retried", f.deletes)
	}
}
func TestHelmBundledPostgresRestartUIDPreconditionProtectsReplacement(t *testing.T) {
	f := newBundledPostgresRestartAPI(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	before, err := readBundledPostgresKubernetes(ctx, f.api, f.plan, f.image)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.pod.UID = "replacement-pod"
	f.mu.Unlock()
	if deleteBundledPostgresPod(ctx, f.api, before) == nil {
		t.Fatal("replacement Pod deleted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deletes != 1 || f.effects != 0 {
		t.Fatal("replacement Pod affected", f.deletes, f.effects)
	}
}
func TestHelmBundledPostgresRestartCancellationHasNoDelete(t *testing.T) {
	f := newBundledPostgresRestartAPI(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if deleteBundledPostgresPod(ctx, f.api, bundledPostgresKubernetesSnapshot{Namespace: f.plan.Namespace, PodName: f.pod.Name, PodUID: f.pod.UID}) == nil {
		t.Fatal("canceled operation mutated")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deletes != 0 {
		t.Fatal("canceled mutation reached API")
	}
}

type bundledPostgresRestartAPI struct {
	mu            sync.Mutex
	plan          contracts.SmallPostgresPlan
	image         string
	api           *kubernetes.Clientset
	sts           *apps.StatefulSet
	pod           *core.Pod
	state         *meta.PartialObjectMetadata
	pvcs          map[string]*core.PersistentVolumeClaim
	missing       string
	deletes       int
	effects       int
	deleteUnknown bool
}

func newBundledPostgresRestartAPI(t *testing.T) *bundledPostgresRestartAPI {
	t.Helper()
	f := &bundledPostgresRestartAPI{plan: contracts.SmallPostgresPlan{Format: contracts.SmallPostgresFormat, Namespace: "restart-test", Name: "trial"}, image: "registry.example/postgres@sha256:" + strings.Repeat("a", 64), pvcs: map[string]*core.PersistentVolumeClaim{}}
	spec := core.PodSpec{Containers: []core.Container{{Name: "postgres", Image: f.image}, {Name: "backup", Image: f.image}}, Volumes: []core.Volume{
		{Name: "data", VolumeSource: core.VolumeSource{PersistentVolumeClaim: &core.PersistentVolumeClaimVolumeSource{ClaimName: f.plan.DataPVCName()}}},
		{Name: "backup", VolumeSource: core.VolumeSource{PersistentVolumeClaim: &core.PersistentVolumeClaimVolumeSource{ClaimName: f.plan.BackupPVCName()}}},
		{Name: "server-material", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: f.plan.StateSecretName()}}},
		{Name: "backup-material", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: f.plan.StateSecretName()}}},
	}}
	f.sts = &apps.StatefulSet{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "StatefulSet"}, ObjectMeta: meta.ObjectMeta{Name: f.plan.ServiceName(), Namespace: f.plan.Namespace, UID: "original-sts", Generation: 1}, Spec: apps.StatefulSetSpec{Replicas: ptr.To(int32(1)), ServiceName: f.plan.ServiceName(), Template: core.PodTemplateSpec{Spec: spec}}}
	f.pod = &core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: f.plan.ServiceName() + "-0", Namespace: f.plan.Namespace, UID: "original-pod", OwnerReferences: []meta.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: f.sts.Name, UID: f.sts.UID, Controller: ptr.To(true)}}}, Spec: *spec.DeepCopy(), Status: core.PodStatus{Phase: core.PodRunning, Conditions: []core.PodCondition{{Type: core.PodReady, Status: core.ConditionTrue}}, ContainerStatuses: []core.ContainerStatus{{Name: "postgres", Ready: true, State: core.ContainerState{Running: &core.ContainerStateRunning{}}}, {Name: "backup", Ready: true, State: core.ContainerState{Running: &core.ContainerStateRunning{}}}}}}
	f.state = &meta.PartialObjectMetadata{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: meta.ObjectMeta{Name: f.plan.StateSecretName(), Namespace: f.plan.Namespace, UID: "original-state", ResourceVersion: "1", Labels: map[string]string{"asservat.io/private-role": "small-postgres"}}}
	for i, name := range []string{f.plan.DataPVCName(), f.plan.BackupPVCName()} {
		uid := types.UID("original-data")
		if i == 1 {
			uid = "original-backup"
		}
		f.pvcs[name] = &core.PersistentVolumeClaim{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: f.plan.Namespace, UID: uid}, Spec: core.PersistentVolumeClaimSpec{VolumeName: "volume-" + name}, Status: core.PersistentVolumeClaimStatus{Phase: core.ClaimBound}}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if f.missing != "" && strings.HasSuffix(r.URL.Path, f.missing) {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Reason: meta.StatusReasonNotFound, Code: 404})
			return
		}
		if r.Method == http.MethodDelete && r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace+"/pods/"+f.pod.Name {
			f.deletes++
			var opts meta.DeleteOptions
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			if json.Unmarshal(raw, &opts) != nil || opts.Preconditions == nil || opts.Preconditions.UID == nil || *opts.Preconditions.UID != "original-pod" || opts.GracePeriodSeconds != nil || opts.PropagationPolicy != nil || opts.OrphanDependents != nil || r.URL.RawQuery != "" {
				t.Error("Pod deletion did not retain exact original UID and normal grace")
			}
			if opts.Preconditions != nil && opts.Preconditions.UID != nil && *opts.Preconditions.UID != f.pod.UID {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Reason: meta.StatusReasonConflict, Code: 409})
				return
			}
			f.effects++
			if f.deleteUnknown {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(500)
				_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Reason: meta.StatusReasonInternalError, Code: 500})
				return
			}
			_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Success", Code: 200})
			return
		}
		if r.Method != http.MethodGet {
			t.Error("unexpected mutating API request")
			w.WriteHeader(403)
			return
		}
		var object any
		switch r.URL.Path {
		case "/apis/apps/v1/namespaces/" + f.plan.Namespace + "/statefulsets/" + f.sts.Name:
			object = f.sts
		case "/api/v1/namespaces/" + f.plan.Namespace + "/pods/" + f.pod.Name:
			object = f.pod
		case "/api/v1/namespaces/" + f.plan.Namespace + "/secrets/" + f.plan.StateSecretName():
			if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1" {
				t.Error("private Secret payload requested")
			}
			object = f.state
		default:
			for name, pvc := range f.pvcs {
				if r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace+"/persistentvolumeclaims/"+name {
					object = pvc
				}
			}
		}
		if object == nil {
			t.Error("unexpected API path")
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(object)
	}))
	t.Cleanup(server.Close)
	cert := server.Certificate()
	config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})}}
	var err error
	f.api, err = kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestHelmBundledPostgresRestartUncordonExactOriginalNode(t *testing.T) {
	for _, mode := range []string{"cordoned", "already-schedulable", "wrong-uid", "unknown-update"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			updates := 0
			original := core.Node{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Node"}, ObjectMeta: meta.ObjectMeta{Name: "original-node", UID: "original-node-uid", ResourceVersion: "17", Labels: map[string]string{"keep": "original"}, Annotations: map[string]string{"keep": "annotation"}}, Spec: core.NodeSpec{Unschedulable: mode != "already-schedulable", ProviderID: "original-provider", Taints: []core.Taint{{Key: "keep", Value: "original", Effect: core.TaintEffectPreferNoSchedule}}}, Status: core.NodeStatus{Addresses: []core.NodeAddress{{Type: core.NodeInternalIP, Address: "192.0.2.1"}}}}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/api/v1/nodes/original-node" {
					t.Error("another node selected")
					w.WriteHeader(404)
					return
				}
				switch r.Method {
				case http.MethodGet:
					_ = json.NewEncoder(w).Encode(original)
				case http.MethodPut:
					updates++
					var got core.Node
					raw, _ := io.ReadAll(io.LimitReader(r.Body, 32<<10))
					want := original.DeepCopy()
					want.Spec.Unschedulable = false
					if json.Unmarshal(raw, &got) != nil || !reflect.DeepEqual(*want, got) || got.ResourceVersion != "17" || got.UID != original.UID {
						t.Error("uncordon changed fields beyond the original scheduling flag/optimistic version")
					}
					if mode == "unknown-update" {
						w.Header().Set("Retry-After", "0")
						w.WriteHeader(500)
						_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Reason: meta.StatusReasonInternalError, Code: 500})
						return
					}
					got.ResourceVersion = "18"
					_ = json.NewEncoder(w).Encode(got)
				default:
					t.Error("unexpected node mutation")
					w.WriteHeader(403)
				}
			}))
			defer server.Close()
			api, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			uid := string(original.UID)
			if mode == "wrong-uid" {
				uid = "replacement-node-uid"
			}
			err = uncordonHelmBundledPostgresNode(ctx, api, original.Name, uid)
			wantErr := mode == "wrong-uid" || mode == "unknown-update"
			if (err != nil) != wantErr {
				t.Fatal("unexpected uncordon result", mode, err)
			}
			wantUpdates := 1
			if mode == "wrong-uid" || mode == "already-schedulable" {
				wantUpdates = 0
			}
			mu.Lock()
			defer mu.Unlock()
			if updates != wantUpdates {
				t.Fatal("node mutation repeated or performed without original identity", updates, wantUpdates)
			}
		})
	}
}
