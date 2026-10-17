package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"github.com/google/uuid"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// TestInitialRuntimeObjectRoundTripWithRealKubernetes only qualifies fixed inert
// resource CREATE/read/defaulting. Its synthetic source plan and in-memory
// receipts are not installation activation, an admitted effect or current proof.
func TestInitialRuntimeObjectRoundTripWithRealKubernetes(t *testing.T) {
	if os.Getenv("ASSERVAT_RUNTIME_OBJECT_ROUNDTRIP_NATIVE") != "1" {
		t.Skip("requires the owned runtime-object-roundtrip native harness")
	}
	var fixture struct{ Clusters []struct{ Config string } }
	bytes, err := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(bytes, &fixture) != nil || len(fixture.Clusters) != 1 || fixture.Clusters[0].Config == "" {
		t.Fatal("exact single owned API fixture required")
	}
	config, err := clientcmd.BuildConfigFromFlags("", fixture.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, layout := range []string{"legacy", "installed-owner"} {
		t.Run(layout, func(t *testing.T) {
			qualifyInitialRuntimeObjectRoundTrip(t, api, layout == "installed-owner")
		})
	}
}

func qualifyInitialRuntimeObjectRoundTrip(t *testing.T, api rest.Interface, installed bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	encode := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	raw, err := api.Post().AbsPath("/apis/authentication.k8s.io/v1/selfsubjectreviews").MaxRetries(0).Body(encode(auth.SelfSubjectReview{TypeMeta: metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}})).DoRaw(ctx)
	var self auth.SelfSubjectReview
	if err != nil || json.Unmarshal(raw, &self) != nil || self.Status.UserInfo.Username == "" {
		t.Fatal("fixture administrator identity", err)
	}
	installation := uuid.NewString()
	namespace := "runtime-roundtrip-" + strings.ReplaceAll(installation, "-", "")
	ns := core.Namespace{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "latest"}}}
	raw, err = api.Post().AbsPath("/api/v1/namespaces").MaxRetries(0).Body(encode(ns)).DoRaw(ctx)
	if err != nil || json.Unmarshal(raw, &ns) != nil || ns.UID == "" {
		t.Fatal("fixture namespace CREATE", err)
	}
	// Every cleanup targets its acknowledged UID. Reverse order removes the two
	// test admission bindings first; no global policy disablement or force-delete.
	type createdObject struct {
		path string
		uid  types.UID
	}
	created := []createdObject{{"/api/v1/namespaces/" + namespace, ns.UID}}
	t.Cleanup(func() {
		cleanup, end := context.WithTimeout(context.Background(), 45*time.Second)
		defer end()
		for i := len(created) - 1; i >= 0; i-- {
			item := created[i]
			body := encode(metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &item.uid}, PropagationPolicy: ptr.To(metav1.DeletePropagationForeground)})
			_, e := api.Delete().AbsPath(item.path).MaxRetries(0).Body(body).DoRaw(cleanup)
			if e != nil && !apierrors.IsNotFound(e) {
				t.Errorf("cleanup DELETE %s: %v", item.path, e)
				continue
			}
			for {
				_, e = api.Get().AbsPath(item.path).MaxRetries(0).DoRaw(cleanup)
				if apierrors.IsNotFound(e) {
					break
				}
				if e != nil {
					t.Errorf("cleanup GET %s: %v", item.path, e)
					break
				}
				select {
				case <-cleanup.Done():
					t.Errorf("cleanup join %s: %v", item.path, cleanup.Err())
				case <-time.After(50 * time.Millisecond):
					continue
				}
				break
			}
		}
	})
	s, state := initialRuntimeResourceFixture(t)
	if installed {
		// This explicitly selects the fresh builders before any object exists.
		// Synthetic original authority remains limited to object qualification.
		s.workerLayout, s.ownerLayout = contracts.HubWorkerInstalledLayout, contracts.OwnerInstalledLayout
		state.WorkerLayout, state.OwnerLayout = s.workerLayout, s.ownerLayout
	}
	s.initial.InstallationID = installation
	s.preparer.plan.InstallationID = installation
	s.initial.Namespace = contracts.WorkerObjectReference{Name: namespace, UID: string(ns.UID)}
	s.preparer.plan.Workload.Namespace = namespace
	s.preparer.plan.Administrators = []contracts.OwnerDeploymentActor{{Kind: "User", Name: self.Status.UserInfo.Username}}
	s.names = runtimeResourceNames(installation)
	state.Objects = nil
	verify := func(phase string, raw []byte, index int) bool {
		call, end := context.WithTimeout(ctx, 5*time.Second)
		defer end()
		_, e := s.verified(call, raw, state, index)
		if e == nil {
			return true
		}
		want, x := s.object(state, index)
		if x != nil {
			t.Errorf("%s %s: %v", phase, state.Objects[index].Item, e)
			return false
		}
		got := reflect.New(reflect.TypeOf(want.object).Elem()).Interface().(runtime.Object)
		paths := []string{"wire decode"}
		if json.Unmarshal(raw, got) == nil {
			m, _ := meta.Accessor(got)
			m.SetAnnotations(nil)
			_ = normalizeInitialRuntimeObject(got)
			_ = normalizeInitialRuntimeObject(want.object)
			paths = runtimeRoundtripDifferencePaths(encode(want.object), encode(got))
		}
		t.Errorf("%s %s decoder: %v; normalized differing fields=%v", phase, state.Objects[index].Item, e, paths)
		return false
	}
	for index, item := range initialRuntimeResourceItems {
		object, e := s.object(state, index)
		if e != nil {
			t.Fatalf("builder %s: %v", item, e)
		}
		m, e := meta.Accessor(object.object)
		if e != nil {
			t.Fatal(e)
		}
		digest := preparationDigest(object.object)
		now := time.Now().UTC().Truncate(time.Microsecond)
		claim := contracts.InitialRuntimeResourceClaim{Item: item, OperationID: uuid.NewString(), TemplateDigest: digest, ClaimedAt: now, Until: now.Add(5 * time.Second)}
		state.Objects = append(state.Objects, claim)
		m.SetAnnotations(map[string]string{initialRuntimeResourceMarker: claim.OperationID})
		if d, ok := object.object.(*apps.Deployment); ok && (d.Spec.Replicas == nil || *d.Spec.Replicas != 0) {
			t.Fatal("non-inert generated Deployment")
		}
		raw, e = api.Post().AbsPath(object.collection).Param("fieldValidation", "Strict").MaxRetries(0).Body(encode(object.object)).DoRaw(ctx)
		if e != nil {
			t.Fatalf("CREATE %s: %v", item, e)
		}
		got := reflect.New(reflect.TypeOf(object.object).Elem()).Interface().(runtime.Object)
		if json.Unmarshal(raw, got) != nil {
			t.Fatalf("CREATE %s wire", item)
		}
		gm, _ := meta.Accessor(got)
		if gm.GetUID() == "" {
			t.Fatalf("CREATE %s UID", item)
		}
		path := object.collection + "/" + m.GetName()
		created = append(created, createdObject{path, gm.GetUID()})
		verify("CREATE", raw, index)
		// Test-only inventory permits checking all later kinds even when an earlier
		// decoder rejects API defaults. No producer journal or authority is written.
		state.Objects[index].Receipt = &contracts.InitialRuntimeResourceReceipt{UID: string(gm.GetUID()), ResourceVersion: gm.GetResourceVersion(), Generation: gm.GetGeneration()}
		raw, e = api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
		if e != nil {
			t.Fatalf("GET %s: %v", item, e)
		}
		verify("independent GET", raw, index)
		t.Logf("roundtrip item=%s kind=%s original-template=%s", item, object.object.GetObjectKind().GroupVersionKind().Kind, digest)
	}
	// The controller may finish after CREATE/GET. Its first original revision
	// must remain readable without weakening later generation/template checks.
	for _, index := range []int{10, 11} {
		object, _ := s.object(state, index)
		m, _ := meta.Accessor(object.object)
		path := object.collection + "/" + m.GetName()
		wait, end := context.WithTimeout(ctx, 30*time.Second)
		var d apps.Deployment
		for {
			raw, err = api.Get().AbsPath(path).MaxRetries(0).DoRaw(wait)
			if err != nil {
				end()
				t.Fatalf("controller GET %s: %v", state.Objects[index].Item, err)
			}
			if json.Unmarshal(raw, &d) != nil {
				end()
				t.Fatal("controller Deployment wire")
			}
			if d.Annotations["deployment.kubernetes.io/revision"] != "" {
				break
			}
			select {
			case <-wait.Done():
				end()
				t.Fatal("original zero-replica controller revision not observed")
			case <-time.After(100 * time.Millisecond):
			}
		}
		end()
		if d.Annotations["deployment.kubernetes.io/revision"] != "1" || d.Generation != state.Objects[index].Receipt.Generation || d.Spec.Replicas == nil || *d.Spec.Replicas != 0 {
			t.Fatal("controller changed original inert revision/generation/replicas")
		}
		verify("controller original revision", raw, index)
		if installed && index == 10 {
			digest, e := ConnectorAPITemplateDigest(d.Spec.Template)
			if e != nil || digest == (artifact.Digest{}) {
				t.Fatal("actual API installed owner template rejected by native matcher", e)
			}
			if len(d.Spec.Template.Spec.Tolerations) != 2 {
				t.Fatal("actual API owner changed original finite eviction bounds")
			}
			for name, mutate := range map[string]func(*core.PodTemplateSpec){
				"missing eviction bounds":        func(v *core.PodTemplateSpec) { v.Spec.Tolerations = nil },
				"longer eviction bound":          func(v *core.PodTemplateSpec) { *v.Spec.Tolerations[0].TolerationSeconds = 301 },
				"unbounded eviction":             func(v *core.PodTemplateSpec) { v.Spec.Tolerations[0].TolerationSeconds = nil },
				"additional template annotation": func(v *core.PodTemplateSpec) { v.Annotations = map[string]string{"unreviewed": "value"} },
			} {
				bad := d.Spec.Template.DeepCopy()
				mutate(bad)
				got, err := ConnectorAPITemplateDigest(*bad)
				if err == nil && got == digest {
					t.Error("actual API template mutation retained digest", name)
				}
			}
			t.Logf("actual API installed owner template accepted with original digest %x", digest)
		}
		for name, change := range map[string]func(*apps.Deployment){
			"new revision":   func(d *apps.Deployment) { d.Annotations["deployment.kubernetes.io/revision"] = "2" },
			"new generation": func(d *apps.Deployment) { d.Generation++ },
			"new template":   func(d *apps.Deployment) { d.Spec.Template.Spec.Containers[0].Image = "unqualified" },
			"new annotation": func(d *apps.Deployment) { d.Annotations["unqualified"] = "value" },
		} {
			bad := d.DeepCopy()
			change(bad)
			call, stop := context.WithTimeout(ctx, 5*time.Second)
			_, e := s.verified(call, encode(bad), state, index)
			stop()
			if e == nil {
				t.Errorf("actual API response allowed %s", name)
			}
		}
	}
	inventory, err := s.inventory(state)
	if err != nil {
		t.Fatal("actual object receipts cannot reconstruct original inventory", err)
	}
	administration := inventory.BridgeAdministration
	if installed {
		if state.OwnerLayout != contracts.OwnerInstalledLayout || state.WorkerLayout != contracts.HubWorkerInstalledLayout || administration.Owner.CapacityProbe == nil || administration.Owner.CapacityProbe.ServiceAccount != inventory.WorkerAccount.Name || administration.Owner.CapacityProbe.ServiceAccountUID != inventory.WorkerAccount.UID || len(administration.SourceProbes) != 3 || administration.SourceProbes[2].ConfigMap != installedProcessingSource(installation) || administration.SourceProbes[2].ServiceAccountUID != inventory.WorkerAccount.UID {
			t.Fatal("fresh installed inventory lost exact original third probe")
		}
		object, err := s.object(state, 14)
		if err != nil {
			t.Fatal(err)
		}
		var source contracts.OwnerConfiguration
		if json.Unmarshal([]byte(object.object.(*core.ConfigMap).Data["owner-pool.json"]), &source) != nil || source.NativePort != contracts.OwnerInstalledNativePort || source.NativeBootstrap != fleet.OwnerBootstrapProfile || source.Service != inventory.OwnerService || source.ServiceAccount != inventory.OwnerAccount || source.Deployment != inventory.OwnerDeployment {
			t.Fatal("fresh installed source changed original service or identity profile")
		}
	} else if state.OwnerLayout != "" || state.WorkerLayout != "" || administration.Owner.CapacityProbe != nil || len(administration.SourceProbes) != 2 {
		t.Fatal("legacy roundtrip acquired fresh installed fields")
	}
	// Re-read all acknowledged originals after both policies/controllers run.
	for index := range initialRuntimeResourceItems {
		object, _ := s.object(state, index)
		m, _ := meta.Accessor(object.object)
		raw, err = api.Get().AbsPath(object.collection + "/" + m.GetName()).MaxRetries(0).DoRaw(ctx)
		if err != nil {
			t.Fatalf("final GET %s: %v", state.Objects[index].Item, err)
		}
		verify("final original GET", raw, index)
	}
	raw, err = api.Get().AbsPath("/api/v1/namespaces/" + namespace + "/pods").MaxRetries(0).DoRaw(ctx)
	var pods core.PodList
	if err != nil || json.Unmarshal(raw, &pods) != nil || len(pods.Items) != 0 {
		t.Fatal("inert roundtrip created a Pod", err)
	}
	t.Logf("All 19 fixed objects round-tripped through the real API (installed-owner=%t); both Deployments stayed at zero; no activation/provider/runtime authority tested.", installed)
}

func runtimeRoundtripDifferencePaths(want, got []byte) []string {
	var a, b any
	_ = json.Unmarshal(want, &a)
	_ = json.Unmarshal(got, &b)
	var paths []string
	var walk func(string, any, any)
	walk = func(path string, a, b any) {
		if reflect.DeepEqual(a, b) {
			return
		}
		am, ao := a.(map[string]any)
		bm, bo := b.(map[string]any)
		if ao && bo {
			keys := map[string]bool{}
			for k := range am {
				keys[k] = true
			}
			for k := range bm {
				keys[k] = true
			}
			for k := range keys {
				walk(path+"."+k, am[k], bm[k])
			}
			return
		}
		aa, ao := a.([]any)
		bb, bo := b.([]any)
		if ao && bo && len(aa) == len(bb) {
			for i := range aa {
				walk(fmt.Sprintf("%s[%d]", path, i), aa[i], bb[i])
			}
			return
		}
		paths = append(paths, path)
	}
	walk("$", a, b)
	sort.Strings(paths)
	if len(paths) > 32 {
		paths = paths[:32]
	}
	return paths
}
