package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// Real loopback TLS qualifies the child object boundary only. Original journal,
// SQL authority, provider credentials and guard facts here are synthetic; this
// is not the full protected publisher or native admission qualification.
func TestOwnerIdentityChildObjectUnknownCreateIsIndependentLookupOnly(t *testing.T) {
	for _, purpose := range []string{"credentials", "configuration"} {
		for _, mode := range []string{"positive", "unknown-create", "wrong-version", "wrong-kind", "changed-child", "extra-key", "replacement-uid", "blocked-original-deadline"} {
			t.Run(purpose+"/"+mode, func(t *testing.T) {
				resources, state, input, a := ownerIdentityActivationFixture(t)
				parent := state.OwnerIdentity
				child := parent.Credentials
				if purpose == "configuration" {
					child = parent.Configuration
				}
				originalReceipt := *child.Receipt
				if mode != "replacement-uid" {
					child.Receipt = nil
				}
				var posts, gets atomic.Int32
				entered, release := make(chan struct{}), make(chan struct{})
				var object any
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						posts.Add(1)
						if mode == "unknown-create" {
							http.Error(w, "unknown", 500)
							return
						}
						permissionReply(w, object)
						return
					}
					if r.Method != http.MethodGet {
						t.Error("unexpected method")
						http.Error(w, "denied", 400)
						return
					}
					gets.Add(1)
					if mode == "blocked-original-deadline" {
						close(entered)
						<-release
					}
					permissionReply(w, object)
				}))
				defer server.Close()
				defer close(release)
				client, e := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, resources.initial.ClusterID, cfg.NamespaceRef{Name: resources.initial.Namespace.Name, UID: resources.initial.Namespace.UID}, time.Now)
				if e != nil {
					t.Fatal(e)
				}
				producer := &OwnerIdentityProjection{root: &OwnerIdentityRoleRoot{resources: resources, bridge: &InitialRuntimeBridge{source: &ConfigurationRoleSource{client: client}}}}
				data := map[string][]byte{"one": []byte("synthetic-secret"), "two": []byte("synthetic-other")}
				object, _, _, e = producer.object(parent, purpose, input, a, data)
				if e != nil {
					t.Fatal(e)
				}
				var metadata *meta.ObjectMeta
				switch typed := object.(type) {
				case *core.Secret:
					metadata = &typed.ObjectMeta
				case *core.ConfigMap:
					metadata = &typed.ObjectMeta
				}
				metadata.UID = types.UID(originalReceipt.Object.UID)
				metadata.ResourceVersion = originalReceipt.ResourceVersion
				switch mode {
				case "wrong-version":
					switch typed := object.(type) {
					case *core.Secret:
						typed.APIVersion = "wrong/v1"
					case *core.ConfigMap:
						typed.APIVersion = "wrong/v1"
					}
				case "wrong-kind":
					switch typed := object.(type) {
					case *core.Secret:
						typed.Kind = "ConfigMap"
					case *core.ConfigMap:
						typed.Kind = "Secret"
					}
				case "changed-child":
					metadata.Annotations[ownerIdentityObjectMarker] = ownerID(8801)
				case "extra-key":
					switch typed := object.(type) {
					case *core.Secret:
						copy := map[string][]byte{}
						for k, b := range typed.Data {
							copy[k] = b
						}
						copy["unexpected"] = []byte("extra")
						typed.Data = copy
					case *core.ConfigMap:
						typed.Data["unexpected"] = "extra"
					}
				case "replacement-uid":
					metadata.UID = types.UID(ownerID(8802))
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if mode == "blocked-original-deadline" {
					short, end := context.WithTimeout(ctx, 40*time.Millisecond)
					defer end()
					finished := make(chan error, 1)
					go func() { _, e := producer.readObject(short, parent, purpose, input, a, data); finished <- e }()
					select {
					case <-entered:
					case <-ctx.Done():
						t.Fatal("read did not enter")
					}
					select {
					case e := <-finished:
						if e == nil {
							t.Fatal("blocked read outlived original bound")
						}
					case <-ctx.Done():
						t.Fatal("read did not join original cancellation")
					}
					if posts.Load() != 0 || gets.Load() != 1 {
						t.Fatal("deadline failure started another effect")
					}
					return
				}
				if mode == "positive" || mode == "unknown-create" {
					e = producer.createObject(ctx, parent, purpose, input, a, data)
					if mode == "positive" && e != nil || mode == "unknown-create" && e == nil {
						t.Fatalf("CREATE result %v", e)
					}
				}
				got, e := producer.readObject(ctx, parent, purpose, input, a, data)
				positive := mode == "positive" || mode == "unknown-create"
				if positive && (e != nil || got.Object != originalReceipt.Object || got.ResourceVersion != originalReceipt.ResourceVersion) {
					t.Fatalf("independent target lookup failed: %v", e)
				}
				if !positive && e == nil {
					t.Fatal("changed target accepted")
				}
				if gets.Load() != 1 || positive && posts.Load() != 1 || !positive && posts.Load() != 0 {
					t.Fatal("lookup repeated CREATE or GET")
				}
			})
		}
	}
}

func TestOwnerIdentityPendingLaunchDoesNotConvertInertOrReplacementIntoCompletion(t *testing.T) {
	fixture := newOwnerIdentityObjectFixture(t)
	state := fixture.state
	state.OwnerLaunch.Receipt = nil
	if !ownerIdentityClaimedLaunchObject(*fixture.deployment, state, fixture.reader.activation.Input) {
		t.Fatal("exact unknown running disposition cannot be inspected")
	}
	original, _ := json.Marshal(fixture.deployment)
	for name, change := range map[string]func(*apps.Deployment){
		"inert":                     func(d *apps.Deployment) { *d.Spec.Replicas = 0 },
		"replacement":               func(d *apps.Deployment) { d.UID = types.UID(ownerID(8811)) },
		"later-generation":          func(d *apps.Deployment) { d.Generation++ },
		"unrelated-operation":       func(d *apps.Deployment) { d.Annotations[ownerIdentityLaunchMarker] = ownerID(8812) },
		"later-controller-revision": func(d *apps.Deployment) { d.Annotations["deployment.kubernetes.io/revision"] = "2" },
		"template-change":           func(d *apps.Deployment) { d.Spec.Template.Spec.Containers[0].Image = "invalid:changed" },
	} {
		t.Run(name, func(t *testing.T) {
			var d apps.Deployment
			if e := json.Unmarshal(original, &d); e != nil {
				t.Fatal(e)
			}
			change(&d)
			if ownerIdentityClaimedLaunchObject(d, state, fixture.reader.activation.Input) {
				t.Fatal("changed running disposition accepted")
			}
		})
	}
}
