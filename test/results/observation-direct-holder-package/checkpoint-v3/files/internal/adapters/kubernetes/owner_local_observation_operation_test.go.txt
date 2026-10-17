package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Concrete readers and real HTTPS; API objects/TokenReviews are synthetic. No
// installation authorization or sustained native five-second result is implied.
type ownerLocalNativeFixture struct {
	base                          *ownerOperationFixture
	mu                            sync.Mutex
	pin                           value.ClusterObservationCallerPin
	deploy                        apps.Deployment
	rs                            apps.ReplicaSet
	pod                           core.Pod
	account                       core.ServiceAccount
	reader                        *OwnerLocalObservationOperationReader
	token                         []byte
	revoke, changedPod            bool
	reviews, pods                 int
	block                         bool
	entered, handlerDone, release chan struct{}
	once, releaseOnce             sync.Once
}

func newOwnerLocalNativeFixture(t *testing.T) *ownerLocalNativeFixture {
	base := newOwnerOperationFixture(t)
	d, rs, pod, image := connectorAPITemplateFixture()
	md := func(name string, n int) meta.ObjectMeta {
		return meta.ObjectMeta{Name: name, Namespace: base.v.pool.Namespace, UID: types.UID(ownerID(n)), ResourceVersion: "10"}
	}
	d.TypeMeta = meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}
	d.ObjectMeta = md("hwork", 50)
	d.Spec.Replicas = ptr.To(int32(1))
	d.Spec.Selector = &meta.LabelSelector{MatchLabels: map[string]string{"app": "connector"}}
	rs.TypeMeta = meta.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"}
	rs.ObjectMeta = md("hwork-rs", 51)
	rs.Spec.Replicas = ptr.To(int32(1))
	rs.OwnerReferences = []meta.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: d.Name, UID: d.UID, Controller: ptr.To(true)}}
	pod.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}
	pod.ObjectMeta.Name = "hwork-rs-pod"
	pod.Namespace = base.v.pool.Namespace
	pod.UID = types.UID(ownerID(52))
	pod.ResourceVersion = "10"
	pod.Status.Phase = core.PodRunning
	pod.OwnerReferences = []meta.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: ptr.To(true)}}
	account := core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: md("connector", 53)}
	template, err := ConnectorAPITemplateDigest(d.Spec.Template)
	if err != nil {
		t.Fatal(err)
	}
	f := &ownerLocalNativeFixture{base: base, deploy: d, rs: rs, pod: pod, account: account, entered: make(chan struct{}), handlerDone: make(chan struct{}), release: make(chan struct{})}
	f.pin = value.ClusterObservationCallerPin{RootID: base.pin.RootID, InstallationID: base.v.pool.InstallationID, ClusterID: base.v.pool.ClusterID, Namespace: base.guard.plan.ControlNamespace, Account: account.Name, AccountUID: string(account.UID), Deployment: d.Name, DeploymentUID: string(d.UID), TemplateDigest: template, ImageDigest: image, ProtectionDigest: base.pin.ProtectionDigest}
	claims, _ := json.Marshal(map[string]int64{"iat": base.start.Add(-time.Second).Unix(), "exp": base.start.Add(time.Minute).Unix()})
	f.token = []byte("e30." + base64.RawURLEncoding.EncodeToString(claims) + ".synthetic")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" && r.URL.Path != "/api/v1/namespaces/owners/serviceaccounts/connector" && r.URL.Path != "/apis/apps/v1/namespaces/owners/deployments/hwork" && r.URL.Path != "/apis/apps/v1/namespaces/owners/replicasets/hwork-rs" && r.URL.Path != "/api/v1/namespaces/owners/pods/hwork-rs-pod" {
			base.serve(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer observer" {
			t.Error("caller token used as API credential")
		}
		base.observer.Add(1)
		// Consume the actual bounded TokenReview before holding its response.
		// An unread HTTP/1 request body can prevent the server from observing
		// peer cancellation; that server notification is not owned client work.
		var q auth.TokenReview
		if r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews" {
			if json.NewDecoder(r.Body).Decode(&q) != nil || q.Spec.Token != string(f.token) || len(q.Spec.Audiences) != 1 || q.Spec.Audiences[0] != value.ClusterObservationAudience(f.pin.InstallationID) {
				t.Error("wrong online token proof")
			}
			_ = r.Body.Close()
		}
		f.mu.Lock()
		blocked := f.block && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews"
		f.mu.Unlock()
		if blocked {
			f.once.Do(func() { close(f.entered) })
			<-f.release
			close(f.handlerDone)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			f.reviews++
			u := auth.UserInfo{Username: "system:serviceaccount:owners:connector", UID: f.pin.AccountUID, Groups: []string{"system:serviceaccounts", "system:authenticated", "system:serviceaccounts:owners"}, Extra: map[string]auth.ExtraValue{"authentication.kubernetes.io/pod-name": {f.pod.Name}, "authentication.kubernetes.io/pod-uid": {string(f.pod.UID)}}}
			permissionReply(w, auth.TokenReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}, Status: auth.TokenReviewStatus{Authenticated: !f.revoke, Audiences: q.Spec.Audiences, User: u}})
		case "/api/v1/namespaces/owners/serviceaccounts/connector":
			permissionReply(w, f.account)
		case "/apis/apps/v1/namespaces/owners/deployments/hwork":
			permissionReply(w, f.deploy)
		case "/apis/apps/v1/namespaces/owners/replicasets/hwork-rs":
			permissionReply(w, f.rs)
		case "/api/v1/namespaces/owners/pods/hwork-rs-pod":
			f.pods++
			p := f.pod.DeepCopy()
			if f.changedPod {
				p.Spec.Containers[0].Args = []string{"changed"}
			}
			permissionReply(w, p)
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(f.releaseHandler)
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client := func(token string) *PermissionClient {
		c, e := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: roots}, BearerToken: token}, base.v.pool.ClusterID, base.guard.plan.ControlNamespace, func() time.Time { return time.Unix(0, base.clock.Load()).UTC() })
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	observer, probe := client("observer"), client("probe")
	guard, err := NewOwnerWorkloadProtection(observer, probe, base.guard.plan, base.guard.pin)
	if err != nil {
		t.Fatal(err)
	}
	f.reader, err = NewOwnerLocalObservationOperationReader(observer, guard, base.pin, f.pin)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *ownerLocalNativeFixture) releaseHandler() {
	f.releaseOnce.Do(func() { close(f.release) })
}
func (f *ownerLocalNativeFixture) begin(t *testing.T) (*OwnerLocalObservationOperation, context.Context) {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), f.base.start.Add(5*time.Second))
	t.Cleanup(cancel)
	r := value.OwnerObservationRequest{RootID: f.base.pin.RootID, ID: ownerID(80), Challenge: ownerID(81), RequestedAt: f.base.start, NotAfter: f.base.start.Add(5 * time.Second)}
	o, err := f.reader.Begin(ctx, r, f.base.v.binding, f.token, string(f.pod.UID))
	if err != nil {
		t.Fatal("initial local native bracket", err)
	}
	t.Cleanup(o.Close)
	return o, ctx
}
func TestOwnerLocalObservationActualBoundariesAndCounts(t *testing.T) {
	f := newOwnerLocalNativeFixture(t)
	o, ctx := f.begin(t)
	first, err := o.Original(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f.base.observer.Load() != 21 || f.base.probe.Load() != 3 || f.reviews != 2 {
		t.Fatal("initial real port count", f.base.observer.Load(), f.base.probe.Load(), f.reviews)
	}
	original := first.FreshUntil
	end, err := o.Claim(ctx, f.token, string(f.pod.UID))
	if err != nil || end.After(original) {
		t.Fatal("claim original bound", err)
	}
	if f.base.observer.Load() != 30 || f.base.probe.Load() != 3 || f.reviews != 4 {
		t.Fatal("claim refreshed native guard or omitted actual caller", f.base.observer.Load(), f.base.probe.Load(), f.reviews)
	}
	final, err := o.Final(ctx)
	if err != nil || !final.Final || !final.ObservedAt.Equal(first.ObservedAt) || final.FreshUntil.After(original) {
		t.Fatal("final original bracket", err)
	}
	if f.base.observer.Load() != 51 || f.base.probe.Load() != 6 || f.reviews != 6 {
		t.Fatal("final real port count", f.base.observer.Load(), f.base.probe.Load(), f.reviews)
	}
	if _, err = o.Original(ctx); err == nil {
		t.Fatal("final proof reopened")
	}
}
func TestOwnerLocalObservationRejectsCallerChangeAndOriginalExpiry(t *testing.T) {
	for _, mode := range []string{"wrong-token", "wrong-pod", "duplicate-claim", "revoked-claim", "changed-claim", "revoked-final", "changed-final", "guard-final", "expired-original", "no-claim"} {
		t.Run(mode, func(t *testing.T) {
			f := newOwnerLocalNativeFixture(t)
			o, ctx := f.begin(t)
			token := f.token
			pod := string(f.pod.UID)
			switch mode {
			case "wrong-token":
				token = []byte("replacement")
			case "wrong-pod":
				pod = ownerID(99)
			case "revoked-claim":
				f.mu.Lock()
				f.revoke = true
				f.mu.Unlock()
			case "changed-claim":
				f.mu.Lock()
				f.changedPod = true
				f.mu.Unlock()
			case "expired-original":
				f.base.clock.Store(f.base.start.Add(5 * time.Second).UnixNano())
			}
			if mode == "no-claim" {
				if _, err := o.Final(ctx); err == nil {
					t.Fatal("unadmitted final")
				}
				return
			}
			_, err := o.Claim(ctx, token, pod)
			if mode == "wrong-token" || mode == "wrong-pod" || mode == "revoked-claim" || mode == "changed-claim" || mode == "expired-original" {
				if err == nil {
					t.Fatal("invalid claim admitted")
				}
				if _, err = o.Original(ctx); err == nil {
					t.Fatal("failed claim remained reusable")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "duplicate-claim":
				if _, err = o.Claim(ctx, token, pod); err == nil {
					t.Fatal("duplicate claim")
				}
				return
			case "revoked-final":
				f.mu.Lock()
				f.revoke = true
				f.mu.Unlock()
			case "changed-final":
				f.mu.Lock()
				f.changedPod = true
				f.mu.Unlock()
			case "guard-final":
				f.base.mu.Lock()
				f.base.binding.UID = types.UID(ownerID(90))
				f.base.mu.Unlock()
			}
			if _, err = o.Final(ctx); err == nil {
				t.Fatal("final change accepted")
			}
		})
	}
}
func TestOwnerLocalObservationCloseJoinsClaimRead(t *testing.T) {
	f := newOwnerLocalNativeFixture(t)
	o, ctx := f.begin(t)
	f.mu.Lock()
	f.block = true
	f.mu.Unlock()
	claimDone := make(chan error, 1)
	go func() { _, err := o.Claim(ctx, f.token, string(f.pod.UID)); claimDone <- err }()
	select {
	case <-f.entered:
	case <-time.After(time.Second):
		t.Fatal("claim did not reach held native read")
	}
	closed := make(chan struct{})
	go func() { o.Close(); close(closed) }()
	// Join the actual client-side adapter while the independent fake API server
	// still holds its response. Server handler completion is a separate owner.
	select {
	case err := <-claimDone:
		if err == nil {
			t.Fatal("cancelled claim succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("claim did not join")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join")
	}
	if len(o.caller.token) != 0 {
		t.Fatal("retained private token after joined close")
	}
	f.releaseHandler()
	select {
	case <-f.handlerDone:
	case <-time.After(time.Second):
		t.Fatal("owned fake API handler did not join")
	}
}
func TestOwnerLocalObservationCannotAliasCallerAndOwner(t *testing.T) {
	f := newOwnerLocalNativeFixture(t)
	pin := f.pin
	pin.DeploymentUID = f.base.pin.Pool.DeploymentUID
	if _, err := NewOwnerLocalObservationOperationReader(f.reader.owner.client, f.reader.owner.guard, f.base.pin, pin); err == nil {
		t.Fatal("owner template substituted for HWORK")
	}
	pin = f.pin
	pin.Namespace = cfg.NamespaceRef{Name: "other", UID: ownerID(90)}
	if _, err := NewOwnerLocalObservationOperationReader(f.reader.owner.client, f.reader.owner.guard, f.base.pin, pin); err == nil {
		t.Fatal("other namespace caller")
	}
}
