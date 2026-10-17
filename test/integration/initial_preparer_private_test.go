package integration

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Bounded fixture diagnostics retain only static route classes and HTTP status.
// They never inspect/log a request or response body, URL, token, or Secret data.
type initialProbeHTTPEvent struct {
	Route          string
	Status         int
	TransportError bool
}
type initialProbeTrace struct {
	mu                                 sync.Mutex
	events                             []initialProbeHTTPEvent
	requests, reviews                  atomic.Int32
	tokenPath, privatePath, anchorPath string
}
type initialProbeCountTransport struct {
	next  http.RoundTripper
	trace *initialProbeTrace
}

func (t initialProbeCountTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	label := "other"
	switch {
	case r.Method == "POST" && r.URL.Path == t.trace.tokenPath:
		label = "token-request"
		t.trace.requests.Add(1)
	case r.Method == "POST" && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews":
		label = "token-review"
		t.trace.reviews.Add(1)
	case r.URL.Path == t.trace.privatePath:
		label = "private-state-" + r.Method
	case r.URL.Path == t.trace.anchorPath:
		label = "probe-anchor-" + r.Method
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/secrets"):
		label = "secret-create"
	}
	response, err := t.next.RoundTrip(r)
	event := initialProbeHTTPEvent{Route: label, TransportError: err != nil}
	if response != nil {
		event.Status = response.StatusCode
	}
	if label != "other" || err != nil || event.Status >= 400 {
		t.trace.mu.Lock()
		if len(t.trace.events) == 24 {
			copy(t.trace.events, t.trace.events[1:])
			t.trace.events = t.trace.events[:23]
		}
		t.trace.events = append(t.trace.events, event)
		t.trace.mu.Unlock()
	}
	return response, err
}
func initialPrivateProbeDiagnostic(t *testing.T, ctx context.Context, api kubernetes.Interface, c contracts.InitialPreparer, trace *initialProbeTrace) {
	t.Helper()
	trace.mu.Lock()
	events := append([]initialProbeHTTPEvent(nil), trace.events...)
	trace.mu.Unlock()
	t.Logf("bounded probe HTTP diagnostics: token requests=%d reviews=%d events=%v", trace.requests.Load(), trace.reviews.Load(), events)
	read, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	v, e := api.CoreV1().Secrets(c.Plan.BootstrapNamespace.Name).Get(read, c.Plan.PrivateState.Name, meta.GetOptions{})
	if e != nil {
		t.Log("original private state observation unavailable")
		return
	}
	for _, raw := range v.Data {
		defer clear(raw)
	}
	state, e := contracts.DecodeInitialPreparationPrivateState(strings.NewReader(string(v.Data["state.json"])))
	if e != nil {
		t.Log("original private state decoding unavailable")
		return
	}
	anchorIntent := state.Probe != nil
	anchorReceipt, claim, response := false, false, false
	if anchorIntent {
		anchorReceipt = state.Probe.Anchor != nil
		claim = state.Probe.Issue != nil
		if claim {
			response = state.Probe.Issue.Response != nil
		}
	}
	t.Logf("original private state presence: root=%t anchorIntent=%t anchorReceipt=%t tokenClaim=%t tokenResponse=%t", state.RootUID != "", anchorIntent, anchorReceipt, claim, response)
}

func TestInitialPreparationPrivateProbeWithRealKubernetes(t *testing.T) {
	setup := func(ctx context.Context, kc *rest.Config, api kubernetes.Interface, plan *contracts.InitialPreparationPlan) {
		// Explicit trusted bootstrap fixture: create and pin the one private state
		// before compiling its protection. Product code cannot create or adopt it.
		body, _ := json.Marshal(contracts.InitialPreparationPrivateState{Format: contracts.InitialPreparationPrivateFormat, InstallationID: plan.InstallationID, RequestID: plan.RequestID})
		private, e := api.CoreV1().Secrets(plan.BootstrapNamespace.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "private-progress", Annotations: map[string]string{"asservat.io/installation-id": plan.InstallationID, "asservat.io/preparation-request": plan.RequestID}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": body}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		plan.PrivateState = &contracts.WorkerObjectReference{Name: private.Name, UID: string(private.UID)}
		// Determine this owned lab's API audience through one fixture-only request.
		// Production accepts one explicit installation-owned audience, never token
		// inference or alternate-audience retries. This account has no RBAC grants.
		account, e := api.CoreV1().ServiceAccounts(plan.BootstrapNamespace.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "fixture-audience"}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		response, e := api.CoreV1().ServiceAccounts(account.Namespace).CreateToken(ctx, account.Name, &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: private.Name, UID: private.UID}}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture API audience unavailable")
		}
		parts := strings.Split(response.Status.Token, ".")
		if len(parts) != 3 {
			t.Fatal("fixture audience syntax")
		}
		raw, e := base64.RawURLEncoding.DecodeString(parts[1])
		if e != nil {
			t.Fatal("fixture audience encoding")
		}
		defer clear(raw)
		var claims struct {
			Audience []string `json:"aud"`
		}
		if json.Unmarshal(raw, &claims) != nil || len(claims.Audience) != 1 {
			t.Fatal("fixture API audience profile")
		}
		plan.ProbeAudience = claims.Audience[0]
	}
	hook := func(ctx context.Context, kc *rest.Config, api kubernetes.Interface, admin, probe *kube.PermissionClient, c contracts.InitialPreparer) {
		trace := &initialProbeTrace{tokenPath: "/api/v1/namespaces/" + c.Plan.Workload.Namespace + "/serviceaccounts/" + c.Plan.Workload.ProbeAccount + "/token", privatePath: "/api/v1/namespaces/" + c.Plan.BootstrapNamespace.Name + "/secrets/" + c.Plan.PrivateState.Name, anchorPath: "/api/v1/namespaces/" + c.Plan.Workload.Namespace + "/secrets/" + c.Plan.Workload.Credentials + "-probe"}
		effect := rest.CopyConfig(kc)
		effect.Wrap(func(next http.RoundTripper) http.RoundTripper {
			return initialProbeCountTransport{next: next, trace: trace}
		})
		observedAdmin, e := kube.NewPermissionClient(effect, c.Plan.ClusterID, cfg.NamespaceRef{Name: c.Plan.BootstrapNamespace.Name, UID: c.Plan.BootstrapNamespace.UID}, time.Now)
		if e != nil {
			t.Fatal("diagnostic observer unavailable")
		}
		p, e := kube.NewInitialPreparer(effect, observedAdmin, probe, c)
		if e != nil {
			t.Fatal(e)
		}
		defer p.Close()
		first, e := p.PrepareProbe(ctx)
		if e != nil {
			initialPrivateProbeDiagnostic(t, ctx, api, c, trace)
			t.Fatal("native private probe", e)
		}
		defer clear(first.Token)
		replay, e := kube.NewInitialPreparer(effect, observedAdmin, probe, c)
		if e != nil {
			t.Fatal(e)
		}
		defer replay.Close()
		again, e := replay.PrepareProbe(ctx)
		if e != nil {
			initialPrivateProbeDiagnostic(t, ctx, api, c, trace)
			t.Fatal("native private replay", e)
		}
		defer clear(again.Token)
		if string(first.Token) != string(again.Token) || !first.ExpiresAt.Equal(again.ExpiresAt) || trace.requests.Load() != 1 {
			t.Fatal("native private replay reissued or renewed probe")
		}

		anchor, e := api.CoreV1().Secrets(c.Plan.Workload.Namespace).Get(ctx, c.Plan.Workload.Credentials+"-probe", meta.GetOptions{})
		if e != nil {
			t.Fatal("native original probe anchor unavailable")
		}
		// This second empty anchor is fixture-owned negative-test material only;
		// product inventory retains exactly its one original anchor.
		other, e := api.CoreV1().Secrets(c.Plan.Workload.Namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "fixture-other-probe"}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture negative anchor unavailable")
		}
		pod, e := api.CoreV1().Pods(c.Plan.Workload.Namespace).Get(ctx, c.Plan.Workload.Name, meta.GetOptions{})
		if e != nil {
			t.Fatal("fixture original gated Pod unavailable")
		}
		for _, mode := range []string{"wrong-account", "wrong-audience", "extra-audience", "shorter-duration", "longer-duration", "wrong-bound-kind", "wrong-bound-name", "missing-bound-uid", "no-binding", "nonadministrator"} {
			t.Run("token-boundary-"+mode, func(t *testing.T) {
				q := &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: []string{c.Plan.ProbeAudience}, ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: anchor.Name, UID: anchor.UID}}}
				account := c.Plan.Workload.ProbeAccount
				client := api
				switch mode {
				case "wrong-account":
					account = c.Plan.Workload.WriterAccount
				case "wrong-audience":
					q.Spec.Audiences = []string{"https://wrong.example.test"}
				case "extra-audience":
					q.Spec.Audiences = append(q.Spec.Audiences, "https://extra.example.test")
				case "shorter-duration":
					q.Spec.ExpirationSeconds = ptr.To(int64(599))
				case "longer-duration":
					q.Spec.ExpirationSeconds = ptr.To(int64(601))
				case "wrong-bound-kind":
					q.Spec.BoundObjectRef.Kind = "Pod"
					q.Spec.BoundObjectRef.Name = pod.Name
					q.Spec.BoundObjectRef.UID = pod.UID
				case "wrong-bound-name":
					q.Spec.BoundObjectRef.Name = other.Name
					q.Spec.BoundObjectRef.UID = other.UID
				case "missing-bound-uid":
					q.Spec.BoundObjectRef.UID = ""
				case "no-binding":
					q.Spec.BoundObjectRef = nil
				case "nonadministrator":
					pc := rest.CopyConfig(kc)
					pc.BearerToken = string(first.Token)
					pc.BearerTokenFile = ""
					pc.CertData = nil
					pc.KeyData = nil
					pc.CertFile = ""
					pc.KeyFile = ""
					client, e = kubernetes.NewForConfig(pc)
					if e != nil {
						t.Fatal("native probe client unavailable")
					}
				}
				result, e := client.CoreV1().ServiceAccounts(c.Plan.Workload.Namespace).CreateToken(ctx, account, q, meta.CreateOptions{})
				if e == nil {
					result.Status.Token = ""
					t.Fatal("out-of-scope TokenRequest accepted")
				}
				// Nonadministrator rejection may precede admission at RBAC. All
				// otherwise valid administrator scope mutations must reach this exact
				// guard denial. Built-in field validation may reject a too-short
				// interval or omitted UID before admission.
				if mode != "nonadministrator" && mode != "shorter-duration" && mode != "missing-bound-uid" && !strings.Contains(e.Error(), "Asservat preparation identities must remain occupied and may only lose setup authority.") {
					t.Fatal("out-of-scope request did not reach continuity guard")
				}
			})
		}
		for _, mode := range []string{"delete", "replace-uid", "owner", "data-key"} {
			t.Run("private-guard-"+mode, func(t *testing.T) {
				v, e := api.CoreV1().Secrets(c.Plan.BootstrapNamespace.Name).Get(ctx, c.Plan.PrivateState.Name, meta.GetOptions{})
				if e != nil {
					t.Fatal(e)
				}
				if mode == "delete" {
					e = api.CoreV1().Secrets(v.Namespace).Delete(ctx, v.Name, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}})
				} else {
					switch mode {
					case "replace-uid":
						v.UID = "00000000-0000-4000-8000-000000000099"
					case "owner":
						v.OwnerReferences = []meta.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "other", UID: v.UID}}
					case "data-key":
						v.Data = map[string][]byte{"other": []byte("invalid")}
					}
					_, e = api.CoreV1().Secrets(v.Namespace).Update(ctx, v, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
				}
				if e == nil {
					t.Fatal("native private guard accepted forbidden change")
				}
			})
		}
		// Qualify only the native terminal shape, using fixture administrator after
		// joining this local producer. This is not product credential retirement:
		// the finite probe itself is still live until fixture namespace cleanup.
		p.Close()
		replay.Close()
		old, e := api.CoreV1().Secrets(c.Plan.BootstrapNamespace.Name).Get(ctx, c.Plan.PrivateState.Name, meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		inert := old.DeepCopy()
		inert.Data = map[string][]byte{"retired": []byte("true")}
		inert.Immutable = ptr.To(true)
		if _, e = api.CoreV1().Secrets(inert.Namespace).Update(ctx, inert, meta.UpdateOptions{}); e != nil {
			t.Fatal("canonical inert private state", e)
		}
		if _, e = api.CoreV1().Secrets(old.Namespace).Update(ctx, old, meta.UpdateOptions{}); e == nil {
			t.Fatal("old-RV private update revived secret")
		}
		fresh, e := kube.NewInitialPreparer(effect, observedAdmin, probe, c)
		if e != nil {
			t.Fatal(e)
		}
		defer fresh.Close()
		if got, e := fresh.PrepareProbe(ctx); e == nil {
			clear(got.Token)
			t.Fatal("retired private state reissued credential")
		}
		if trace.requests.Load() != 1 {
			t.Fatal("retired state caused TokenRequest")
		}
	}
	initialPreparationSupervisorNativePlan(t, true, false, setup, hook)
}
