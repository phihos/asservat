package kubernetes

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type preparationProbeFixture struct {
	f         *preparerFixture
	requests  int
	token     string
	fault     string
	triggered bool
}

func newPrivatePreparationFixture(t *testing.T, fault string) (*preparationProbeFixture, *InitialPreparer) {
	t.Helper()
	plan := preparerTestPlan()
	plan.Continuation = contracts.InitialPreparationActivationProtocol
	plan.PrivateState = &contracts.WorkerObjectReference{Name: "private-progress", UID: ownerID(900)}
	plan.ProbeAudience = "https://kubernetes.default.svc.cluster.local"
	f := newPreparerFixturePlan(t, "", plan)
	p := f.preparer(t)
	t.Cleanup(p.Close)
	private := contracts.InitialPreparationPrivateState{Format: contracts.InitialPreparationPrivateFormat, InstallationID: plan.InstallationID, RequestID: plan.RequestID}
	data, _ := json.Marshal(private)
	secret := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: plan.PrivateState.Name, Namespace: plan.BootstrapNamespace.Name, UID: types.UID(plan.PrivateState.UID), ResourceVersion: "10", Annotations: map[string]string{initialNamespaceInstallationAnnotation: plan.InstallationID, initialNamespaceRequestAnnotation: plan.RequestID}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": data}}
	raw, _ := json.Marshal(secret)
	f.mu.Lock()
	f.store(p.privatePath(), raw)
	f.objects[p.privatePath()]["metadata"].(map[string]any)["uid"] = plan.PrivateState.UID
	f.mu.Unlock()
	if _, e := p.Declare(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e := p.PrepareGatedPod(context.Background()); e != nil {
		t.Fatal(e)
	}
	probe := &preparationProbeFixture{f: f, fault: fault}
	f.mu.Lock()
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/serviceaccounts/probe/token") {
			probe.requests++
			var request auth.TokenRequest
			b, e := io.ReadAll(r.Body)
			if e != nil || json.Unmarshal(b, &request) != nil {
				t.Error("synthetic token request")
				return true
			}
			if len(request.Spec.Audiences) != 1 || request.Spec.Audiences[0] != plan.ProbeAudience || request.Spec.ExpirationSeconds == nil || *request.Spec.ExpirationSeconds != 600 || request.Spec.BoundObjectRef == nil || request.Spec.BoundObjectRef.Kind != "Secret" || request.Spec.BoundObjectRef.Name != p.probeAnchorName() {
				t.Error("probe issuance scope changed")
				return true
			}
			if fault == "unknown-issue" {
				f.status(w, 503, meta.StatusReasonServiceUnavailable, "", "")
				return true
			}
			account := f.objects["/api/v1/namespaces/initial-target/serviceaccounts/probe"]["metadata"].(map[string]any)["uid"].(string)
			now := time.Now().UTC().Truncate(time.Second)
			expires := now.Add(600 * time.Second)
			bound := string(request.Spec.BoundObjectRef.UID)
			aud := plan.ProbeAudience
			if fault == "wrong-bound" {
				bound = ownerID(990)
			}
			if fault == "wrong-audience" {
				aud = "other-audience"
			}
			claims := map[string]any{"iat": now.Unix(), "exp": expires.Unix(), "aud": []string{aud}, "kubernetes.io": map[string]any{"namespace": plan.Workload.Namespace, "serviceaccount": map[string]string{"name": "probe", "uid": account}, "secret": map[string]string{"name": p.probeAnchorName(), "uid": bound}}}
			payload, _ := json.Marshal(claims)
			probe.token = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"synthetic"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString([]byte("synthetic-only"))
			if fault == "expired-positive" {
				f.shift = 6 * time.Second
			}
			request.Status.Token = probe.token
			request.Status.ExpirationTimestamp = meta.NewTime(expires)
			w.WriteHeader(201)
			permissionReply(w, request)
			return true
		}
		if r.Method == "POST" && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews" {
			var q auth.TokenReview
			b, _ := io.ReadAll(r.Body)
			if json.Unmarshal(b, &q) != nil || q.Spec.Token != probe.token {
				t.Error("unexpected synthetic token review")
				return true
			}
			account := f.objects["/api/v1/namespaces/initial-target/serviceaccounts/probe"]["metadata"].(map[string]any)["uid"].(string)
			permissionReply(w, auth.TokenReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}, Status: auth.TokenReviewStatus{Authenticated: fault != "review-denied", Audiences: []string{plan.ProbeAudience}, User: auth.UserInfo{Username: "system:serviceaccount:initial-target:probe", UID: account}}})
			return true
		}
		if r.Method == "PUT" && r.URL.Path == p.privatePath() && (strings.HasPrefix(fault, "lost-response-") || strings.HasPrefix(fault, "lost-claim-")) && !probe.triggered {
			b, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(b)))
			var v core.Secret
			_ = json.Unmarshal(b, &v)
			state, _ := contracts.DecodeInitialPreparationPrivateState(strings.NewReader(string(v.Data["state.json"])))
			if state.Probe != nil && state.Probe.Issue != nil && (state.Probe.Issue.Response != nil && strings.HasPrefix(fault, "lost-response-") || state.Probe.Issue.Response == nil && strings.HasPrefix(fault, "lost-claim-")) {
				probe.triggered = true
				if fault == "lost-response-after" || fault == "lost-claim-after" {
					var obj map[string]any
					_ = json.Unmarshal(b, &obj)
					f.serial++
					obj["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(f.serial)
					f.objects[r.URL.Path] = obj
				}
				f.status(w, 503, meta.StatusReasonServiceUnavailable, "", "")
				return true
			}
		}
		return false
	}
	f.mu.Unlock()
	return probe, p
}
func TestInitialPrivateProbePreservesOneOriginalIssuance(t *testing.T) {
	f, p := newPrivatePreparationFixture(t, "")
	ctx := context.Background()
	first, e := p.PrepareProbe(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(first.Token)
	second := f.f.preparer(t)
	defer second.Close()
	again, e := second.PrepareProbe(ctx)
	defer clear(again.Token)
	if e != nil || string(first.Token) != string(again.Token) || !first.ExpiresAt.Equal(again.ExpiresAt) || f.requests != 1 {
		t.Fatal("original probe changed or reissued", e)
	}
	_, state, e := p.readPrivate(ctx)
	if e != nil || state.Probe == nil || state.Probe.Issue == nil || state.Probe.Issue.Response == nil {
		t.Fatal("original response not retained", e)
	}
	if len(first.Token) == 0 || !first.ValidUntil.Before(first.ExpiresAt) {
		t.Fatal("probe observation lost its current short lease")
	}
}
func TestInitialPrivateProbeUnknownIssuanceNeverRepeats(t *testing.T) {
	for _, fault := range []string{"unknown-issue", "wrong-bound", "wrong-audience", "review-denied", "expired-positive"} {
		t.Run(fault, func(t *testing.T) {
			f, p := newPrivatePreparationFixture(t, fault)
			if v, e := p.PrepareProbe(context.Background()); e == nil {
				clear(v.Token)
				t.Fatal("unverified issuance returned credential")
			}
			replay := f.f.preparer(t)
			defer replay.Close()
			if v, e := replay.PrepareProbe(context.Background()); e == nil {
				clear(v.Token)
				t.Fatal("unknown issuance reopened")
			}
			if f.requests != 1 {
				t.Fatal("TokenRequest repeated")
			}
		})
	}
}
func TestInitialPrivateProbeLostPersistenceUsesOnlyOriginalResponse(t *testing.T) {
	for _, fault := range []string{"lost-response-before", "lost-response-after"} {
		t.Run(fault, func(t *testing.T) {
			f, p := newPrivatePreparationFixture(t, fault)
			if v, e := p.PrepareProbe(context.Background()); e == nil {
				clear(v.Token)
				t.Fatal("lost persistence reply reported success")
			}
			owner := p
			if fault == "lost-response-after" {
				owner = f.f.preparer(t)
				defer owner.Close()
			}
			v, e := owner.PrepareProbe(context.Background())
			defer clear(v.Token)
			if e != nil || f.requests != 1 || string(v.Token) != f.token {
				t.Fatal("lost persistence did not preserve original response", e)
			}
		})
	}
}
func TestInitialPrivateStateCannotLoseClaimOrAdoptIdentity(t *testing.T) {
	f, p := newPrivatePreparationFixture(t, "")
	v, e := p.PrepareProbe(context.Background())
	clear(v.Token)
	if e != nil {
		t.Fatal(e)
	}
	_, old, e := p.readPrivate(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for _, modify := range []func(*contracts.InitialPreparationPrivateState){func(v *contracts.InitialPreparationPrivateState) { v.RootUID = ownerID(901) }, func(v *contracts.InitialPreparationPrivateState) { v.Probe = nil }, func(v *contracts.InitialPreparationPrivateState) { q := *v.Probe; q.Issue = nil; v.Probe = &q }, func(v *contracts.InitialPreparationPrivateState) {
		q := *v.Probe
		i := *q.Issue
		i.Until = i.Until.Add(time.Second)
		q.Issue = &i
		v.Probe = &q
	}} {
		next := old
		modify(&next)
		if p.privateTransition(old, next) {
			t.Fatal("private progress rewound or renewed")
		}
	}
	f.f.mu.Lock()
	f.f.objects[p.privatePath()]["metadata"].(map[string]any)["uid"] = ownerID(902)
	f.f.mu.Unlock()
	if _, _, e = p.OpenPrivateState(context.Background()); e == nil {
		t.Fatal("replacement private Secret adopted")
	}
}

func TestInitialPrivateProbeLostClaimNeverConfersFreshness(t *testing.T) {
	for _, fault := range []string{"lost-claim-before", "lost-claim-after"} {
		t.Run(fault, func(t *testing.T) {
			f, p := newPrivatePreparationFixture(t, fault)
			if v, e := p.PrepareProbe(context.Background()); e == nil {
				clear(v.Token)
				t.Fatal("lost claim reported success")
			}
			if f.requests != 0 {
				t.Fatal("lost claim acknowledgement issued token")
			}
			retry := f.f.preparer(t)
			defer retry.Close()
			v, e := retry.PrepareProbe(context.Background())
			defer clear(v.Token)
			if fault == "lost-claim-after" {
				if e == nil || f.requests != 0 {
					t.Fatal("persisted unresolved claim reopened issuance")
				}
			} else if e != nil || f.requests != 1 {
				t.Fatal("new acknowledged CAS did not recover absent original claim", e)
			}
		})
	}
}

func TestInitialPrivateProbeConcurrentOwnersIssueAtMostOnce(t *testing.T) {
	f, p := newPrivatePreparationFixture(t, "")
	if e := p.prepareProbeAnchor(context.Background()); e != nil {
		t.Fatal(e)
	}
	const contenders = 8
	owners := make([]*InitialPreparer, contenders)
	for i := range owners {
		owners[i] = f.f.preparer(t)
		defer owners[i].Close()
	}
	start := make(chan struct{})
	var joined sync.WaitGroup
	for _, owner := range owners {
		joined.Add(1)
		go func(p *InitialPreparer) {
			defer joined.Done()
			<-start
			v, _ := p.PrepareProbe(context.Background())
			clear(v.Token)
		}(owner)
	}
	close(start)
	joined.Wait()
	// Conflicted peers may report unavailable; the persisted winner can be read
	// by a new current owner. Neither conflict nor GET grants another issuance.
	v, e := p.PrepareProbe(context.Background())
	defer clear(v.Token)
	if e != nil || f.requests != 1 {
		t.Fatal("concurrent claim did not preserve exactly one issuance", e)
	}
}

func TestInitialPrivateContinuationPreservesExistingPolicyBytes(t *testing.T) {
	for _, continuation := range []string{"", contracts.InitialPreparationActivationProtocol} {
		p := preparerTestPlan()
		p.Continuation = continuation
		policy, binding, e := InitialPreparationContinuityAdmission(p)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(struct {
			Policy  any
			Binding any
		}{policy, binding})
		got := fmt.Sprintf("%x", sha256.Sum256(raw))
		want := map[string]string{"": "040a058ff689335d97580222faa96afc9c3b4ecb2d726e2b9e6664bcf02151e0", contracts.InitialPreparationActivationProtocol: "54978715f6559bfe5df88233c8fdde2ce97afb3b570dd71ffb3932f81518b394"}[continuation]
		if got != want {
			t.Fatalf("policy profile %q changed: %s", continuation, got)
		}
	}
}

func TestInitialPrivateProbeDiagnosticIsStaticAndPreservesCause(t *testing.T) {
	for _, tc := range []struct {
		fault, phase string
		cause        error
	}{
		{"unknown-issue", "initial probe token-request", cfg.ErrUnavailable},
		{"wrong-bound", "initial probe initial-token-review: probe review bound-claims", cfg.ErrChanged},
	} {
		t.Run(tc.fault, func(t *testing.T) {
			f, p := newPrivatePreparationFixture(t, tc.fault)
			got, err := p.PrepareProbe(context.Background())
			defer clear(got.Token)
			if err == nil || !strings.Contains(err.Error(), tc.phase) || !errors.Is(err, tc.cause) {
				t.Fatalf("static diagnostic/cause missing: %v", err)
			}
			if f.token != "" && strings.Contains(err.Error(), f.token) {
				t.Fatal("credential leaked in diagnostic")
			}
			if strings.Contains(err.Error(), p.plan.InstallationID) || strings.Contains(err.Error(), p.plan.RequestID) {
				t.Fatal("scope identity leaked in diagnostic")
			}
			if f.requests != 1 {
				t.Fatal("diagnostic caused another issuance")
			}
		})
	}
}
