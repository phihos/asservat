package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

type syntheticInitialIssuer struct {
	parent     contracts.InitialProviderParent
	issues     atomic.Int32
	fail       bool
	afterIssue func()
}

func (s *syntheticInitialIssuer) Check(context.Context, time.Time) (contracts.InitialProviderParent, time.Time, error) {
	return s.parent, time.Now().Add(5 * time.Second), nil
}
func (s *syntheticInitialIssuer) Issue(_ context.Context, purpose string, i contracts.InitialProviderIssue, p contracts.InitialProviderParent) (contracts.InitialProviderResponse, error) {
	s.issues.Add(1)
	if s.afterIssue != nil {
		s.afterIssue()
	}
	if s.fail {
		return contracts.InitialProviderResponse{}, cfg.ErrUnavailable
	}
	return contracts.InitialProviderResponse{Token: "synthetic-" + purpose + "-token", Accessor: "synthetic-" + purpose + "-accessor", IssuedAt: time.Now().UTC(), ExpiresAt: p.ExpiresAt.Add(-time.Second)}, nil
}
func (s *syntheticInitialIssuer) Verify(_ context.Context, purpose string, _ contracts.InitialProviderIssue, _ contracts.InitialProviderParent, r contracts.InitialProviderResponse) error {
	if r.Token != "synthetic-"+purpose+"-token" {
		return cfg.ErrChanged
	}
	return nil
}
func initialProviderPreparationFixture(t *testing.T) (*preparationBindingFixture, *InitialPreparationCredentialBinder, *syntheticInitialIssuer) {
	t.Helper()
	f, b, payload := initialSQLPreparationFixture(t)
	if _, e := b.PersistSQLState(context.Background(), payload); e != nil {
		t.Fatal(e)
	}
	m := contracts.InitialProviderMaterial{Format: contracts.InitialProviderMaterialFormat, InstallationID: f.f.plan.InstallationID, RequestID: f.f.plan.RequestID, IssuerToken: "synthetic-original-issuer", Storage: contracts.OwnerStorageCredential{AccessKeyID: "synthetic-access", SecretAccessKey: "synthetic-private"}, StorageUseUntil: time.Now().UTC().Add(time.Hour)}
	raw, _ := json.Marshal(m)
	defer clear(raw)
	secret := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "provider-material", Namespace: "bootstrap"}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: map[string][]byte{"material.json": raw}}
	encoded, _ := json.Marshal(secret)
	defer clear(encoded)
	path := "/api/v1/namespaces/bootstrap/secrets/provider-material"
	f.f.mu.Lock()
	f.f.store(path, encoded)
	uid := f.f.objects[path]["metadata"].(map[string]any)["uid"].(string)
	f.f.mu.Unlock()
	// Synthetic composition supplies the protected provider profile directly; real
	// constructor/native profile admission is tested separately from these CAS cases.
	b.preparer.providers = &contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: contracts.WorkerObjectReference{Name: secret.Name, UID: uid}, IssuerPolicy: "issuer", WrapRole: "wrap-role", WrapPolicy: "wrap-policy", UnwrapRole: "unwrap-role", UnwrapPolicy: "unwrap-policy"}
	return f, b, &syntheticInitialIssuer{parent: contracts.InitialProviderParent{Accessor: "synthetic-parent", IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}}
}
func providerBinderAgain(t *testing.T, f *preparationBindingFixture, b *InitialPreparationCredentialBinder) *InitialPreparationCredentialBinder {
	t.Helper()
	next := f.binder(t)
	p := *b.preparer.providers
	next.preparer.providers = &p
	return next
}
func TestInitialProviderPreparationOriginalClaimsAndProjection(t *testing.T) {
	f, b, issuer := initialProviderPreparationFixture(t)
	first, _, e := b.PrepareProvider(context.Background(), "wrap", issuer)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = b.PrepareProvider(context.Background(), "unwrap", issuer); e != nil {
		t.Fatal(e)
	}
	got, _, e := providerBinderAgain(t, f, b).PrepareProvider(context.Background(), "wrap", issuer)
	if e != nil || got != first {
		t.Fatal("original reply changed", e)
	}
	projection, e := b.PersistProviderProjection(context.Background(), issuer)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := providerBinderAgain(t, f, b).PersistProviderProjection(context.Background(), issuer)
	if e != nil || replay.Secret != projection.Secret {
		t.Fatal("projection replay changed", e)
	}
	if issuer.issues.Load() != 2 {
		t.Fatal("reissued provider credential")
	}
	f.f.mu.Lock()
	defer f.f.mu.Unlock()
	path := "/api/v1/namespaces/initial-target/secrets/credentials"
	if f.f.posts[path] != 1 {
		t.Fatal("projection CREATE repeated")
	}
	raw, _ := json.Marshal(f.f.objects[path])
	defer clear(raw)
	var secret core.Secret
	if json.Unmarshal(raw, &secret) != nil || len(secret.Data) != 7 {
		t.Fatal("wrong projection")
	}
	for _, data := range secret.Data {
		defer clear(data)
		if bytes.Contains(data, []byte("synthetic-original-issuer")) {
			t.Fatal("issuer projected")
		}
	}
	if string(secret.Data["audit-wrap.token"]) != "synthetic-wrap-token" || string(secret.Data["audit-unwrap.token"]) != "synthetic-unwrap-token" || len(secret.Data["kube-writer.token"]) != 0 {
		t.Fatal("provider purpose crossed or writer fabricated")
	}
}
func TestInitialProviderPreparationUnknownClaimsAndResponses(t *testing.T) {
	for _, mode := range []string{"claim-before", "claim-after", "response-before", "response-after", "provider-lost"} {
		t.Run(mode, func(t *testing.T) {
			f, b, issuer := initialProviderPreparationFixture(t)
			var injected atomic.Bool
			if mode == "provider-lost" {
				issuer.fail = true
			} else {
				f.f.client.Wrap(func(next http.RoundTripper) http.RoundTripper {
					return prepActivationRoundTrip(func(r *http.Request) (*http.Response, error) {
						selected := false
						if r.Method == "PUT" && r.URL.Path == "/api/v1/namespaces/bootstrap/secrets/private-progress" {
							raw, _ := io.ReadAll(r.Body)
							r.Body = io.NopCloser(bytes.NewReader(raw))
							defer clear(raw)
							var secret core.Secret
							_ = json.Unmarshal(raw, &secret)
							state, _ := contracts.DecodeInitialPreparationPrivateState(bytes.NewReader(secret.Data["state.json"]))
							selected = state.Providers != nil && state.Providers.Wrap != nil && ((state.Providers.Wrap.Response == nil && strings.HasPrefix(mode, "claim-")) || (state.Providers.Wrap.Response != nil && strings.HasPrefix(mode, "response-")))
							for _, data := range secret.Data {
								clear(data)
							}
						}
						if selected && injected.CompareAndSwap(false, true) {
							if strings.HasSuffix(mode, "-after") {
								response, e := next.RoundTrip(r)
								if e != nil {
									return response, e
								}
								response.Body.Close()
							}
							raw, _ := json.Marshal(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonServiceUnavailable, Code: 503})
							return &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw)), Request: r}, nil
						}
						return next.RoundTrip(r)
					})
				})
				b = providerBinderAgain(t, f, b)
			}
			_, _, e := b.PrepareProvider(context.Background(), "wrap", issuer)
			if e == nil {
				t.Fatal("injected uncertainty accepted")
			}
			// Only the same still-live joined owner retains an unpersisted positive reply.
			replay := b
			if mode != "response-before" {
				replay = providerBinderAgain(t, f, b)
			}
			_, _, e = replay.PrepareProvider(context.Background(), "wrap", issuer)
			want := mode == "claim-before" || strings.HasPrefix(mode, "response-")
			if (e == nil) != want {
				t.Fatal("wrong original response disposition", mode, e)
			}
			count := int32(1)
			if mode == "claim-after" {
				count = 0
			}
			if issuer.issues.Load() != count {
				t.Fatal("unknown POST repeated", issuer.issues.Load())
			}
		})
	}
}
func TestInitialProviderPreparationConcurrentClaimAndChangedParent(t *testing.T) {
	f, b, issuer := initialProviderPreparationFixture(t)
	var wg sync.WaitGroup
	var successes atomic.Int32
	for range 4 {
		peer := providerBinderAgain(t, f, b)
		wg.Go(func() {
			if _, _, e := peer.PrepareProvider(context.Background(), "wrap", issuer); e == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if successes.Load() == 0 || issuer.issues.Load() != 1 {
		t.Fatal("concurrent issue claim did not serialize", successes.Load(), issuer.issues.Load())
	}
	issuer.parent.ExpiresAt = issuer.parent.ExpiresAt.Add(time.Second)
	if _, _, e := b.PrepareProvider(context.Background(), "wrap", issuer); e == nil {
		t.Fatal("parent lifetime changed")
	}
	if issuer.issues.Load() != 1 {
		t.Fatal("changed parent caused new issue")
	}
}
func TestInitialProviderPreparationFinalDeadlineAndSize(t *testing.T) {
	f, b, issuer := initialProviderPreparationFixture(t)
	issuer.afterIssue = func() { f.f.mu.Lock(); f.f.shift = 6 * time.Second; f.f.mu.Unlock() }
	if got, until, e := b.PrepareProvider(context.Background(), "wrap", issuer); e == nil || got.Token != "" || !until.IsZero() {
		t.Fatal("final original authority expiry ignored")
	}
	f.f.mu.Lock()
	f.f.shift = 0
	f.f.mu.Unlock()
	issuer.afterIssue = nil
	if _, _, e := b.PrepareProvider(context.Background(), "wrap", issuer); e != nil {
		t.Fatal("live positive reply could not finish original persistence", e)
	}
	_, state, e := b.preparer.readPrivate(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if !b.preparer.providerStateFits(state) {
		t.Fatal("maximum finite replies do not fit private state")
	}
	state.Probe.Issue.Response.Token = strings.Repeat("x", contracts.InitialPreparationPrivateMaxBytes)
	if b.preparer.providerStateFits(state) {
		t.Fatal("oversized future replies accepted")
	}
}
