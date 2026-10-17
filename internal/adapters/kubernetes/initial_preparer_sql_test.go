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
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func initialSQLPreparationFixture(t *testing.T) (*preparationBindingFixture, *InitialPreparationCredentialBinder, []byte) {
	t.Helper()
	probe, p := newPrivatePreparationFixture(t, "")
	token, e := p.PrepareProbe(context.Background())
	clear(token.Token)
	if e != nil {
		t.Fatal(e)
	}
	f := preparationBindingFixtureFrom(t, probe.f, p)
	b := f.binder(t)
	material, binding, _, e := b.Bind(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	v := contracts.InitialSQLCredentialState{Format: contracts.InitialSQLCredentialsFormat, InstallationID: f.config.InstallationID, PlanDigest: binding.StartupDigest, NotBefore: binding.NotBefore, NotAfter: binding.NotAfter, Preparation: contracts.OwnerSQLCredential{Username: "prepare", Password: material.PreparationPassword}, Audit: contracts.OwnerSQLCredential{Username: "audit", Password: material.AuditPassword}, Activation: contracts.OwnerSQLCredential{Username: "activate", Password: material.ActivationPassword}}
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(raw) })
	return f, b, raw
}

func TestInitialSQLPreparationPersistsOriginalSecretOnce(t *testing.T) {
	f, b, payload := initialSQLPreparationFixture(t)
	first, e := b.PersistSQLState(context.Background(), payload)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := f.binder(t).PersistSQLState(context.Background(), payload)
	if e != nil || replay.Secret != first.Secret || !time.Now().Before(replay.ValidUntil) {
		t.Fatal("original SQL Secret replay", e)
	}
	f.f.mu.Lock()
	defer f.f.mu.Unlock()
	if f.f.posts["/api/v1/namespaces/initial-target/secrets/credentials-sql"] != 1 {
		t.Fatal("SQL Secret CREATE repeated")
	}
}

func TestInitialSQLPreparationUnknownEffectsNeverCreateAgain(t *testing.T) {
	for _, mode := range []string{"claim-before", "claim-after", "create-before", "create-after", "receipt-before", "receipt-after"} {
		t.Run(mode, func(t *testing.T) {
			f, b, payload := initialSQLPreparationFixture(t)
			var creates atomic.Int32
			var injected atomic.Bool
			f.f.client.Wrap(func(next http.RoundTripper) http.RoundTripper {
				return prepActivationRoundTrip(func(r *http.Request) (*http.Response, error) {
					isCreate := r.Method == "POST" && r.URL.Path == "/api/v1/namespaces/initial-target/secrets"
					if isCreate {
						creates.Add(1)
					}
					selected := isCreate && strings.HasPrefix(mode, "create-")
					if r.Method == "PUT" && r.URL.Path == "/api/v1/namespaces/bootstrap/secrets/private-progress" {
						raw, _ := io.ReadAll(r.Body)
						r.Body = io.NopCloser(bytes.NewReader(raw))
						defer clear(raw)
						var secret core.Secret
						_ = json.Unmarshal(raw, &secret)
						state, _ := contracts.DecodeInitialPreparationPrivateState(bytes.NewReader(secret.Data["state.json"]))
						selected = state.SQL != nil && ((state.SQL.Secret == nil && strings.HasPrefix(mode, "claim-")) || (state.SQL.Secret != nil && strings.HasPrefix(mode, "receipt-")))
						for _, data := range secret.Data {
							clear(data)
						}
					}
					if selected && injected.CompareAndSwap(false, true) {
						if strings.HasSuffix(mode, "-after") {
							reply, e := next.RoundTrip(r)
							if e != nil {
								return reply, e
							}
							reply.Body.Close()
						}
						raw, _ := json.Marshal(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonServiceUnavailable, Code: 503})
						return &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw)), Request: r}, nil
					}
					return next.RoundTrip(r)
				})
			})
			b = f.binder(t)
			_, firstErr := b.PersistSQLState(context.Background(), payload)
			if (firstErr == nil) != (mode == "create-after") {
				t.Fatal("unexpected first uncertain effect disposition", mode, firstErr)
			}
			got, replayErr := f.binder(t).PersistSQLState(context.Background(), payload)
			// A lost claim before persistence has no surviving SQL intent; the next call
			// can obtain its first acknowledged claim. An existing claim never does so.
			resolves := mode == "claim-before" || mode == "create-after" || strings.HasPrefix(mode, "receipt-")
			if (replayErr == nil) != resolves {
				t.Fatal("unexpected original effect lookup", mode, replayErr)
			}
			if replayErr == nil && got.Secret.UID == "" {
				t.Fatal("lost original SQL Secret identity")
			}
			expected := int32(1)
			if mode == "claim-after" {
				expected = 0
			}
			if creates.Load() != expected {
				t.Fatal("unknown SQL effect repeated", mode, creates.Load())
			}
		})
	}
}

func TestInitialSQLPreparationRejectsChangedOrExpiredOriginalState(t *testing.T) {
	for _, mode := range []string{"password", "expired", "private-uid", "target-uid"} {
		t.Run(mode, func(t *testing.T) {
			f, b, payload := initialSQLPreparationFixture(t)
			if mode == "target-uid" {
				if _, e := b.PersistSQLState(context.Background(), payload); e != nil {
					t.Fatal(e)
				}
			}
			f.f.mu.Lock()
			switch mode {
			case "password":
				var v contracts.InitialSQLCredentialState
				_ = json.Unmarshal(payload, &v)
				v.Preparation.Password = "different"
				payload, _ = json.Marshal(v)
			case "expired":
				f.f.shift = 16 * time.Minute
			case "private-uid":
				f.f.objects[b.preparer.privatePath()]["metadata"].(map[string]any)["uid"] = ownerID(990)
			case "target-uid":
				f.f.objects["/api/v1/namespaces/initial-target/secrets/credentials-sql"]["metadata"].(map[string]any)["uid"] = ownerID(990)
			}
			before := f.f.posts["/api/v1/namespaces/initial-target/secrets/credentials-sql"]
			f.f.mu.Unlock()
			if _, e := b.PersistSQLState(context.Background(), payload); e == nil {
				t.Fatal("changed or expired state accepted")
			}
			f.f.mu.Lock()
			defer f.f.mu.Unlock()
			if f.f.posts["/api/v1/namespaces/initial-target/secrets/credentials-sql"] != before {
				t.Fatal("rejected input caused credential CREATE")
			}
		})
	}
}

func TestInitialSQLPreparationConcurrentClaimCreatesAtMostOnce(t *testing.T) {
	f, _, payload := initialSQLPreparationFixture(t)
	var wg sync.WaitGroup
	var successes atomic.Int32
	for range 4 {
		b := f.binder(t)
		wg.Go(func() {
			if _, e := b.PersistSQLState(context.Background(), payload); e == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if successes.Load() == 0 {
		t.Fatal("no acknowledged claim completed")
	}
	f.f.mu.Lock()
	defer f.f.mu.Unlock()
	if f.f.posts["/api/v1/namespaces/initial-target/secrets/credentials-sql"] != 1 {
		t.Fatal("concurrent private claims repeated CREATE")
	}
}

func TestInitialSQLPreparationPreservesOriginalLeaseAfterSecretCreate(t *testing.T) {
	f, _, payload := initialSQLPreparationFixture(t)
	var once atomic.Bool
	f.f.client.Wrap(func(next http.RoundTripper) http.RoundTripper {
		return prepActivationRoundTrip(func(r *http.Request) (*http.Response, error) {
			result, e := next.RoundTrip(r)
			if e == nil && r.Method == "POST" && r.URL.Path == "/api/v1/namespaces/initial-target/secrets" && once.CompareAndSwap(false, true) {
				f.f.mu.Lock()
				f.f.shift = 6 * time.Second
				f.f.mu.Unlock()
			}
			return result, e
		})
	})
	b := f.binder(t)
	first, e := b.PersistSQLState(context.Background(), payload)
	if e == nil || !first.ValidUntil.IsZero() {
		t.Fatal("late Secret create returned a renewed effect lease")
	}
	f.f.mu.Lock()
	f.f.shift = 0
	f.f.mu.Unlock()
	got, e := f.binder(t).PersistSQLState(context.Background(), payload)
	if e != nil || got.Secret.UID == "" {
		t.Fatal("exact original Secret could not be reconciled", e)
	}
	f.f.mu.Lock()
	defer f.f.mu.Unlock()
	if f.f.posts["/api/v1/namespaces/initial-target/secrets/credentials-sql"] != 1 {
		t.Fatal("late result caused another Secret create")
	}
}
