package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
)

func preparationUnavailableResponse() *http.Response {
	b, _ := json.Marshal(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonServiceUnavailable, Code: 503})
	return &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b))}
}
func TestInitialPreparationPodRequestDrain(t *testing.T) {
	for _, mode := range []string{"healthy", "lost-create-response", "lost-completion-write"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := activationPreparerFixture(t)
			var altered atomic.Bool
			f.client.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
				return prepActivationRoundTrip(func(r *http.Request) (*http.Response, error) {
					if mode == "lost-completion-write" && r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/configmaps/prepare") {
						b, _ := io.ReadAll(r.Body)
						r.Body = io.NopCloser(bytes.NewReader(b))
						var cm core.ConfigMap
						_ = json.Unmarshal(b, &cm)
						var root contracts.InitialPreparationRoot
						_ = json.Unmarshal([]byte(cm.Data["root.json"]), &root)
						if root.Activation != nil && len(root.Activation.Pod.Requests) > 0 && root.Activation.Pod.Requests[0].Completion != nil && altered.CompareAndSwap(false, true) {
							return preparationUnavailableResponse(), nil
						}
					}
					response, e := next.RoundTrip(r)
					if mode == "lost-create-response" && r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/pods") && e == nil && altered.CompareAndSwap(false, true) {
						response.Body.Close()
						return preparationUnavailableResponse(), nil
					}
					return response, e
				})
			}
			p := f.preparer(t)
			t.Cleanup(p.Close)
			root, e := p.PrepareGatedPod(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if len(root.Activation.Pod.Requests) != 1 {
				t.Fatal("missing exact request claim")
			}
			original := root.Activation.Pod.Requests[0]
			if mode == "lost-create-response" {
				if original.Completion != nil {
					t.Fatal("GET invented original POST completion")
				}
				if e = p.DrainPodCreateRequests(context.Background()); !errors.Is(e, ErrInitialPreparationRequestsUnresolved) {
					t.Fatal("unknown request reported drained", e)
				}
				peer := f.preparer(t)
				defer peer.Close()
				later, e := peer.PrepareGatedPod(context.Background())
				if e != nil || len(later.Activation.Pod.Requests) != 1 || later.Activation.Pod.Requests[0].Completion != nil {
					t.Fatal("known UID replay reopened or resolved unknown CREATE", e)
				}
				if e = peer.DrainPodCreateRequests(context.Background()); !errors.Is(e, ErrInitialPreparationRequestsUnresolved) {
					t.Fatal("another owner adopted unknown completion", e)
				}
			} else {
				if mode == "lost-completion-write" {
					f.mu.Lock()
					f.shift = 10 * time.Second
					f.mu.Unlock()
				}
				if e = p.DrainPodCreateRequests(context.Background()); e != nil {
					t.Fatal("healthy request did not drain", e)
				}
				_, after, e := p.read(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				closed := after.Activation.Pod.Requests[0]
				if closed.ID != original.ID || closed.OwnerID != original.OwnerID || !closed.StartedAt.Equal(original.StartedAt) || !closed.Until.Equal(original.Until) || closed.Completion == nil || closed.Completion.Outcome != "created" {
					t.Fatal("completion changed original request")
				}
				if e = p.DrainPodCreateRequests(context.Background()); e != nil {
					t.Fatal("drain acknowledgement not replayable", e)
				}
			}
			f.mu.Lock()
			posts := f.posts["/api/v1/namespaces/"+f.plan.Workload.Namespace+"/pods/"+f.plan.Workload.Name]
			f.mu.Unlock()
			if posts != 1 {
				t.Fatal("drain caused another POST", posts)
			}
		})
	}
}

func TestInitialPreparationPodCloseJoinsRequestWithoutInventingCompletion(t *testing.T) {
	f, _ := activationPreparerFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.client.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return prepActivationRoundTrip(func(r *http.Request) (*http.Response, error) {
			response, e := next.RoundTrip(r)
			if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/pods") && e == nil {
				once.Do(func() { close(entered) })
				<-release // deliberately uncooperative transport; shutdown must join
			}
			return response, e
		})
	}
	p := f.preparer(t)
	done := make(chan error, 1)
	go func() { _, e := p.PrepareGatedPod(context.Background()); done <- e }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request not reached")
	}
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned before request joined")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not join")
	}
	if e := <-done; e == nil {
		t.Fatal("cancelled request reported current success")
	}
	if _, _, e := p.ownPodRequest(context.Background()); !errors.Is(e, cfg.ErrUnavailable) {
		t.Fatal("closed owner accepted another request")
	}
	fresh := f.preparer(t)
	defer fresh.Close()
	root, e := fresh.PrepareGatedPod(context.Background())
	if e != nil || root.Activation.Pod.Receipt == nil || root.Activation.Pod.Requests[0].Completion != nil {
		t.Fatal("joined uncertain request changed completion", e)
	}
	if e = fresh.DrainPodCreateRequests(context.Background()); !errors.Is(e, ErrInitialPreparationRequestsUnresolved) {
		t.Fatal("local cancellation treated as server quiescence", e)
	}
}

func TestInitialPreparationPodRequestBudgetAndOriginalDates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := contracts.InitialPreparationPod{OperationID: ownerID(10), Requests: []contracts.InitialPreparationPodRequest{{ID: ownerID(11), OwnerID: ownerID(12), StartedAt: now, Until: now.Add(5 * time.Second)}}}
	if !validPreparationPodRequests(p) {
		t.Fatal("valid original request rejected")
	}
	for _, change := range []func(*contracts.InitialPreparationPod){
		func(p *contracts.InitialPreparationPod) {
			p.Requests[0].Until = now.Add(5*time.Second + time.Microsecond)
		},
		func(p *contracts.InitialPreparationPod) {
			p.Requests[0].Completion = &contracts.InitialPreparationPodRequestCompletion{Outcome: "created", CompletedAt: now.Add(5 * time.Second)}
		},
		func(p *contracts.InitialPreparationPod) {
			p.Requests[0].Completion = &contracts.InitialPreparationPodRequestCompletion{Outcome: "observed", CompletedAt: now}
		},
		func(p *contracts.InitialPreparationPod) { p.Requests = append(p.Requests, p.Requests[0]) },
	} {
		copy := p
		copy.Requests = append([]contracts.InitialPreparationPodRequest(nil), p.Requests...)
		change(&copy)
		if validPreparationPodRequests(copy) {
			t.Fatal("renewed, inferred or duplicated completion accepted")
		}
	}
}

func TestInitialPreparationPodRequestExhaustionKeepsOriginalIntent(t *testing.T) {
	f, _ := activationPreparerFixture(t)
	f.client.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return prepActivationRoundTrip(func(r *http.Request) (*http.Response, error) {
			if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/pods") {
				return preparationUnavailableResponse(), nil
			}
			return next.RoundTrip(r)
		})
	}
	p := f.preparer(t)
	defer p.Close()
	if _, e := p.PrepareGatedPod(context.Background()); e == nil {
		t.Fatal("synthetic unknown create reported successful")
	}
	f.mu.Lock()
	cm := f.objects["/api/v1/namespaces/bootstrap/configmaps/prepare"]
	var root contracts.InitialPreparationRoot
	_ = json.Unmarshal([]byte(cm["data"].(map[string]any)["root.json"].(string)), &root)
	original := root.Activation.Pod.OperationID
	first := root.Activation.Pod.Requests[0]
	for len(root.Activation.Pod.Requests) < contracts.InitialPreparationPodRequests {
		next := first
		next.ID = ownerID(300 + len(root.Activation.Pod.Requests))
		root.Activation.Pod.Requests = append(root.Activation.Pod.Requests, next)
	}
	raw, _ := json.Marshal(root)
	cm["data"].(map[string]any)["root.json"] = string(raw)
	f.mu.Unlock()
	if _, e := p.PrepareGatedPod(context.Background()); !errors.Is(e, ErrInitialPreparationRequestsUnresolved) {
		t.Fatal("exhausted unknown request budget retried or reset", e)
	}
	_, after, e := p.read(context.Background())
	if e != nil || after.Activation.Pod.OperationID != original || len(after.Activation.Pod.Requests) != contracts.InitialPreparationPodRequests {
		t.Fatal("budget exhaustion changed original records", e)
	}
}
