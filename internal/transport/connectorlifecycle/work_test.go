package connectorlifecycle

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/fleet"
)

const (
	workClusterA = "10000000-0000-4000-8000-00000000000a"
	workClusterB = "10000000-0000-4000-8000-00000000000b"
)

type workTokens struct{}

func (workTokens) VerifyConnectorUntil(_ context.Context, token string) (fleet.ConnectorCluster, time.Time, error) {
	cluster, lifetime := workClusterA, time.Minute
	switch token {
	case "A":
	case "B":
		cluster = workClusterB
	case "short":
		lifetime = 100 * time.Millisecond
	case "expired":
		lifetime = -time.Second
	default:
		return fleet.ConnectorCluster{}, time.Time{}, fleet.ErrDenied
	}
	return fleet.ConnectorCluster{ClusterID: cluster}, time.Now().Add(lifetime), nil
}

func workFixture(t *testing.T, h *WorkHandler) (func(string) *Client, <-chan string) {
	t.Helper()
	ended := make(chan string, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		ended <- strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return func(token string) *Client {
		t.Helper()
		client, err := NewClient(server.URL, roots, func() ([]byte, error) { return []byte(token), nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		return client
	}, ended
}

func startWorkWatch(t *testing.T, client *Client) (<-chan WorkHint, <-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	hints, done := make(chan WorkHint, 8), make(chan error, 1)
	go func() { done <- client.WatchWork(ctx, func(h WorkHint) { hints <- h }) }()
	return hints, done, cancel
}

func workEvent[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for work stream event")
		var zero T
		return zero
	}
}

func testWorkHint(cluster string, until time.Time) WorkHint {
	p := testProcess()
	return WorkHint{Cluster: cluster, Until: until, Owner: fleet.OwnerBinding{
		InstallationID: p.Binding.InstallationID, ClusterID: p.Binding.ClusterID,
		IssuerEpoch: p.Binding.IssuerEpoch, PodUID: p.PodUID, ProcessEpoch: p.ProcessEpoch,
	}}
}

func publishHint(t *testing.T, h *WorkHandler, hint WorkHint) {
	t.Helper()
	payload, err := json.Marshal(hint)
	if err != nil {
		t.Error(err)
		return
	}
	h.Publish(string(payload))
}

func TestWorkWatchRoutesToAuthenticatedClustersAndResyncs(t *testing.T) {
	ready := make(chan string, 8)
	h := &WorkHandler{Tokens: workTokens{}, Concurrency: 2}
	h.Ready = func(_ context.Context, cluster string) error { ready <- cluster; return nil }
	client, ended := workFixture(t, h)
	a, doneA, cancelA := startWorkWatch(t, client("A"))
	if got := workEvent(t, ready); got != workClusterA {
		t.Fatal("registered", got)
	}
	b, doneB, cancelB := startWorkWatch(t, client("B"))
	if got := workEvent(t, ready); got != workClusterB {
		t.Fatal("registered", got)
	}

	until := time.Now().UTC().Add(time.Minute)
	first, second := testWorkHint(workClusterA, until), testWorkHint(workClusterA, until.Add(time.Second))
	other := testWorkHint(workClusterB, until)
	publishHint(t, h, testWorkHint(workClusterA, until.Add(-2*time.Minute)))
	publishHint(t, h, first)
	publishHint(t, h, second)
	publishHint(t, h, other)
	if workEvent(t, a) != first || workEvent(t, a) != second || workEvent(t, b) != other {
		t.Fatal("work streams mixed cluster identities, collapsed requests or changed a deadline")
	}

	cancelA()
	if workEvent(t, doneA) == nil || workEvent(t, ended) != "A" {
		t.Fatal("client cancellation did not end stream A")
	}
	h.Publish("") // PostgreSQL LISTEN reestablished after an interruption.
	if got := workEvent(t, ready); got != workClusterB {
		t.Fatal("resync registered a disconnected connector", got)
	}
	publishHint(t, h, other)
	if workEvent(t, b) != other {
		t.Fatal("remaining stream lost work")
	}
	cancelB()
	if workEvent(t, doneB) == nil || workEvent(t, ended) != "B" {
		t.Fatal("client cancellation did not end stream B")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subscribers) != 0 {
		t.Fatal("disconnected subscribers retained", h.subscribers)
	}
}

func TestWorkWatchIdleStreamEndsAtTokenExpiry(t *testing.T) {
	ready := make(chan string, 8)
	h := &WorkHandler{Tokens: workTokens{}, Concurrency: 1, Ready: func(_ context.Context, cluster string) error { ready <- cluster; return nil }}
	client, ended := workFixture(t, h)
	for _, token := range []string{"expired", "unknown"} {
		_, done, _ := startWorkWatch(t, client(token))
		if !errors.Is(workEvent(t, done), ErrChannel) || workEvent(t, ended) != token {
			t.Fatal("accepted invalid token", token)
		}
	}
	hints, done, _ := startWorkWatch(t, client("short"))
	if workEvent(t, ready) != workClusterA || workEvent(t, done) == nil || workEvent(t, ended) != "short" {
		t.Fatal("idle stream did not end at original token expiry")
	}
	if len(hints) != 0 || len(ready) != 0 {
		t.Fatal("idle stream generated work or repeated its registration")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subscribers) != 0 {
		t.Fatal("expired subscriber retained")
	}
}

func TestWorkWatchRecoversOutstandingWorkAtSubscriptionAndAfterBackpressure(t *testing.T) {
	until := time.Now().UTC().Add(time.Minute)
	first, second := testWorkHint(workClusterA, until), testWorkHint(workClusterA, until.Add(time.Second))
	h := &WorkHandler{Tokens: workTokens{}, Concurrency: 1}
	outstanding := []WorkHint{first, second}
	h.Ready = func(_ context.Context, _ string) error {
		// Owners with waiting callers can respond before the stream sends
		// its first byte. Two hints fill and overflow the one-slot queue.
		for _, hint := range outstanding {
			publishHint(t, h, hint)
		}
		return nil
	}
	client, ended := workFixture(t, h)
	h.Publish("") // LISTEN established before the connector subscribes.
	publishHint(t, h, first)
	connector := client("A")
	hints, done, _ := startWorkWatch(t, connector)
	if workEvent(t, hints) != first || workEvent(t, done) == nil || workEvent(t, ended) != "A" {
		t.Fatal("overloaded stream did not drain and disconnect")
	}
	outstanding = outstanding[1:]
	hints, _, cancel := startWorkWatch(t, connector)
	if workEvent(t, hints) != second {
		t.Fatal("remaining demand was lost during reconnect")
	}
	cancel()
	if workEvent(t, ended) != "A" {
		t.Fatal("reconnected stream leaked")
	}
}

func TestWorkWatchFailedReadyClosesStreamForRetry(t *testing.T) {
	h := &WorkHandler{Tokens: workTokens{}, Concurrency: 1, Ready: func(context.Context, string) error { return errors.New("database unavailable") }}
	client, ended := workFixture(t, h)
	_, done, _ := startWorkWatch(t, client("A"))
	if !errors.Is(workEvent(t, done), ErrChannel) || workEvent(t, ended) != "A" {
		t.Fatal("subscription accepted despite failed readiness notification")
	}
}
