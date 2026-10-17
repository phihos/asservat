package clusterobservation

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
)

func localID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func localPin() fleet.ClusterObservationCallerPin {
	return fleet.ClusterObservationCallerPin{RootID: localID(1), InstallationID: localID(2), ClusterID: localID(3), Namespace: cfg.NamespaceRef{Name: "control", UID: localID(4)}, Account: "hwork", AccountUID: localID(5), Deployment: "hwork", DeploymentUID: localID(6), TemplateDigest: artifact.Digest{1}, ImageDigest: artifact.Digest{2}, ProtectionDigest: artifact.Digest{3}}
}

type localTokenFunc func(context.Context) ([]byte, error)

func (f localTokenFunc) ReadClusterObservationToken(c context.Context) ([]byte, error) { return f(c) }

type localCallerFunc func(context.Context, []byte, string, fleet.ClusterObservationRequest) (fleet.ClusterObservationCaller, error)

func (f localCallerFunc) ObserveClusterObservationCaller(c context.Context, b []byte, p string, r fleet.ClusterObservationRequest) (fleet.ClusterObservationCaller, error) {
	return f(c, b, p, r)
}

type localExchangeFunc func(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error)

func (f localExchangeFunc) ObserveCluster(c context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	return f(c, r)
}
func localRequest() fleet.ClusterObservationRequest {
	now := time.Now().UTC()
	return fleet.ClusterObservationRequest{ID: localID(10), Challenge: localID(11), RootID: localID(1), ClusterID: localID(12), Purpose: fleet.ObserveCapacityNamespaces, RequestedAt: now, NotAfter: now.Add(5 * time.Second)}
}
func localProof(r fleet.ClusterObservationRequest) fleet.ClusterObservationCaller {
	return fleet.ClusterObservationCaller{Pin: localPin(), Pod: "hwork-pod", PodUID: localID(7), ReplicaSet: "hwork-rs", ReplicaSetUID: localID(8), WorkloadDigest: artifact.Digest{9}, ObservedAt: time.Now().UTC(), FreshUntil: r.NotAfter}
}
func localResult(r fleet.ClusterObservationRequest) fleet.ClusterObservationResult {
	d, _ := RequestDigest(r)
	return fleet.ClusterObservationResult{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: r.Purpose, RequestDigest: d, Interval: fleet.ClusterObservationInterval{ObservedAt: time.Now().UTC(), FreshUntil: r.NotAfter}, Namespaces: &fleet.ClusterNamespaceCandidatePage{ResourceVersion: "10", Items: []cfg.NamespaceRef{}}}
}
func localServer(t *testing.T, caller localCallerFunc, exchange localExchangeFunc, maximum int) (*LocalHandler, *LocalClient, *httptest.Server) {
	t.Helper()
	var h *LocalHandler
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	s.EnableHTTP2 = true
	s.StartTLS()
	var e error
	h, e = NewLocalHandler(context.Background(), strings.TrimPrefix(s.URL, "https://"), localPin(), caller, exchange, maximum, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	c, e := NewLocalClient(context.Background(), s.URL, localPin().RootID, localID(7), pool, localTokenFunc(func(context.Context) ([]byte, error) { return []byte("synthetic-projected-token"), nil }), 2, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close(); h.Close(); s.Close() })
	return h, c, s
}

// Actual h2/TLS and body handling, but synthetic caller and regional authority.
// Native local Pod/TokenReview/guard and remote mTLS qualification are separate.
func TestClusterObservationLocalTLSOriginalCallerAndSelection(t *testing.T) {
	for _, mode := range []string{"valid", "caller-denied", "caller-replaced-after-read", "caller-first-shortened", "wrong-target", "wrong-purpose", "wrong-request-digest", "wrong-page", "remote-unavailable", "expiry-before-delivery"} {
		t.Run(mode, func(t *testing.T) {
			var calls, reads atomic.Int32
			var firstEnd atomic.Int64
			caller := localCallerFunc(func(c context.Context, token []byte, pod string, r fleet.ClusterObservationRequest) (fleet.ClusterObservationCaller, error) {
				n := calls.Add(1)
				if string(token) != "synthetic-projected-token" || pod != localID(7) {
					t.Error("token/pod hint changed")
				}
				v := localProof(r)
				if mode == "caller-denied" {
					return fleet.ClusterObservationCaller{}, fleet.ErrDenied
				}
				if mode == "caller-replaced-after-read" && n > 1 {
					v.WorkloadDigest[0]++
				}
				if mode == "caller-first-shortened" && n == 1 {
					firstEnd.Store(time.Now().Add(time.Second).UnixNano())
					v.FreshUntil = time.Unix(0, firstEnd.Load())
				}
				return v, nil
			})
			exchange := localExchangeFunc(func(c context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
				reads.Add(1)
				if d, ok := c.Deadline(); !ok || d.After(r.NotAfter) {
					t.Error("original remote call bound missing")
				}
				if mode == "caller-first-shortened" {
					if d, _ := c.Deadline(); d.After(time.Unix(0, firstEnd.Load())) {
						t.Error("first caller deadline renewed")
					}
				}
				if mode == "remote-unavailable" {
					return fleet.ClusterObservationResult{}, fleet.ErrUnavailable
				}
				v := localResult(r)
				switch mode {
				case "wrong-target":
					v.ClusterID = localID(99)
				case "wrong-purpose":
					v.Purpose = fleet.ObserveCapacityWorkloads
				case "wrong-request-digest":
					v.RequestDigest[0] ^= 1
				case "wrong-page":
					v.Namespaces.Items = nil
				case "expiry-before-delivery":
					v.Interval.FreshUntil = time.Now().Add(-time.Millisecond)
				}
				return v, nil
			})
			_, client, _ := localServer(t, caller, exchange, 2)
			r := localRequest()
			got, e := client.ObserveCluster(context.Background(), r)
			if mode == "valid" || mode == "caller-first-shortened" {
				d, _ := RequestDigest(r)
				if e != nil || !got.Matches(r, d, time.Now()) || calls.Load() != 2 || reads.Load() != 1 {
					t.Fatalf("local h2 read failed: %v", e)
				}
				if mode == "caller-first-shortened" && got.Interval.FreshUntil.After(time.Unix(0, firstEnd.Load())) {
					t.Fatal("returned first proof deadline renewed")
				}
			} else if e == nil {
				t.Fatal("unsafe local response accepted")
			}
			if mode == "caller-denied" && reads.Load() != 0 {
				t.Fatal("regional metadata read before local caller eligibility")
			}
		})
	}
}

func TestClusterObservationLocalCancellationJoinsAndRetainsSlot(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	returned := make(chan struct{})
	caller := localCallerFunc(func(_ context.Context, _ []byte, _ string, r fleet.ClusterObservationRequest) (fleet.ClusterObservationCaller, error) {
		return localProof(r), nil
	})
	exchange := localExchangeFunc(func(c context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
		close(entered)
		<-c.Done()
		<-release
		close(returned)
		return fleet.ClusterObservationResult{}, fleet.ErrUnavailable
	})
	h, client, _ := localServer(t, caller, exchange, 1)
	response := make(chan error, 1)
	go func() { _, e := client.ObserveCluster(context.Background(), localRequest()); response <- e }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first exchange not entered")
	}
	if _, e := client.ObserveCluster(context.Background(), localRequest()); e == nil {
		t.Fatal("full handler slot admitted another exchange")
	}
	closed := make(chan struct{})
	go func() { h.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned before actual remote work joined")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not join")
	}
	select {
	case <-returned:
	default:
		t.Fatal("slot released before reader joined")
	}
	if e := <-response; e == nil {
		t.Fatal("cancelled exchange succeeded")
	}
	if _, e := client.ObserveCluster(context.Background(), localRequest()); e == nil {
		t.Fatal("closed handler admitted work")
	}
}

func TestClusterObservationLocalUnknownPOSTIsNotRetried(t *testing.T) {
	var requests atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", contracts.ClusterObservationLocalMedia)
		w.Header().Set("Content-Length", "128")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{"))
		_ = http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	}))
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	c, e := NewLocalClient(context.Background(), s.URL, localID(1), localID(7), pool, localTokenFunc(func(context.Context) ([]byte, error) { return []byte("synthetic"), nil }), 1, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = c.ObserveCluster(context.Background(), localRequest()); e == nil {
		t.Fatal("unknown reply accepted")
	}
	if requests.Load() != 1 {
		t.Fatal("unknown POST replayed")
	}
}

func TestClusterObservationLocalOriginalDeadlineIncludesTokenRead(t *testing.T) {
	var requests atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); http.Error(w, "not reached", 500) }))
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	c, e := NewLocalClient(context.Background(), s.URL, localID(1), localID(7), pool, localTokenFunc(func(c context.Context) ([]byte, error) { <-c.Done(); return []byte("synthetic"), nil }), 1, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, e = c.ObserveCluster(ctx, localRequest()); e == nil {
		t.Fatal("expired original caller deadline renewed after token read")
	}
	if requests.Load() != 0 {
		t.Fatal("network effect began after original deadline")
	}
}

func TestClusterObservationChildIntervalsCannotEscapeRelayCap(t *testing.T) {
	r := localRequest()
	r.Purpose = fleet.ObserveCapacityNamespaceGuard
	d, _ := RequestDigest(r)
	v := localResult(r)
	v.Namespaces = nil
	v.Guard = &fleet.ClusterNamespaceGuardObservation{Digest: artifact.Digest{1}, Keys: []string{"team"}, Interval: fleet.ClusterObservationInterval{ObservedAt: r.RequestedAt, FreshUntil: r.NotAfter}}
	end := r.RequestedAt.Add(time.Second)
	out := v.Restrict(r.RequestedAt, end)
	if !out.Matches(r, d, time.Now()) || out.Guard.Interval.FreshUntil != end || v.Guard.Interval.FreshUntil != r.NotAfter {
		t.Fatal("child interval escaped cap or original aliased")
	}
	out.Guard.Keys[0] = "changed"
	if v.Guard.Keys[0] != "team" {
		t.Fatal("result aliases producer keys")
	}
}
