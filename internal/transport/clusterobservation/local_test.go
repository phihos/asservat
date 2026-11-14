package clusterobservation

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
