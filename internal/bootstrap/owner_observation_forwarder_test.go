package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
)

// Real process-owned client/server keys and mutual TLS/h2; registry, native
// workload/Ready observations, CA and regional result are synthetic component
// facts. This fixture does not qualify actual SQL/API or two-cluster latency.
type observationForwardFixture struct {
	t          *testing.T
	base       *runtimeFixture
	pin        value.OwnerObservationPin
	mode       string
	bound      time.Time
	callerEnd  time.Time
	client     value.OwnerBinding
	servers    []value.OwnerBinding
	mu         sync.Mutex
	identities map[value.OwnerCertificate]value.OwnerEnrollment
	get, post  atomic.Int32
	reads      atomic.Int32
	legacy     atomic.Int32
	readyReads atomic.Int32
	dials      atomic.Int32
	registry   atomic.Int32
	guards     atomic.Int32
	routes     atomic.Int32
	workloads  atomic.Int32
	activeGET  atomic.Int32
	maxGET     atomic.Int32
	claimed    atomic.Int32
	held       chan struct{}
	release    chan struct{}
	blocked    atomic.Int32
	handlers   sync.WaitGroup
}

func observationForwardID(n int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", n)
}
func (f *observationForwardFixture) checkBound(ctx context.Context) {
	if f.callerEnd.IsZero() {
		return
	}
	end, ok := ctx.Deadline()
	if !ok || end.After(f.callerEnd) {
		f.t.Error("original total caller interval was widened between legs")
	}
}
func (f *observationForwardFixture) configuration() value.OwnerConfigurationObservation {
	now := time.Now()
	c := f.base.configuration.Clone()
	if f.mode == "revision-after-get" && f.get.Load() > 0 || f.mode == "revision-after-post" && f.post.Load() > 0 {
		c.Revision.Generation++
	}
	return value.OwnerConfigurationObservation{Configuration: c, ObservedAt: now, FreshUntil: identity.Earlier(now.Add(5*time.Second), f.bound)}
}
func (f *observationForwardFixture) Enroll(ctx context.Context, r value.OwnerEnrollmentRequest) (value.IssuedOwnerCertificate, error) {
	csr, err := x509.ParseCertificateRequest(r.CSRDER)
	key, ke := mtls.EnrollmentKey(r.CSRDER)
	if err != nil || ke != nil || csr.CheckSignature() != nil || ctx.Err() != nil {
		return value.IssuedOwnerCertificate{}, value.ErrDenied
	}
	now := time.Now().UTC().Truncate(time.Second)
	_, until, _ := value.OwnerCertificateWindow(now)
	u, _ := mtls.OwnerURI(r.Binding)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(f.base.signings.Add(1))), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}, NotBefore: now.Add(-time.Second), NotAfter: until}
	if r.Usage == "server" {
		exact, _ := mtls.OwnerServerName(r.Binding)
		common, _ := mtls.OwnerBootstrapServerName(f.pin.Pool)
		leaf.DNSNames = []string{exact, common}
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.base.ca, csr.PublicKey, f.base.key)
	if err != nil {
		return value.IssuedOwnerCertificate{}, err
	}
	c := value.OwnerCertificate{Binding: r.Binding, Usage: r.Usage, Digest: artifact.Digest(sha256.Sum256(der)), NotBefore: leaf.NotBefore, NotAfter: until}
	e := value.OwnerEnrollment{ID: r.Binding.ProcessEpoch, Binding: r.Binding, Usage: r.Usage, Pool: f.pin.Pool, SourceUID: f.pin.SourceUID, Pod: "owner-" + r.Binding.PodUID, ReplicaSet: "owner-rs", ReplicaSetUID: runtimeID, PublicKeyDigest: key, InitialTokenDigest: artifact.Digest{1}, InitialWorkloadDigest: artifact.Digest{2}, InitialProtectionDigest: f.pin.ProtectionDigest, ClaimedAt: now, InitialHoldUntil: until.Add(time.Minute)}
	f.mu.Lock()
	f.identities[c] = e
	f.mu.Unlock()
	return value.IssuedOwnerCertificate{Certificate: c, DER: der}, nil
}
func (f *observationForwardFixture) ReadOwnerRegistration(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	f.checkBound(ctx)
	f.registry.Add(1)
	f.mu.Lock()
	e, ok := f.identities[c]
	f.mu.Unlock()
	if !ok || ctx.Err() != nil || f.mode == "revoked-after-get" && f.get.Load() > 0 || f.mode == "revoked-after-post" && f.post.Load() > 0 {
		return value.OwnerRegistrationObservation{}, value.ErrUnavailable
	}
	o := f.configuration()
	return value.OwnerRegistrationObservation{Certificate: c, Enrollment: e, Configuration: o, ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}, nil
}
func (f *observationForwardFixture) ReadContextStartOwners(context.Context) (value.APIContextOwnerCandidates, error) {
	f.legacy.Add(1)
	return value.APIContextOwnerCandidates{}, value.ErrUnavailable
}
func (f *observationForwardFixture) ReadOwnerObservationCandidates(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	f.checkBound(ctx)
	f.reads.Add(1)
	o := f.configuration()
	owners := slices.Clone(f.servers)
	if f.mode == "same-pod17" {
		owners = nil
		for i := 100; i < 116; i++ {
			b := f.servers[0]
			b.ProcessEpoch = observationForwardID(i)
			owners = append(owners, b)
		}
		owners = append(owners, f.servers[0])
	}
	if f.mode == "excluded-leaf" {
		owners[0].ProcessEpoch = observationForwardID(200)
	}
	if f.mode == "candidate-error" || ctx.Err() != nil {
		return value.APIContextOwnerCandidates{}, value.ErrUnavailable
	}
	return value.APIContextOwnerCandidates{Pool: f.pin.Pool, Owners: owners, ObservedAt: o.ObservedAt, ValidUntil: o.FreshUntil}, nil
}
func (f *observationForwardFixture) ReadyOwnerObservationCandidates(ctx context.Context, c value.APIContextOwnerCandidates) (value.OwnerObservationCandidateGroups, error) {
	f.checkBound(ctx)
	f.readyReads.Add(1)
	if f.mode == "ready-error" || ctx.Err() != nil {
		return value.OwnerObservationCandidateGroups{}, value.ErrUnavailable
	}
	if f.mode == "mutated-candidate-input" {
		c.Owners[0].ProcessEpoch = observationForwardID(200)
	}
	groups := make([]value.OwnerObservationCandidateGroup, 0, len(f.servers))
	for _, server := range f.servers {
		g := value.OwnerObservationCandidateGroup{PodUID: server.PodUID}
		for _, b := range c.Owners {
			if b.PodUID == server.PodUID {
				g.Owners = append(g.Owners, b)
			}
		}
		groups = append(groups, g)
	}
	if f.mode == "empty-ready" {
		groups = nil
	}
	return value.OwnerObservationCandidateGroups{Candidates: c, Groups: groups, EndpointResourceVersion: "17", ObservedAt: time.Now(), ValidUntil: c.ValidUntil}, nil
}
func (f *observationForwardFixture) CurrentOwnerRoute(ctx context.Context, b value.OwnerBinding) (value.OwnerRoute, error) {
	f.checkBound(ctx)
	f.routes.Add(1)
	if ctx.Err() != nil || f.mode == "route-loss-after-get" && f.get.Load() > 0 {
		return value.OwnerRoute{}, value.ErrUnavailable
	}
	o := f.configuration()
	address := "10.0.0.200"
	for i, v := range f.servers {
		if b.PodUID == v.PodUID {
			address = fmt.Sprintf("10.0.0.%d", i+1)
		}
	}
	return value.OwnerRoute{Configuration: o, Endpoint: value.OwnerEndpoint{Binding: b, Pool: f.pin.Pool, Pod: "owner-" + b.PodUID, ReplicaSetUID: runtimeID, Addresses: []string{address}, ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}, ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}, nil
}
func (f *observationForwardFixture) ReadOwnerProtection(ctx context.Context, p value.OwnerPool) (value.OwnerProtection, error) {
	f.checkBound(ctx)
	f.guards.Add(1)
	if ctx.Err() != nil || f.mode == "guard-loss-after-get" && f.get.Load() > 0 {
		return value.OwnerProtection{}, value.ErrUnavailable
	}
	o := f.configuration()
	return value.OwnerProtection{Pool: p, Digest: f.pin.ProtectionDigest, ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}, nil
}
func (f *observationForwardFixture) ObserveOwnerWorkload(ctx context.Context, b value.OwnerBinding, pod string) (value.OwnerObservationWorkload, error) {
	f.checkBound(ctx)
	f.workloads.Add(1)
	if f.mode == "blocked-proof" {
		if f.blocked.Add(1) <= 2 {
			f.held <- struct{}{}
		}
		<-ctx.Done()
		<-f.release
		return value.OwnerObservationWorkload{}, value.ErrUnavailable
	}
	if ctx.Err() != nil || f.mode == "template-loss-after-get" && f.get.Load() > 0 {
		return value.OwnerObservationWorkload{}, value.ErrUnavailable
	}
	o := f.configuration()
	return value.OwnerObservationWorkload{Pin: f.pin, Binding: b, Pod: pod, ReplicaSetUID: runtimeID, WorkloadDigest: artifact.Digest{9}, ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}, nil
}

func (f *observationForwardFixture) handler(index int, w http.ResponseWriter, r *http.Request) {
	f.handlers.Add(1)
	defer f.handlers.Done()
	common, _ := mtls.OwnerBootstrapServerName(f.pin.Pool)
	exact, _ := mtls.OwnerServerName(f.servers[index])
	if r.TLS == nil || r.ProtoMajor != 2 || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) != 1 || len(r.TLS.VerifiedChains) == 0 || len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Idempotency-Key")) != 0 {
		f.t.Error("wrong native peer transport or credential forwarding")
		http.Error(w, "unavailable", 503)
		return
	}
	if r.Method == http.MethodGet {
		f.get.Add(1)
		n := f.activeGET.Add(1)
		defer f.activeGET.Add(-1)
		for old := f.maxGET.Load(); n > old && !f.maxGET.CompareAndSwap(old, n); old = f.maxGET.Load() {
		}
		if r.TLS.ServerName != common || r.Host != net.JoinHostPort(common, strconv.Itoa(f.pin.Pool.NativePort)) || r.ContentLength != 0 || r.Header.Get("Accept") != contracts.ClusterObservationLocatorMediaType || r.Header.Get("Content-Type") != "" {
			f.t.Error("locator did not bind common SNI and exact GET authority")
			http.Error(w, "unavailable", 503)
			return
		}
		q, err := contracts.DecodeClusterObservationLocatorTarget(r.RequestURI)
		if err != nil {
			f.t.Error("invalid original locator query")
			return
		}
		if f.mode == "unknown-first" && index == 0 || f.mode == "all-unknown" {
			http.Error(w, "unavailable", 503)
			return
		}
		if f.mode == "blocked-headers" || f.mode == "cancel-other-get" && index == 1 {
			f.held <- struct{}{}
			<-r.Context().Done()
			return
		}
		if f.mode == "cancel-other-get" && index == 0 {
			select {
			case <-f.held:
			case <-r.Context().Done():
				return
			}
		}
		requested, _ := time.Parse(time.RFC3339Nano, q.RequestedAt)
		until, _ := time.Parse(time.RFC3339Nano, q.NotAfter)
		out := value.ClusterObservationLocator{RequestID: q.RequestID, Challenge: q.Challenge, RootID: q.RootID, ClusterID: q.ClusterID, Holder: f.servers[index], ExchangeID: observationForwardID(300 + index), Sequence: 1<<53 + 1, Interval: value.ClusterObservationInterval{ObservedAt: identity.Earlier(time.Now(), until), FreshUntil: identity.Earlier(f.bound, until)}}
		if out.Interval.ObservedAt.Before(requested) {
			f.t.Error("fixture clock before query")
		}
		if f.mode == "wrong-holder" {
			out.Holder.ProcessEpoch = observationForwardID(200)
		}
		body, err := contracts.EncodeClusterObservationLocator(wire.LocatorWire(out))
		if err != nil {
			f.t.Error("locator fixture encoding", err)
			return
		}
		f.reply(w, body, contracts.ClusterObservationLocatorMediaType, f.mode == "truncated-get")
		return
	}
	if r.Method != http.MethodPost || r.TLS.ServerName != exact || r.Host != net.JoinHostPort(exact, strconv.Itoa(f.pin.Pool.NativePort)) || r.RequestURI != contracts.ClusterObservationClaimPath || r.Header.Get("Content-Type") != contracts.ClusterObservationClaimMediaType || r.Header.Get("Accept") != contracts.ClusterObservationClaimMediaType {
		f.t.Error("claim did not bind exact SNI/path/purpose")
		http.Error(w, "unavailable", 503)
		return
	}
	f.post.Add(1)
	f.claimed.Store(int32(index + 1))
	data, err := io.ReadAll(io.LimitReader(r.Body, contracts.ClusterObservationClaimBytes+1))
	claim, de := contracts.DecodeClusterObservationClaim(data)
	clear(data)
	if err != nil || de != nil || claim.Locator.Holder.ProcessEpoch != f.servers[index].ProcessEpoch || claim.Locator.Sequence != 1<<53+1 {
		f.t.Error("claim changed exact selected holder or uint64 sequence")
		return
	}
	request, digest, err := wire.ParseRequest(claim.Request, time.Now())
	if err != nil {
		f.t.Error("invalid original metadata request", err)
		return
	}
	if f.mode == "unknown-claim" {
		http.Error(w, "unavailable", 503)
		return
	}
	if f.mode == "blocked-body" {
		w.Header().Set("Content-Type", contracts.ClusterObservationClaimMediaType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("{"))
		_ = http.NewResponseController(w).Flush()
		f.held <- struct{}{}
		<-r.Context().Done()
		return
	}
	now := time.Now()
	out := value.ClusterObservationResult{RequestID: request.ID, Challenge: request.Challenge, RootID: request.RootID, ClusterID: request.ClusterID, Purpose: request.Purpose, RequestDigest: digest, Interval: value.ClusterObservationInterval{ObservedAt: now, FreshUntil: identity.Earlier(f.bound, request.NotAfter)}, Guard: &value.ClusterNamespaceGuardObservation{Digest: artifact.Digest{8}, Keys: []string{"team"}, Interval: value.ClusterObservationInterval{ObservedAt: now, FreshUntil: identity.Earlier(f.bound, request.NotAfter)}}}
	body, err := contracts.EncodeClusterObservationResult(wire.ResultWire(out))
	if err != nil {
		f.t.Error("result fixture encoding", err)
		return
	}
	f.reply(w, body, contracts.ClusterObservationClaimMediaType, f.mode == "truncated-claim")
}
func (f *observationForwardFixture) reply(w http.ResponseWriter, body []byte, media string, partial bool) {
	w.Header().Set("Content-Type", media)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if partial {
		_, _ = w.Write(body[:1])
		_ = http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	}
	_, _ = w.Write(body)
}

func observationForwardRequest() value.ClusterObservationRequest {
	now := time.Now()
	return value.ClusterObservationRequest{ID: observationForwardID(500), Challenge: observationForwardID(501), RootID: observationForwardID(900), ClusterID: observationForwardID(502), Purpose: value.ObserveCapacityNamespaceGuard, RequestedAt: now, NotAfter: now.Add(5 * time.Second)}
}
