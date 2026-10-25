package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type ownerObservationCostSQL struct {
	registry                          app.OwnerCertificateRegistry
	configuration                     app.OwnerConfigurationReader
	registryCalls, configurationCalls atomic.Int64
}

func (s *ownerObservationCostSQL) ReadOwnerRegistration(c context.Context, v value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	s.registryCalls.Add(1)
	return s.registry.ReadOwnerRegistration(c, v)
}
func (s *ownerObservationCostSQL) ReadOwnerConfiguration(c context.Context) (value.OwnerConfigurationObservation, error) {
	s.configurationCalls.Add(1)
	return s.configuration.ReadOwnerConfiguration(c)
}

type ownerObservationCostOutcome struct {
	FirstError, LastError                             string
	FirstNanos, LastNanos, TotalNanos, RemainingNanos int64
	FirstNative                                       ownerObservationCostCount
	Native                                            ownerObservationCostCount
}

func ownerObservationCostError(e error) string {
	switch {
	case e == nil:
		return "none"
	case errors.Is(e, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(e, context.Canceled):
		return "cancelled"
	case errors.Is(e, value.ErrDenied):
		return "denied"
	case errors.Is(e, value.ErrUnavailable):
		return "unavailable"
	default:
		return "other"
	}
}

// This deliberately demonstrates an availability defect, not successful native
// routing. Both checks are the exact concrete receiver adapter for one locator
// pre/post pair, sharing its original five seconds. Native APIs, independent
// admission denial, current SQL, audited activation, process-owned keys and h2
// are real. Initial recovery/source/pins/private CA and encrypted audit wrapping
// root are fixture authorities. No listener/runtime/installed-v2 is selected.
func TestOwnerObservationReceiverOriginalBudgetWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("owned context Kubernetes/SQL/S3 fixture required")
	}
	raw, e := os.ReadFile(path)
	var f fixture
	if e != nil || json.Unmarshal(raw, &f) != nil || len(f.Clusters) == 0 || f.Postgres == "" || f.S3 == "" {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	x := newOwnerObservationNativeCostFixture(t, ctx, f)
	ca, key := connectorSQLCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	c := value.OwnerConfiguration{Pool: x.pool, Revision: identity.Revision{UID: x.pin.SourceUID, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: x.pin.ProtectionDigest, IssuerRoots: [][]byte{ca.Raw}}
	lab := ownerConfigurationLab(t, ctx, f, c)
	sql := newContextStartOwnerSQL(t, ctx, lab, c, contextStartOwnerIssuer{ca, key})
	// Initial registration provenance is explicitly fixture-supplied, but refers
	// to the actual original Pod/ReplicaSet. Current requests re-read the entire
	// native chain; this proof cannot replace their guard or activation checks.
	coordinator := sql.coordinator()
	coordinator.Proofs = ownerProofFunction(func(call context.Context, r value.OwnerEnrollmentRequest) (value.OwnerEnrollmentProof, error) {
		n := time.Now().UTC()
		o, e := sql.refresh(call, 5*time.Second)
		if e != nil {
			return value.OwnerEnrollmentProof{}, e
		}
		d, e := mtls.EnrollmentKey(r.CSRDER)
		if e != nil {
			return value.OwnerEnrollmentProof{}, e
		}
		rsName := ""
		for _, v := range x.pod.OwnerReferences {
			if v.Kind == "ReplicaSet" {
				rsName = v.Name
			}
		}
		return value.OwnerEnrollmentProof{Binding: r.Binding, Usage: r.Usage, Configuration: o, Pod: x.pod.Name, ReplicaSet: rsName, ReplicaSetUID: x.replica, PublicKeyDigest: d, TokenDigest: artifact.Digest{1}, WorkloadDigest: artifact.Digest{2}, ProtectionDigest: x.pin.ProtectionDigest, ObservedAt: n, FreshUntil: identity.Earlier(n.Add(5*time.Second), o.FreshUntil)}, nil
	})
	binding := value.OwnerBinding{InstallationID: x.pool.InstallationID, ClusterID: x.pool.ClusterID, IssuerEpoch: x.pool.IssuerEpoch, PodUID: string(x.pod.UID), ProcessEpoch: custodyID()}
	server, e := mtls.NewOwnerCredentialsForPool(binding, "server", x.pool, roots, coordinator, sql.reader, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(server.Close)
	binding.ProcessEpoch = custodyID()
	client, e := mtls.NewOwnerCredentialsForPool(binding, "client", x.pool, roots, coordinator, sql.reader, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	if e = server.Enroll(ctx); e != nil {
		t.Fatal("actual server activation", e)
	}
	if e = client.Enroll(ctx); e != nil {
		t.Fatal("actual client activation", e)
	}
	sql.closeEffects()
	// Fresh observations belong to an independent fixture owner, never a runtime
	// read. Every stored value retains its original five-second interval. Join on
	// every fatal/cancel path and fail on owner failure, rather than log/continue.
	owner, stopOwner := context.WithCancel(ctx)
	ownerDone := make(chan error, 1)
	ownerReady := make(chan struct{})
	var ownerFailed atomic.Bool
	var ownerRefreshes atomic.Int64
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		first := true
		for {
			refresh, end := context.WithTimeout(owner, 5*time.Second)
			_, err := sql.refresh(refresh, 5*time.Second)
			end()
			if err != nil {
				if owner.Err() != nil {
					ownerDone <- nil
				} else {
					ownerFailed.Store(true)
					ownerDone <- err
					cancel()
				}
				return
			}
			ownerRefreshes.Add(1)
			if first {
				close(ownerReady)
				first = false
			}
			select {
			case <-owner.Done():
				ownerDone <- nil
				return
			case <-ticker.C:
			}
		}
	}()
	t.Cleanup(func() {
		stopOwner()
		if e := <-ownerDone; e != nil {
			t.Error("independent fixture source owner failed")
		}
	})
	select {
	case <-ownerReady:
	case <-ctx.Done():
		t.Fatal("independent fixture source owner did not start")
	}
	// One fresh concrete observer/probe pair grants the original implementation
	// its full initial burst. We do not add parallel clients or enlarge 20/20.
	observer, guard := x.readers(t)
	endpoints, e := kube.NewOwnerEndpoints(observer, x.pool)
	if e != nil {
		t.Fatal(e)
	}
	workloads, e := kube.NewOwnerObservationWorkload(observer, guard, x.pin)
	if e != nil {
		t.Fatal(e)
	}
	ports := &ownerObservationCostSQL{registry: sql.reader, configuration: lab.reader}
	owners := &app.OwnerAuthenticator{Registry: ports, Routes: &app.OwnerRoutes{Configurations: ports, Endpoints: endpoints, Now: time.Now}, Protection: guard, Now: time.Now}
	checker, e := mtls.NewOwnerObservationRoutingPeers(x.pin, server, owners, workloads, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	serving, e := mtls.NewOwnerBootstrapServing(server, x.pool)
	if e != nil {
		t.Fatal(e)
	}
	common, e := mtls.OwnerBootstrapServerName(x.pool)
	if e != nil {
		t.Fatal(e)
	}
	outcome := make(chan ownerObservationCostOutcome, 1)
	handlerDone := make(chan struct{})
	query := make(chan value.ClusterObservationLocatorQuery, 1)
	var handlerCalls atomic.Int32
	// The request's interval is created once before TLS. The handler only narrows
	// its context to that original bound. No raw error/body is retained.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handlerCalls.Add(1) != 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer close(handlerDone)
		q := <-query // One original request; channel publication prevents a setup race.
		call, end := context.WithDeadline(r.Context(), q.NotAfter)
		defer end()
		started := time.Now()
		var v ownerObservationCostOutcome
		if r.ProtoMajor != 2 || r.TLS == nil || r.TLS.ServerName != common {
			v.FirstError = "unexpected-transport"
			outcome <- v
			w.WriteHeader(503)
			return
		}
		first, e := checker.CheckObservationRouting(call, r.TLS, q)
		v.FirstNanos = time.Since(started).Nanoseconds()
		v.FirstError = ownerObservationCostError(e)
		v.FirstNative = x.counter.snapshot()
		if e == nil {
			// Match the real handler's post-operation narrowing. Omitting the
			// local holder lookup makes this the most favorable possible pair.
			finalCall, stopFinal := context.WithDeadline(call, first.Interval.FreshUntil)
			defer stopFinal()
			lastStart := time.Now()
			last, e := checker.CheckObservationRouting(finalCall, r.TLS, q)
			v.LastNanos = time.Since(lastStart).Nanoseconds()
			v.LastError = ownerObservationCostError(e)
			if e == nil && !first.SamePeers(last) {
				v.LastError = "changed"
			}
		} else {
			v.LastError = "not-entered"
		}
		v.TotalNanos = time.Since(started).Nanoseconds()
		v.RemainingNanos = time.Until(q.NotAfter).Nanoseconds()
		v.Native = x.counter.snapshot()
		outcome <- v
		w.WriteHeader(503)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, GetCertificate: serving.GetCertificate, SessionTicketsDisabled: true, NextProtos: []string{"h2"}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tr := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: common, RootCAs: roots, GetClientCertificate: client.GetClientCertificate, SessionTicketsDisabled: true}}
	t.Cleanup(tr.CloseIdleConnections)
	n := time.Now().UTC()
	q := value.ClusterObservationLocatorQuery{RequestID: custodyID(), Challenge: custodyID(), RootID: x.pin.RootID, ClusterID: custodyID(), RequestedAt: n, NotAfter: n.Add(5 * time.Second)}
	query <- q
	x.counter.arm()
	beforeRefreshes := ownerRefreshes.Load()
	beforeRegistry, beforeConfig := sql.readPool.Stat(), lab.readerPool.Stat()
	call, end := context.WithDeadline(ctx, q.NotAfter)
	defer end()
	request, e := http.NewRequestWithContext(call, http.MethodGet, srv.URL, nil)
	if e != nil {
		t.Fatal(e)
	}
	response, transportError := (&http.Client{Transport: tr}).Do(request)
	if response != nil {
		response.Body.Close()
	}
	// This cleanup allowance does not reach any authority or API context. It
	// merely joins the handler already cancelled by the original request.
	joined, stopJoin := context.WithTimeout(ctx, time.Second)
	defer stopJoin()
	var measured ownerObservationCostOutcome
	select {
	case measured = <-outcome:
	case <-joined.Done():
		t.Fatal("native proof handler did not join", ownerObservationCostError(transportError))
	}
	select {
	case <-handlerDone:
	case <-joined.Done():
		t.Fatal("native proof handler did not finish response cleanup")
	}
	afterRegistry, afterConfig := sql.readPool.Stat(), lab.readerPool.Stat()
	t.Logf("receiver admission cost: fixed-phase=%+v registry-port-calls=%d configuration-port-calls=%d registry-acquires=%d configuration-shared-acquires=%d registry-acquire-ns=%d configuration-shared-acquire-ns=%d source-owner-refreshes=%d transport=%s", measured, ports.registryCalls.Load(), ports.configurationCalls.Load(), afterRegistry.AcquireCount()-beforeRegistry.AcquireCount(), afterConfig.AcquireCount()-beforeConfig.AcquireCount(), (afterRegistry.AcquireDuration() - beforeRegistry.AcquireDuration()).Nanoseconds(), (afterConfig.AcquireDuration() - beforeConfig.AcquireDuration()).Nanoseconds(), ownerRefreshes.Load()-beforeRefreshes, ownerObservationCostError(transportError))
	if ownerFailed.Load() || ctx.Err() != nil {
		t.Fatal("fixture source supervision failed before result")
	}
	if measured.FirstError != "none" {
		t.Fatal("first concrete pair proof did not finish; pre/post counterexample not yet established", measured.FirstError)
	}
	if measured.LastError == "none" {
		// Proofs reused for OwnerProtectionReuse now fit the original budget.
		if handlerCalls.Load() != 1 || measured.TotalNanos > int64(5*time.Second) {
			t.Fatal("original admission retried or exceeded its budget", handlerCalls.Load(), measured.TotalNanos)
		}
		t.Log("original nested pre/post completed within the original budget; the earlier availability counterexample no longer reproduces")
		return
	}
	if measured.LastError != "deadline" && measured.LastError != "cancelled" && measured.LastError != "unavailable" {
		t.Fatal("original nested pre/post unexpectedly completed or failed outside timed availability", measured.LastError)
	}
	if handlerCalls.Load() != 1 {
		t.Fatal("original HTTP admission was retried")
	}
	var observerCount, firstCount int64
	for i, n := range measured.Native.Requests[0] {
		observerCount += n
		firstCount += measured.FirstNative.Requests[0][i]
	}
	if firstCount < 94 || observerCount < firstCount || observerCount > 121 || measured.Native.Requests[0][10] != 0 || measured.Native.Requests[1][10] != 0 {
		t.Fatal("unexpected concrete request graph", firstCount, observerCount, measured.Native.Requests)
	}
	if measured.TotalNanos < int64(3500*time.Millisecond) || measured.TotalNanos > int64(5500*time.Millisecond) {
		t.Fatal("denial occurred outside the expected original limiter-bound interval")
	}
	t.Log("expected original-bound denial reproduced with actual native APIs and current SQL; this PASS records an availability counterexample, not successful routing or installed workflow")
}
