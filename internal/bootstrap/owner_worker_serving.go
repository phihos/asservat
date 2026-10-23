package bootstrap

import (
	"crypto/tls"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	native "asservat.local/asservat/internal/transport/native"
	worker "asservat.local/asservat/internal/transport/worker"
	"golang.org/x/net/netutil"
)

// ownerWorkerEndpoints are the pins a hub-local download worker's control
// document carries for one owner pool (ADR-204 decision 9). Name is the
// pool's fixed serving name, present in every owner server leaf of the pool
// beside the exact process name; the worker verifies it against the owner
// issuer roots. Address is the in-cluster owner Service on the owner port,
// which the worker dials for both paths (connectivity only).
type ownerWorkerEndpoints struct {
	Name, Authority            string
	Endpoint, ExchangeEndpoint string
	Address                    string
}

func ownerWorkerEndpointsFor(pool value.OwnerPool) (ownerWorkerEndpoints, error) {
	name, err := mtls.OwnerBootstrapServerName(pool)
	if err != nil {
		return ownerWorkerEndpoints{}, err
	}
	port := strconv.Itoa(pool.Port)
	authority := net.JoinHostPort(name, port)
	return ownerWorkerEndpoints{Name: name, Authority: authority, Endpoint: "https://" + authority, ExchangeEndpoint: "https://" + authority + contracts.NativeWorkerPath, Address: net.JoinHostPort(pool.Service+"."+pool.Namespace+".svc", port)}, nil
}

// ownerWorkerNativeKey routes the fixed name's h2 ClientHellos. It cannot be a
// server name: '#' is not a DNS label character.
const ownerWorkerNativeKey = "#h2"

type ownerWorkerServing struct {
	endpoints  ownerWorkerEndpoints
	serving    *mtls.OwnerBootstrapServing
	enrollment *worker.Handler
	native     *native.Handler
	roots      native.ClientRoots
}

// ServeAcquisitionWorkers adds the two existing worker paths to the owner port
// before Run. HTTP/1.1 performs local admitted-worker enrollment; h2 accepts
// certificate-authenticated native/query operations. Human certificate-owner
// routing and its exact-process listener are absent (ADR-221).
func (r *OwnerRuntime) ServeAcquisitionWorkers(roots native.ClientRoots, exchange evidence.AcquisitionEnrollmentExchange) error {
	if r == nil || roots == nil || exchange == nil || r.native == nil || r.server == nil || r.root == nil || r.root.Err() != nil {
		return value.ErrInvalid
	}
	endpoints, err := ownerWorkerEndpointsFor(r.pool)
	if err != nil {
		return err
	}
	serving, err := mtls.NewOwnerBootstrapServing(r.server, r.pool)
	if err != nil {
		return err
	}
	enrollment, err := worker.NewAcquisitionHandler(r.binding.InstallationID, exchange, time.Now, r.concurrency)
	if err != nil {
		return err
	}
	enrollment.Refused = downloadRefusalReport(eventLog(os.Stderr, "worker enrollment refused"), time.Now)
	admission, err := native.NewHubWorkerAdmission(r.native.peers, r.native.hub, r.native.router, time.Now)
	if err != nil {
		return err
	}
	handler, err := native.NewHandler(contracts.NativeWorkerPath, endpoints.Authority, admission, r.native.concurrency)
	if err != nil {
		return err
	}
	r.compose.Lock()
	defer r.compose.Unlock()
	if r.started.Load() || r.workers != nil {
		return value.ErrInvalid
	}
	r.workers = &ownerWorkerServing{endpoints: endpoints, serving: serving, enrollment: enrollment, native: handler, roots: roots}
	return nil
}

// launchWorkerServing splits the owner port by ClientHello and launches the
// two worker servers. Each
// child keeps its own TLS profile, client authentication and socket bound.
func (r *OwnerRuntime) launchWorkerServing(w *ownerWorkerServing, listener net.Listener, launch func(ownerStartupPhase, func() error)) error {
	name := w.endpoints.Name
	// One raw pre-TLS ceiling for the shared port, the sum of the two
	// servers' own socket bounds: a socket waiting for its classification or
	// for a full server's hand-off stays counted until it closes.
	shared := netutil.LimitListener(listener, r.connections+r.native.connections)
	router, err := native.NewClientHelloRouter(r.root, shared, func(hello *tls.ClientHelloInfo) string {
		if hello.ServerName == name && slices.Contains(hello.SupportedProtos, "h2") {
			return ownerWorkerNativeKey
		}
		return hello.ServerName
	}, name, ownerWorkerNativeKey)
	if err != nil {
		return err
	}
	log := eventLog(os.Stderr, "owner port router")
	names := strings.NewReplacer(" "+name, " worker-enrollment", " "+ownerWorkerNativeKey, " worker-native")
	router.Report = func(event string) { log(names.Replace(event)) }
	enrollment, nativeWorkers := router.Listener(name), router.Listener(ownerWorkerNativeKey)
	launch(startupRunWorkerRouter, router.Run)
	launch(startupRunWorkerEnrollment, func() error {
		return worker.Serve(r.root, enrollment, w.endpoints.Authority, w.serving, w.enrollment, r.connections)
	})
	launch(startupRunWorkerNative, func() error {
		return native.ServeWorker(r.root, nativeWorkers, w.roots, w.serving, w.native, r.native.connections)
	})
	return nil
}
