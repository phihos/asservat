package bootstrap

import (
	"context"
	"crypto/x509"
	"errors"
	mathrand "math/rand/v2"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/clusterobservation"
	native "asservat.local/asservat/internal/transport/native"
)

// This exact startup phase consumes only local owner identity services. Unlike
// OwnerRuntimeConfig it has no worker routing, request-owner, remote Kubernetes,
// native key/proof or context-start capability. The constructors are distinct.
type OwnerObservationRuntimeConfig struct {
	Pin                                value.OwnerObservationPin
	PodUID                             string
	Configuration                      app.OwnerConfigurationReader
	ServerEnrollment, ClientEnrollment app.OwnerCredentialEnrollment
	Registry                           app.OwnerCertificateRegistry
	Proofs                             app.OwnerEnrollmentProofReader
	Routes                             app.OwnerRouteReader
	Protection                         app.OwnerProtectionReader
	Workloads                          app.OwnerObservationWorkloadReader
	Peers                              []mtls.OwnerObservationPeer
	Connections, Concurrency           int
	// Local builds the hub cluster's capacity observation handler for this
	// owner's server authority (ADR-190 decision 7); nil serves none.
	Local func(context.Context, string) (*clusterobservation.LocalHandler, error)
}

type OwnerObservationRuntime struct {
	root           context.Context
	cancel         context.CancelFunc
	binding        value.OwnerBinding
	pool           value.OwnerPool
	server, client *mtls.OwnerCredentials
	serving        *mtls.OwnerBootstrapServing
	roots          *x509.CertPool
	handler        *clusterobservation.OwnerHandler
	local          *clusterobservation.LocalHandler
	readiness      app.OwnerStartupReadiness
	connections    int
	started        atomic.Bool
	ready          atomic.Pointer[ownerReadinessSnapshot]
}

func NewOwnerObservationRuntime(ctx context.Context, c OwnerObservationRuntimeConfig) (*OwnerObservationRuntime, error) {
	return newOwnerObservationRuntime(ctx, ctx, c)
}

// setup preserves the installed loader's independently observed original proof
// deadline without making it the lifetime of the supervised process.
func newOwnerObservationRuntime(ctx, setup context.Context, c OwnerObservationRuntimeConfig) (result *OwnerObservationRuntime, err error) {
	phase, purpose := startupRuntimeInputs, "none"
	defer ownerStartupAnnotate(&phase, &purpose, &err)
	if ctx == nil || ctx.Err() != nil || setup == nil || setup.Err() != nil || !c.Pin.Valid() || !authorization.UUID(c.PodUID) || c.Configuration == nil || c.ServerEnrollment == nil || c.ClientEnrollment == nil || c.Registry == nil || c.Proofs == nil || c.Routes == nil || c.Protection == nil || c.Workloads == nil || c.Connections < 1 || c.Connections > 64 || c.Concurrency < 1 || c.Concurrency > 16 || c.Concurrency > c.Connections || len(c.Peers) < 1 || len(c.Peers) > 16 {
		return nil, value.ErrInvalid
	}
	phase = startupRuntimeConfiguration
	read, end := context.WithTimeout(setup, 5*time.Second)
	current, e := c.Configuration.ReadOwnerConfiguration(read)
	readErr := read.Err()
	end()
	if e != nil || readErr != nil || ctx.Err() != nil || !current.Valid(time.Now()) || current.Configuration.Suspended || current.Configuration.Pool != c.Pin.Pool || current.Configuration.Revision.UID != c.Pin.SourceUID {
		return nil, errors.Join(value.ErrUnavailable, e, readErr)
	}
	phase = startupRuntimeRoots
	roots, _, e := mtls.OwnerTrustRoots(current.Configuration.IssuerRoots, time.Now())
	if e != nil || disableWorkerCoreDumps() != nil {
		return nil, errors.Join(value.ErrUnavailable, e)
	}
	phase = startupRuntimeEpoch
	epoch := ownerRandomID()
	if !authorization.UUID(epoch) {
		return nil, value.ErrUnavailable
	}
	p := c.Pin.Pool
	binding := value.OwnerBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PodUID: c.PodUID, ProcessEpoch: epoch}
	root, cancel := context.WithCancel(ctx)
	r := &OwnerObservationRuntime{root: root, cancel: cancel, binding: binding, pool: p, connections: c.Connections}
	complete := false
	defer func() {
		if !complete {
			r.Close()
		}
	}()
	phase = startupServerCredentials
	r.server, e = mtls.NewOwnerCredentialsForPool(binding, "server", p, roots, c.ServerEnrollment, c.Registry, time.Now)
	if e != nil {
		return nil, e
	}
	phase = startupClientCredentials
	r.client, e = mtls.NewOwnerCredentialsForPool(binding, "client", p, roots, c.ClientEnrollment, c.Registry, time.Now)
	if e != nil {
		return nil, e
	}
	gate := &app.OwnerAuthenticator{Registry: c.Registry, Routes: c.Routes, Protection: c.Protection, Now: time.Now}
	o, e := newOwnerObservationServing(root, OwnerObservationServingConfig{Pin: c.Pin, Workloads: c.Workloads, Peers: c.Peers, Local: c.Local}, r.server, gate, c.Concurrency, &phase)
	if e != nil {
		return nil, e
	}
	r.handler, r.local, r.serving, r.roots = o.handler, o.local, o.serving, o.roots
	r.readiness = app.OwnerStartupReadiness{Binding: binding, Pool: p, Server: r.server, Client: r.client, Registry: c.Registry, Proofs: c.Proofs, Now: time.Now}
	phase = startupRuntimeDeadline
	if root.Err() != nil || setup.Err() != nil || !current.Valid(time.Now()) {
		return nil, value.ErrUnavailable
	}
	complete = true
	return r, nil
}

func (r *OwnerObservationRuntime) Binding() value.OwnerBinding { return r.binding }
func (r *OwnerObservationRuntime) Ready() bool {
	if r == nil || r.root == nil || r.root.Err() != nil {
		return false
	}
	s := r.ready.Load()
	now := time.Now()
	return s != nil && !now.Before(s.observed) && now.Before(s.until)
}
func (r *OwnerObservationRuntime) Close() {
	if r == nil {
		return
	}
	r.ready.Store(nil)
	if r.cancel != nil {
		r.cancel()
	}
	if r.server != nil {
		r.server.Close()
	}
	if r.client != nil {
		r.client.Close()
	}
	if r.handler != nil {
		r.handler.Close()
	}
}
func (r *OwnerObservationRuntime) observeReadiness() error {
	for {
		start := time.Now()
		until, e := r.readiness.Check(r.root)
		if e != nil || r.root.Err() != nil {
			r.ready.Store(nil)
		} else {
			r.ready.Store(&ownerReadinessSnapshot{start, until})
		}
		if e = waitWorker(r.root, time.Second); e != nil {
			return e
		}
	}
}

// Run owns only the original NativePort listener. The ordinary owner port and
// future public port are reserved installation facts, never served as dummy
// endpoints. No full runtime is manufactured from missing backend credentials.
func (r *OwnerObservationRuntime) Run(listener net.Listener) (result error) {
	phase, purpose := startupRunPreconditions, "none"
	defer ownerStartupAnnotate(&phase, &purpose, &result)
	if r == nil || listener == nil {
		return value.ErrInvalid
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.Port != r.pool.NativePort || !r.started.CompareAndSwap(false, true) {
		return value.ErrInvalid
	}
	defer listener.Close()
	done := make(chan error, 3)
	running := 0
	launch := func(f func() error) { running++; go func() { done <- f() }() }
	defer func() {
		r.Close()
		_ = listener.Close()
		for running > 0 {
			<-done
			running--
		}
	}()
	phase = startupInitialIdentity
	ready := make(chan app.OwnerCredentialStatus, 1)
	supervisor := app.OwnerCredentialSupervisor{Server: r.server, Client: r.client, Binding: r.binding, Now: time.Now, Wait: waitWorker, Jitter: func() time.Duration { return time.Duration(mathrand.Int64N(int64(500 * time.Millisecond))) }, IdentityReady: ready}
	launch(func() error { return supervisor.Run(r.root) })
	select {
	case <-r.root.Done():
		return r.root.Err()
	case e := <-done:
		running--
		if e == nil {
			return value.ErrUnavailable
		}
		return e
	case <-ready:
	}
	phase = startupRuntimeServing
	launch(func() error {
		return (&ownerObservationServing{handler: r.handler, local: r.local, serving: r.serving, roots: r.roots}).serve(r.root, listener, r.connections)
	})
	launch(r.observeReadiness)
	select {
	case <-r.root.Done():
		return r.root.Err()
	case e := <-done:
		running--
		if e == nil {
			return value.ErrUnavailable
		}
		return e
	}
}

// OwnerObservationServingConfig is the observation handler set's input: the
// observation pin, workload reader and peers, and the optional hub-cluster
// capacity observation (ADR-190 decision 7).
type OwnerObservationServingConfig struct {
	Pin       value.OwnerObservationPin
	Workloads app.OwnerObservationWorkloadReader
	Peers     []mtls.OwnerObservationPeer
	Local     func(context.Context, string) (*clusterobservation.LocalHandler, error)
}

// ownerObservationServing is the observation handler set served on the
// bootstrap server name. It uses the process's existing server credential;
// the observation runtime and a promoted owner (ADR-190 decision 4) build it
// the same way.
type ownerObservationServing struct {
	name    string
	handler *clusterobservation.OwnerHandler
	local   *clusterobservation.LocalHandler
	serving *mtls.OwnerBootstrapServing
	roots   *x509.CertPool
}

func newOwnerObservationServing(root context.Context, c OwnerObservationServingConfig, server *mtls.OwnerCredentials, gate *app.OwnerAuthenticator, concurrency int, phase *ownerStartupPhase) (*ownerObservationServing, error) {
	if !c.Pin.Valid() || c.Workloads == nil || len(c.Peers) < 1 || len(c.Peers) > 16 || server == nil || gate == nil {
		return nil, value.ErrInvalid
	}
	p := c.Pin.Pool
	*phase = startupObservationIngress
	ingress, e := mtls.NewOwnerObservationIngress(c.Pin, server, gate, c.Workloads, c.Peers, time.Now)
	if e != nil {
		return nil, e
	}
	*phase = startupServerName
	name, e := mtls.OwnerBootstrapServerName(p)
	if e != nil {
		return nil, e
	}
	out := &ownerObservationServing{name: name}
	*phase = startupObservationHandler
	if out.handler, e = clusterobservation.NewOwnerHandler(root, net.JoinHostPort(name, strconv.Itoa(p.NativePort)), ingress, concurrency, time.Now); e != nil {
		return nil, e
	}
	if c.Local != nil {
		if out.local, e = c.Local(root, net.JoinHostPort(name, strconv.Itoa(p.NativePort))); e != nil {
			return nil, e
		}
	}
	*phase = startupBootstrapServing
	if out.serving, e = mtls.NewOwnerBootstrapServing(server, p); e != nil {
		return nil, e
	}
	*phase = startupPeerRoots
	out.roots = x509.NewCertPool()
	for _, peer := range c.Peers {
		// This union is solely TLS pre-authentication. The ingress selects and
		// verifies the exact installed binding's own roots before any read.
		if _, _, e = mtls.OwnerTrustRoots(peer.Roots, time.Now()); e != nil {
			return nil, e
		}
		for _, der := range peer.Roots {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, value.ErrInvalid
			}
			out.roots.AddCert(cert)
		}
	}
	return out, nil
}

// serve is the observation server on its routed listener.
func (o *ownerObservationServing) serve(root context.Context, listener net.Listener, connections int) error {
	if o.local != nil {
		return native.ServeOwnerLocalObservation(root, listener, o.roots, o.serving, o.handler, o.local, connections)
	}
	return native.ServeOwnerObservation(root, listener, o.roots, o.serving, o.handler, connections)
}
