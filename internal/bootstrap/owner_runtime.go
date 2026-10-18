package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	authorization "asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	native "asservat.local/asservat/internal/transport/native"
	"asservat.local/asservat/internal/transport/ownerrelay"
)

// These are installation-owned, independently accepted dependencies, not a
// public request/flag schema. Bootstrap still must supply scoped provider/SQL
// clients and a continuously reconciled recovery/configuration source.
type OwnerRuntimeConfig struct {
	Pool                               value.OwnerPool
	PodUID, SourceUID                  string
	Configuration                      app.OwnerConfigurationReader
	ServerEnrollment, ClientEnrollment app.OwnerCredentialEnrollment
	Registry                           app.OwnerCertificateRegistry
	Proofs                             app.OwnerEnrollmentProofReader
	// ReadinessProofs, when set, serves only the readiness loop, on its own
	// Kubernetes clients (ADR-173); otherwise readiness uses Proofs.
	ReadinessProofs          app.OwnerEnrollmentProofReader
	Routes                   app.OwnerRouteReader
	Protection               app.OwnerProtectionReader
	Requests                 func(value.OwnerBinding) (evidence.WorkerOwnerEnrollment, error)
	WorkerTrust              *mtls.WorkerTrustCatalog
	Workers                  evidence.WorkerEnrollmentBindings
	Locators                 evidence.WorkerOwnerLookup
	Connections, Concurrency int
	Native                   *OwnerNativeRuntimeConfig
	// Observation additionally serves the observation handler set on the
	// native port, split by TLS server name (ADR-190 decisions 4 and 6). It
	// requires Native and binds the same pool.
	Observation *OwnerObservationServingConfig
	// Operation additionally serves the ADR-197 v2 operation server on the
	// pool's OperationPort. It requires Observation and binds the same pool.
	Operation *OwnerOperationConfig
}

type ownerReadinessSnapshot struct{ observed, until time.Time }

// OwnerRuntime owns keys, enrollment renewal, private receiver and outbound
// delivery for one fresh process epoch. It is not the complete hub/API role.
type OwnerRuntime struct {
	root           context.Context
	cancel         context.CancelFunc
	binding        value.OwnerBinding
	pool           value.OwnerPool
	roots          *x509.CertPool
	server, client *mtls.OwnerCredentials
	forwarder      *mtls.OwnerForwarder
	handler        *ownerrelay.Handler
	readiness      app.OwnerStartupReadiness
	connections    int
	started        atomic.Bool
	ready          atomic.Pointer[ownerReadinessSnapshot]
	native         *ownerNativeRuntime
	observation    *ownerObservationServing
	operation      *OwnerOperationConfig
}

func NewOwnerRuntime(ctx context.Context, c OwnerRuntimeConfig) (*OwnerRuntime, error) {
	if ctx == nil || ctx.Err() != nil || !c.Pool.Valid() || !authorization.UUID(c.PodUID) || !authorization.UUID(c.SourceUID) || c.Configuration == nil || c.ServerEnrollment == nil || c.ClientEnrollment == nil || c.Registry == nil || c.Proofs == nil || c.Routes == nil || c.Protection == nil || c.Requests == nil || c.Connections < 1 || c.Connections > 64 || c.Concurrency < 1 || c.Concurrency > 16 || c.Concurrency > c.Connections || !c.WorkerTrust.ForInstallation(c.Pool.InstallationID) || c.Workers == nil || c.Locators == nil {
		return nil, value.ErrInvalid
	}
	if (c.Native == nil) != (c.Pool.NativePort == 0) {
		return nil, value.ErrInvalid
	}
	read, end := context.WithTimeout(ctx, 5*time.Second)
	current, err := c.Configuration.ReadOwnerConfiguration(read)
	readErr := read.Err()
	end()
	if err != nil || readErr != nil || ctx.Err() != nil || !current.Valid(time.Now()) || current.Configuration.Suspended || current.Configuration.Pool != c.Pool || current.Configuration.Revision.UID != c.SourceUID {
		return nil, value.ErrUnavailable
	}
	current.Configuration = current.Configuration.Clone()
	roots, _, err := mtls.OwnerTrustRoots(current.Configuration.IssuerRoots, time.Now())
	if err != nil {
		return nil, err
	}
	// Only this process is affected, before any private process key is created.
	if disableWorkerCoreDumps() != nil {
		return nil, value.ErrUnavailable
	}
	var epoch [16]byte
	if _, err = rand.Read(epoch[:]); err != nil {
		return nil, value.ErrUnavailable
	}
	epoch[6] = (epoch[6] & 15) | 64
	epoch[8] = (epoch[8] & 63) | 128
	binding := value.OwnerBinding{InstallationID: c.Pool.InstallationID, ClusterID: c.Pool.ClusterID, IssuerEpoch: c.Pool.IssuerEpoch, PodUID: c.PodUID, ProcessEpoch: fmt.Sprintf("%x-%x-%x-%x-%x", epoch[:4], epoch[4:6], epoch[6:8], epoch[8:10], epoch[10:])}
	root, cancel := context.WithCancel(ctx)
	r := &OwnerRuntime{root: root, cancel: cancel, binding: binding, pool: c.Pool, roots: roots, connections: c.Connections}
	complete := false
	defer func() {
		if !complete {
			r.Close()
		}
	}()
	r.server, err = mtls.NewOwnerCredentialsForPool(binding, "server", c.Pool, roots, c.ServerEnrollment, c.Registry, time.Now)
	if err != nil {
		return nil, err
	}
	r.client, err = mtls.NewOwnerCredentialsForPool(binding, "client", c.Pool, roots, c.ClientEnrollment, c.Registry, time.Now)
	if err != nil {
		return nil, err
	}
	gate := &app.OwnerAuthenticator{Registry: c.Registry, Routes: c.Routes, Protection: c.Protection, Now: time.Now}
	verifier, err := mtls.NewOwnerPeerVerifierForPool(roots, c.Pool, time.Now)
	if err != nil {
		return nil, err
	}
	requests, err := c.Requests(binding)
	if err != nil || requests == nil {
		return nil, value.ErrInvalid
	}
	r.handler, err = ownerrelay.NewHandler(binding, &mtls.OwnerRequestPeers{Verifier: verifier, Authenticator: gate, Server: r.server}, requests, time.Now, c.Concurrency)
	if err != nil {
		return nil, err
	}
	r.forwarder, err = mtls.NewOwnerForwarder(root, mtls.OwnerForwarderConfig{Pool: c.Pool, WorkerTrust: c.WorkerTrust, Client: r.client, OwnerRoots: roots, Routes: c.Routes, Authentication: gate, Owners: c.Locators, Workers: c.Workers, Now: time.Now, Concurrency: c.Concurrency})
	if err != nil {
		return nil, err
	}
	if c.Native != nil {
		r.native, err = newOwnerNativeRuntime(r, *c.Native, gate)
		if err != nil {
			return nil, ownerStartupError(startupNativeRuntime, "none", err)
		}
	}
	if o := c.Observation; o != nil {
		phase := startupObservationIngress
		if c.Native == nil || o.Pin.Pool != c.Pool {
			return nil, value.ErrInvalid
		}
		if r.observation, err = newOwnerObservationServing(root, *o, r.server, gate, c.Concurrency, &phase); err != nil {
			return nil, ownerStartupError(phase, "none", err)
		}
	}
	if o := c.Operation; o != nil {
		if r.observation == nil || o.Pin.Pool != c.Pool || c.Pool.OperationPort == 0 {
			return nil, value.ErrInvalid
		}
		r.operation = o
	}
	readiness := c.Proofs
	if c.ReadinessProofs != nil {
		readiness = c.ReadinessProofs
	}
	r.readiness = app.OwnerStartupReadiness{Binding: binding, Pool: c.Pool, Server: r.server, Client: r.client, Registry: c.Registry, Proofs: readiness, Now: time.Now}
	if root.Err() != nil || !current.Valid(time.Now()) {
		return nil, value.ErrUnavailable
	}
	complete = true
	return r, nil
}

func (r *OwnerRuntime) Binding() value.OwnerBinding { return r.binding }

// Readiness is an expiring scheduling hint, never an authorization cache.
// Other hub dependencies must also be ready before the whole Pod is marked Ready.
func (r *OwnerRuntime) Ready() bool {
	if r == nil || r.root == nil || r.root.Err() != nil {
		return false
	}
	s := r.ready.Load()
	now := time.Now()
	return s != nil && !now.Before(s.observed) && now.Before(s.until)
}

// stop removes readiness, cancels work and disables retained keys before any
// joined shutdown can block on a child that has not yet returned.
func (r *OwnerRuntime) stop() {
	if r == nil {
		return
	}
	r.ready.Store(nil)
	if r.cancel != nil {
		r.cancel()
	}
	if r.forwarder != nil {
		r.forwarder.Close()
	}
	if r.server != nil {
		r.server.Close()
	}
	if r.client != nil {
		r.client.Close()
	}
}

func (r *OwnerRuntime) Close() {
	if r == nil {
		return
	}
	r.stop()
	if r.native != nil {
		r.native.router.Close()
		if r.native.startRouter != nil {
			r.native.startRouter.Close()
		}
	}
}

func (r *OwnerRuntime) BeginWorkerEnrollment(ctx context.Context, installation, session, worker string, token, csr []byte) (evidence.WorkerEnrollmentDelivery, error) {
	if !r.Ready() {
		return nil, artifact.ErrDownloadUnavailable
	}
	return r.forwarder.BeginWorkerEnrollment(ctx, installation, session, worker, token, csr)
}

func (r *OwnerRuntime) observeReadiness() error {
	for {
		start := time.Now()
		until, err := r.readiness.Check(r.root)
		if err != nil || r.root.Err() != nil {
			r.ready.Store(nil)
		} else {
			r.ready.Store(&ownerReadinessSnapshot{start, until})
		}
		if err = waitWorker(r.root, time.Second); err != nil {
			return err
		}
	}
}

// Run takes ownership of the already-bound enrollment listener and, only when
// configured, its separately bound native h2 listener. It enrolls
// before serving, supervises renewal/readiness, and joins all started work on
// shutdown. No readiness-dependent route is used to enroll or become ready.
func (r *OwnerRuntime) Run(listener net.Listener, additional ...net.Listener) (result error) {
	if r == nil || listener == nil {
		return value.ErrInvalid
	}
	var nativeListener, operationListener net.Listener
	if r.native != nil {
		want := 1
		if r.operation != nil {
			want = 2
		}
		if len(additional) != want || additional[0] == nil {
			return value.ErrInvalid
		}
		nativeListener = additional[0]
		address, ok := nativeListener.Addr().(*net.TCPAddr)
		if !ok || address.Port != r.pool.NativePort {
			return value.ErrInvalid
		}
		if r.operation != nil {
			operationListener = additional[1]
			address, ok := operationListener.Addr().(*net.TCPAddr)
			if operationListener == nil || !ok || address.Port != r.pool.OperationPort {
				return value.ErrInvalid
			}
			defer operationListener.Close()
		}
	} else if len(additional) != 0 {
		return value.ErrInvalid
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.Port != r.pool.Port || !r.started.CompareAndSwap(false, true) {
		return value.ErrInvalid
	}
	defer listener.Close()
	if nativeListener != nil {
		defer nativeListener.Close()
	}
	finished := make(chan error, 8)
	running := 0
	// Each child's error names its fixed server phase in the startup
	// diagnostic; the cause stays available to errors.Is/As.
	launch := func(phase ownerStartupPhase, f func() error) {
		running++
		go func() {
			err := f()
			if err != nil {
				err = ownerStartupError(phase, "none", err)
			}
			finished <- err
		}()
	}
	var operation *ownerOperationServing
	defer func() {
		if operation != nil {
			// After every server has joined below.
			defer operation.close()
		}
		r.stop()
		listener.Close()
		if nativeListener != nil {
			nativeListener.Close()
		}
		if operationListener != nil {
			operationListener.Close()
		}
		r.Close()
		// Cancellation and socket/key closure remove effect authority first.
		// A timeout cannot establish that an already-started child terminated.
		// Process-level forced termination is distinct from joined Run return.
		for running > 0 {
			<-finished
			running--
		}
	}()
	identityReady := make(chan app.OwnerCredentialStatus, 1)
	supervisor := app.OwnerCredentialSupervisor{Server: r.server, Client: r.client, Binding: r.binding, Now: time.Now, Wait: waitWorker, Jitter: func() time.Duration { return time.Duration(mathrand.Int64N(int64(500 * time.Millisecond))) }, IdentityReady: identityReady}
	launch(startupRunIdentity, func() error { return supervisor.Run(r.root) })
	select {
	case <-r.root.Done():
		return r.root.Err()
	case err := <-finished:
		running--
		if err == nil {
			return value.ErrUnavailable
		}
		return err
	case <-identityReady:
	}
	launch(startupRunRelay, func() error { return ownerrelay.Serve(r.root, listener, r.roots, r.server, r.handler, r.connections) })
	if r.observation != nil {
		// One port, two servers: each keeps its TLS profile and slots.
		name, err := mtls.OwnerServerName(r.binding)
		if err != nil {
			return err
		}
		router, err := native.NewServerNameRouter(r.root, nativeListener, name, r.observation.name)
		if err != nil {
			return err
		}
		observed := router.Listener(r.observation.name)
		nativeListener = router.Listener(name)
		router.Report = ownerRouterReporter(name, r.observation.name)
		launch(startupRunRouter, router.Run)
		launch(startupRunObservation, func() error { return r.observation.serve(r.root, observed, r.connections) })
	}
	if operationListener != nil {
		// ADR-197: the claim receiver binds the now-active serving leaf.
		var err error
		if operation, err = newOwnerOperationServing(r.root, *r.operation, r.server); err != nil {
			return ownerStartupError(startupOperationServing, "none", err)
		}
		launch(startupRunOperation, func() error { return operation.serve(r.root, operationListener) })
	}
	if nativeListener != nil {
		launch(startupRunNative, func() error {
			if r.native.starts != nil {
				return native.ServeWithContextStart(r.root, nativeListener, r.native.roots, r.server, r.native.handler, r.native.starts, r.native.connections, r.native.startConnections)
			}
			return native.Serve(r.root, nativeListener, r.native.roots, r.server, r.native.handler, r.native.connections)
		})
	}
	launch(startupRunReadiness, r.observeReadiness)
	select {
	case <-r.root.Done():
		return r.root.Err()
	case err := <-finished:
		running--
		if err == nil {
			return value.ErrUnavailable
		}
		return err
	}
}

// ownerRouterReporter logs the server-name router's events, naming the child
// as native or observation rather than by its DNS name.
func ownerRouterReporter(native, observation string) func(string) {
	log := eventLog(os.Stderr, "owner router")
	names := strings.NewReplacer(" "+native, " native", " "+observation, " observation")
	return func(event string) { log(names.Replace(event)) }
}
