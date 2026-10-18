package bootstrap

import (
	"context"
	"crypto/x509"
	"net"
	"strconv"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	authorization "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/transport/contextstart"
	native "asservat.local/asservat/internal/transport/native"
)

// OwnerNativeRuntimeConfig is protected installation composition. NativePeers
// must be built from current SQL/proof adapters; a callback supplied by a public
// request is never a peer or original-caller authority source.
type OwnerNativeRuntimeConfig struct {
	Peers                    *mtls.NativePeerChecks
	ConnectorRoots           *x509.CertPool
	Connections, Concurrency int
	ContextStarts            *OwnerContextStartRuntimeConfig
}

// OwnerContextStartRuntimeConfig is installation-owned input for the two fixed
// purposes on the already accepted NativePort. Router is the same request-owned
// router used by RegionalAPIContextStart; this gives no public caller a route.
// Current profile/registry checks remain in ContextStartIngress. The existing
// protected loader does not yet provision this optional composition.
type OwnerContextStartRuntimeConfig struct {
	RootID                 string
	Router                 *contextstart.Router
	Admissions             []mtls.ContextStartConnectorAdmission
	Connections, Preflight int
}
type ownerNativeRuntime struct {
	roots            *x509.CertPool
	router           *native.HubRouter
	handler          *native.Handler
	connections      int
	starts           *contextstart.Handler
	startRouter      *contextstart.Router
	startConnections int
	// peers, hub and concurrency are the same checks and bound the owner
	// path uses; the optional worker path (ADR-204) reuses them.
	peers       native.NativePeers
	hub         native.NativeHubServing
	concurrency int
}

func newOwnerNativeRuntime(r *OwnerRuntime, c OwnerNativeRuntimeConfig, auth *app.OwnerAuthenticator) (*ownerNativeRuntime, error) {
	if r == nil || auth == nil || c.Peers == nil || c.ConnectorRoots == nil || len(c.ConnectorRoots.Subjects()) == 0 || c.Connections < 1 || c.Connections > 64 || c.Concurrency < 1 || c.Concurrency > 16 || c.Concurrency > c.Connections {
		return nil, artifact.ErrInvalid
	}
	p := *c.Peers
	if p.Workers == nil || p.WorkerTrust == nil || p.Certificates == nil || p.ConnectorVerifier == nil || p.Connectors == nil || p.Now == nil || p.Origins.Locators == nil || p.Origins.Operations == nil || p.Origins.Proofs == nil || p.Origins.Now == nil || !p.WorkerTrust.ForInstallation(r.binding.InstallationID) {
		return nil, artifact.ErrInvalid
	}
	router, err := native.NewHubRouter(c.Concurrency)
	if err != nil {
		return nil, err
	}
	serving := &mtls.OwnerRequestPeers{Authenticator: auth, Server: r.server}
	admission, err := native.NewHubAdmission(&p, serving, router, time.Now)
	if err != nil {
		router.Close()
		return nil, err
	}
	name, err := mtls.OwnerServerName(r.binding)
	if err != nil {
		router.Close()
		return nil, err
	}
	handler, err := native.NewHandler(contracts.NativeOwnerPath, net.JoinHostPort(name, strconv.Itoa(r.pool.NativePort)), admission, c.Concurrency)
	if err != nil {
		router.Close()
		return nil, err
	}
	out := &ownerNativeRuntime{roots: c.ConnectorRoots.Clone(), router: router, handler: handler, connections: c.Connections, peers: &p, hub: serving, concurrency: c.Concurrency}
	if c.ContextStarts != nil {
		start := c.ContextStarts
		if !authorization.UUID(start.RootID) || start.Router == nil || start.Connections < 1 || start.Connections > 64 || start.Preflight < 1 || start.Preflight > start.Connections || c.Connections+start.Connections > 64 {
			router.Close()
			return nil, artifact.ErrInvalid
		}
		ingress, e := mtls.NewContextStartIngress(start.RootID, r.server, auth, start.Admissions, time.Now)
		if e != nil {
			router.Close()
			return nil, e
		}
		h, e := contextstart.NewHandler(net.JoinHostPort(name, strconv.Itoa(r.pool.NativePort)), start.Router, ingress, start.Preflight)
		if e != nil {
			router.Close()
			return nil, e
		}
		out.starts, out.startRouter, out.startConnections = h, start.Router, start.Connections
	}
	return out, nil
}

// RegisterNativeExchange retains the actual original request closure in this
// exact serving process. It supplies no SQL admission or human authority, and
// cannot register another owner's route through the shared runtime.
func (r *OwnerRuntime) RegisterNativeExchange(ctx context.Context, input evidence.NativeExchangeRegistration, before func(context.Context, evidence.NativeOrigin) error, check func(context.Context, evidence.NativeOrigin) (authorization.NativeLease, error)) (evidence.NativePendingExchange, error) {
	if r == nil || r.native == nil || ctx == nil || ctx.Err() != nil || r.root.Err() != nil || input.Operation.Reference.InstallationID != r.binding.InstallationID || input.Operation.HubPodUID != r.binding.PodUID || input.Operation.HubProcessEpoch != r.binding.ProcessEpoch {
		return nil, artifact.ErrDownloadUnavailable
	}
	return r.native.router.RegisterNativeExchange(ctx, input, before, check)
}
