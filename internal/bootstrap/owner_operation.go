package bootstrap

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
	native "asservat.local/asservat/internal/transport/native"
)

// OwnerOperationConfig is the promoted owner's ADR-197 v2 operation server:
// the owner's observation pin, the regional capacity clusters whose standbys
// it holds, and the concrete readers. The hub-worker's local claim and a
// region's standby meet on OperationPort, matched by cluster; native and v1
// serving are unchanged.
type OwnerOperationConfig struct {
	Pin      value.OwnerObservationPin
	Regional []RegionalObservationOperationCluster
	Owners   *postgres.OwnerEnrollments
	Proof    *kube.OwnerLocalObservationOperationReader
}

// ownerRegionalStandbys admits each region's two standbys (regionalStandbys)
// plus one served entry still in joined cleanup. The holder and the
// listener's standby slots are shared by all regions: a standby is admitted
// before its hello names a cluster.
const ownerRegionalStandbys = 3

// capacityRegionalCalls is the concurrent hub-worker capacity observations
// of n regional clusters: one per regional discovery loop plus the demand
// lane, never fewer than the original two. The hub-worker's holder client,
// the owner's local receiver and its proof connections use the same bound.
func capacityRegionalCalls(n int) int {
	return max(2, min(n, contracts.OwnerClusterCatalogSlots)+1)
}

// ownerOperationServing is composed once the server identity is active: the
// claim receiver binds the current serving leaf.
type ownerOperationServing struct {
	roots    *x509.CertPool
	serving  *mtls.OwnerBootstrapServing
	receiver *OwnerLocalObservationReceiver
	handler  *wire.HubObservationOperationHandler
	holder   *wire.HubObservationOperationHolder
	standbys int
	calls    int
}

func newOwnerOperationServing(root context.Context, c OwnerOperationConfig, server *mtls.OwnerCredentials) (*ownerOperationServing, error) {
	out := &ownerOperationServing{}
	var err error
	standbys := ownerRegionalStandbys * len(c.Regional)
	if out.holder, err = wire.NewHubObservationOperationHolder(root, standbys, time.Now); err != nil {
		return nil, err
	}
	if out.receiver, err = NewOwnerLocalObservationReceiver(root, c.Pin, server, c.Owners, c.Proof, out.holder, capacityRegionalCalls(len(c.Regional)), time.Now); err != nil {
		out.close()
		return nil, err
	}
	// Each region's peer keeps its own issuer roots in the ingress; the
	// handshake pool below only admits a chain to some joined region's roots
	// before that exact per-binding verification.
	peers := make([]mtls.OwnerObservationPeer, len(c.Regional))
	for i, r := range c.Regional {
		peers[i] = mtls.OwnerObservationPeer{Binding: r.Pin.Profile.Binding, Roots: r.Pin.Profile.ClientIssuerRoots}
	}
	ingress, err := mtls.NewOwnerObservationOperationIngress(c.Pin, server, peers, time.Now)
	if err != nil {
		out.close()
		return nil, err
	}
	if out.handler, err = NewRegionalObservationOperationHandler(out.receiver.CommonAuthority(), out.holder, c.Regional, ingress, time.Now); err != nil {
		out.close()
		return nil, err
	}
	if out.serving, err = mtls.NewOwnerBootstrapServing(server, c.Pin.Pool); err != nil {
		out.close()
		return nil, err
	}
	out.roots = x509.NewCertPool()
	for _, r := range c.Regional {
		if _, _, err = mtls.OwnerTrustRoots(r.Pin.Profile.ClientIssuerRoots, time.Now()); err != nil {
			out.close()
			return nil, err
		}
		for _, der := range r.Pin.Profile.ClientIssuerRoots {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				out.close()
				return nil, value.ErrInvalid
			}
			out.roots.AddCert(cert)
		}
	}
	out.standbys = standbys
	out.calls = capacityRegionalCalls(len(c.Regional))
	return out, nil
}

func (o *ownerOperationServing) serve(root context.Context, listener net.Listener) error {
	return native.ServeOwnerObservationOperation(root, listener, o.roots, o.serving, o.receiver, o.handler, o.calls, o.standbys)
}

func (o *ownerOperationServing) close() {
	if o.receiver != nil {
		o.receiver.Close()
	}
	if o.holder != nil {
		o.holder.Close()
	}
}

// ownerOperationConfig builds the v2 server's input from the guarded catalog
// (ADR-197 decisions 1 and 7). It first records each regional capacity
// cluster's write-once capacity qualification. A promoted owner without a
