package native

import (
	"context"
	"crypto/x509"
	"net"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/transport/clusterobservation"
)

// ServeOwnerRegionalObservation is an explicitly selected private phase with
// exactly own-proof, local HWORK and regional standby paths. It is not a generic
// mux or a complete installed backend. The caller must independently acknowledge
// the original backend projection and join the prior listener before selection.
//
// Common SNI plus exact authority is mandatory. Only the local HWORK path may
// omit a client certificate; it still needs its online dedicated Pod token.
// Regional and own-proof requests require mutual TLS plus their current concrete
// per-path proof. No credential-relay or exact-owner forwarding route is served.
//
// A standby retains the original accept-time thirty-second hard bound. Proof
// paths retain accept-time five seconds; both include TLS/header time. Separate
// purpose reservations remain charged through actual socket and handler close,
// and the sum stays within the existing sixty-four-connection ceiling. These
// are per-process ceilings, not an installation-wide capacity guarantee.
func ServeOwnerRegionalObservation(ctx context.Context, listener net.Listener, roots *x509.CertPool, credentials ServerCredentials, own *clusterobservation.OwnerHandler, local *clusterobservation.LocalHandler, regional *clusterobservation.HubObservationHandler, proofConnections, regionalConnections int) error {
	if own == nil || local == nil || regional == nil || own.Authority() != local.Authority() || own.Authority() != regional.Authority() || proofConnections < 1 || proofConnections > 64 || regionalConnections < 1 || regionalConnections > 64 || proofConnections+regionalConnections > 64 {
		return contracts.ErrNativeProtocol
	}
	return serveOwnerObservationPurposes(ctx, listener, roots, credentials, own, local, regional, proofConnections, regionalConnections)
}
