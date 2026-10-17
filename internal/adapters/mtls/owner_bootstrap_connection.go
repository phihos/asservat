package mtls

import (
	"crypto/tls"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

// OwnerBootstrapConnection is restricted to an actual common-SNI observation
// connection and its independently read original SQL candidate set. It cannot
// enter exact-request owner routing or extend the candidate observation.
type OwnerBootstrapConnection struct {
	verifier   *OwnerPeerVerifier
	state      tls.ConnectionState
	candidates value.APIContextOwnerCandidates
}

var _ app.OwnerPeerConnection = (*OwnerBootstrapConnection)(nil)

func NewOwnerBootstrapConnection(v *OwnerPeerVerifier, state *tls.ConnectionState, candidates value.APIContextOwnerCandidates) (*OwnerBootstrapConnection, error) {
	if _, e := v.VerifyBootstrapServer(state, candidates); e != nil {
		return nil, e
	}
	snapshot, e := snapshotOwnerTLS(state)
	if e != nil {
		return nil, e
	}
	candidates.Owners = append([]value.OwnerBinding(nil), candidates.Owners...)
	c := &OwnerBootstrapConnection{v, snapshot, candidates}
	if _, e = c.OwnerCertificate(); e != nil {
		return nil, e
	}
	return c, nil
}
func (c *OwnerBootstrapConnection) OwnerCertificate() (value.OwnerCertificate, error) {
	if c == nil || c.verifier == nil {
		return value.OwnerCertificate{}, value.ErrDenied
	}
	return c.verifier.VerifyBootstrapServer(&c.state, c.candidates)
}
func (c *OwnerBootstrapConnection) VerifyCurrentOwner(observed value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
	var zero value.OwnerCertificate
	first, e := c.OwnerCertificate()
	if e != nil {
		return zero, e
	}
	current, e := c.verifier.currentVerifier(observed)
	if e != nil {
		return zero, e
	}
	last, e := current.VerifyBootstrapServer(&c.state, c.candidates)
	if e != nil || first != last || !observed.Valid(c.verifier.now()) {
		return zero, value.ErrDenied
	}
	return last, nil
}
