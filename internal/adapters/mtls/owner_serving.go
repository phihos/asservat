package mtls

import (
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	permissions "asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
)

var _ app.OwnerServingIdentity = (*OwnerCredentials)(nil)
var _ app.OwnerClientIdentity = (*OwnerCredentials)(nil)

func (c *OwnerCredentials) ServingCertificate() (value.OwnerCertificate, error) {
	if c == nil || c.usage != "server" {
		return value.OwnerCertificate{}, value.ErrDenied
	}
	return c.Certificate()
}

func (c *OwnerCredentials) VerifyServingCertificate(configuration value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
	return c.verifyLocalCertificate(configuration, "server")
}
func (c *OwnerCredentials) ClientCertificate() (value.OwnerCertificate, error) {
	if c == nil || c.usage != "client" {
		return value.OwnerCertificate{}, value.ErrDenied
	}
	return c.Certificate()
}
func (c *OwnerCredentials) VerifyClientCertificate(configuration value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
	return c.verifyLocalCertificate(configuration, "client")
}
func (c *OwnerCredentials) verifyLocalCertificate(configuration value.OwnerConfigurationObservation, usage string) (value.OwnerCertificate, error) {
	var zero value.OwnerCertificate
	if c == nil || c.usage != usage {
		return zero, value.ErrDenied
	}
	initial, err := c.Certificate()
	if err != nil {
		return zero, err
	}
	configuration.Configuration = configuration.Configuration.Clone()
	p := configuration.Configuration.Pool
	if !configuration.Valid(c.now()) || configuration.Configuration.Suspended || p.InstallationID != c.binding.InstallationID || p.ClusterID != c.binding.ClusterID || p.IssuerEpoch != c.binding.IssuerEpoch {
		return zero, value.ErrDenied
	}
	cert, err := c.snapshot()
	if err != nil {
		return zero, err
	}
	chain := make([]*x509.Certificate, 0, len(cert.Certificate))
	for _, der := range cert.Certificate {
		parsed, e := x509.ParseCertificate(der)
		if e != nil {
			return zero, value.ErrDenied
		}
		chain = append(chain, parsed)
	}
	pinned, err := c.verifier.verifyCertificates(chain, usage)
	if err != nil || !sameOwnerCertificate(pinned, initial) {
		return zero, value.ErrDenied
	}
	current, err := c.verifier.currentVerifier(configuration)
	if err != nil {
		return zero, err
	}
	checked, err := current.verifyCertificates(chain, usage)
	last, live := c.Certificate()
	if err != nil || live != nil || !sameOwnerCertificate(checked, initial) || !sameOwnerCertificate(last, initial) || !configuration.Valid(c.now()) {
		return zero, value.ErrDenied
	}
	return checked, nil
}

// OwnerRequestPeers adapts actual HTTP TLS state and a separately owned server
// key to current application checks. It conveys no evidence/locator authority.
type OwnerRequestPeers struct {
	Verifier      *OwnerPeerVerifier
	Authenticator *app.OwnerAuthenticator
	Server        *OwnerCredentials
}

func (p *OwnerRequestPeers) AuthenticateOwnerRequest(ctx context.Context, state *tls.ConnectionState) (value.AuthenticatedOwner, error) {
	if p == nil || p.Verifier == nil || p.Authenticator == nil {
		return value.AuthenticatedOwner{}, value.ErrInvalid
	}
	connection, err := NewOwnerClientConnection(p.Verifier, state)
	if err != nil {
		return value.AuthenticatedOwner{}, err
	}
	return p.Authenticator.AuthenticateOwner(ctx, connection)
}
func (p *OwnerRequestPeers) CheckOwnerServing(ctx context.Context) (time.Time, error) {
	if p == nil || p.Authenticator == nil || p.Server == nil {
		return time.Time{}, value.ErrInvalid
	}
	return p.Authenticator.CheckOwnerServing(ctx, p.Server)
}

func (p *OwnerRequestPeers) CheckNativeHub(ctx context.Context, operation permissions.NativeOperation) (time.Time, error) {
	if p == nil || p.Authenticator == nil || p.Server == nil {
		return time.Time{}, value.ErrInvalid
	}
	// The refusal keeps its decision (ErrDenied) and names the closed stage:
	// the serving authentication step with its remaining-deadline bucket, the
	// operation's own validity, or the hub placement (installed native84).
	var refused string
	observed, e := p.Authenticator.ObserveOwnerServing(app.ChainRefusalSteps(ctx, func(step string) {
		if refused == "" {
			refused = step
		}
	}), p.Server)
	switch {
	case e != nil:
		if refused == "" {
			refused = "unknown"
		}
		return time.Time{}, answerStep("serving/"+refused, value.ErrDenied, nil)
	case !operation.CurrentValid(p.Authenticator.Now()):
		return time.Time{}, answerStep("operation"+app.RemainingBucket(ctx, p.Authenticator.Now()), value.ErrDenied, nil)
	case observed.Pool.InstallationID != operation.Reference.InstallationID || observed.Pool.ClusterID != operation.Path.HubClusterID || observed.ConfigurationRevision != operation.Path.HubConfiguration || observed.Certificate.Binding.PodUID != operation.HubPodUID || observed.Certificate.Binding.ProcessEpoch != operation.HubProcessEpoch:
		return time.Time{}, answerStep("placement", value.ErrDenied, nil)
	}
	return identity.Earlier(observed.ValidUntil, operation.Until), nil
}
