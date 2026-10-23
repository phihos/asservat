package mtls

import (
	"asservat.local/asservat/internal/application/evidence"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)

type NativeWorkerCertificates interface {
	ReadNativeWorkerCertificate(context.Context, string, string, []byte) (value.WorkerCertificate, error)
}

// NativePeerChecks reuses the installed exact-profile issuer catalog and actual
// TLS verifiers. A forwarded acquisition leaf is a trusted connector report,
// independently matched to the original activated SQL certificate, never a
// manufactured hub TLS state or a replacement worker/process.
type NativePeerChecks struct {
	Workers           evidence.WorkerEnrollmentBindings
	Projection        evidence.ProjectionNativeReader
	WorkerTrust       *WorkerTrustCatalog
	Certificates      NativeWorkerCertificates
	Origins           evidence.NativeOrigins
	ConnectorVerifier *PeerVerifier
	Connectors        *fleetapp.PeerAuthenticator
	Now               func() time.Time
}

func (p *NativePeerChecks) worker(ctx context.Context, h contracts.NativeHello) (value.AcquisitionWorkerIdentity, *KeyPeerVerifier, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || p.WorkerTrust == nil || p.Now == nil {
		return value.AcquisitionWorkerIdentity{}, nil, artifact.ErrInvalid
	}
	parent := value.AcquisitionParentFor(h.Reference.SessionID, h.Reference.QueryID)
	var w value.AcquisitionWorkerIdentity
	var e error
	switch parent.Purpose {
	case value.AcquisitionDownload:
		if p.Workers == nil {
			return w, nil, artifact.ErrInvalid
		}
		original, err := p.Workers.ReadDownloadWorkerEnrollment(ctx, parent.ID, h.Reference.WorkerID)
		if err != nil || !original.Valid(p.Now()) {
			return w, nil, artifact.ErrDownloadUnavailable
		}
		w = original.Acquisition()
	case value.AcquisitionProjection:
		if p.Projection == nil {
			return w, nil, artifact.ErrInvalid
		}
		w, e = p.Projection.ReadAcquisitionEnrollment(ctx, parent, h.Reference.WorkerID)
	default:
		return w, nil, artifact.ErrInvalid
	}
	if !parent.Valid() || w.Worker.Intent.Parent != parent || w.Worker.Intent.ID != h.Reference.WorkerID {
		return w, nil, artifact.ErrDownloadUnavailable
	}
	if e != nil || !w.Valid(p.Now()) || w.Worker.Binding.InstallationID != h.Reference.InstallationID {
		return w, nil, artifact.ErrDownloadUnavailable
	}
	roots, e := p.WorkerTrust.IssuerRoots(w.Worker.Intent.Profile, p.Now())
	if e != nil {
		return w, nil, e
	}
	verifier, e := NewKeyPeerVerifier(roots, h.Reference.InstallationID, p.Now)
	return w, verifier, e
}
func (p *NativePeerChecks) CheckWorkerNative(ctx context.Context, state *tls.ConnectionState, h contracts.NativeHello) (evidence.NativeOrigin, error) {
	var zero evidence.NativeOrigin
	w, v, e := p.worker(ctx, h)
	if e != nil {
		return zero, e
	}
	peer, e := v.Verify(state)
	if e != nil || peer.Role != "acquisition" || peer.PeerID != w.Worker.Binding.PodUID || len(h.WorkerLeaf) != 0 {
		return zero, artifact.ErrDownloadUnavailable
	}
	call, stop := context.WithDeadline(ctx, w.FreshUntil)
	defer stop()
	origin, e := p.Origins.CheckAcquisition(call, h.Reference.InstallationID, w.Worker.Intent.Parent, h.Reference.WorkerID, peer, h.WorkerToken)
	if e != nil {
		var idle *evidence.NativeIdle
		if errors.As(e, &idle) && idle != nil {
			idle.Until = identity.Earlier(idle.Until, w.FreshUntil)
			if idle.Worker.Worker.Binding != w.Worker.Binding || !idle.Valid(p.Now()) || call.Err() != nil {
				return zero, artifact.ErrDownloadUnavailable
			}
		}
		return zero, e
	}
	if !origin.Lease.Operation.CurrentValid(p.Now()) || origin.Lease.Operation.Path.AcquisitionClusterID != w.Worker.Intent.Profile.ClusterID || origin.Lease.Operation.Path.WorkerConfiguration != w.Worker.Intent.Profile.Configuration || origin.Proof.Binding != w.Worker.Binding {
		return zero, artifact.ErrDownloadUnavailable
	}
	origin.Lease.Until = identity.Earlier(origin.Lease.Until, w.FreshUntil)
	if !origin.Lease.Valid(p.Now()) || call.Err() != nil {
		return zero, artifact.ErrDownloadExpired
	}
	return origin, nil
}
func (p *NativePeerChecks) CheckForwardedNative(ctx context.Context, state *tls.ConnectionState, h contracts.NativeHello) (evidence.NativeOrigin, error) {
	var zero evidence.NativeOrigin
	if p == nil || p.ConnectorVerifier == nil || p.Connectors == nil || len(h.WorkerLeaf) < 1 || len(h.WorkerLeaf) > 16<<10 {
		return zero, artifact.ErrInvalid
	}
	connector, e := p.ConnectorVerifier.Verify(state)
	if e != nil || connector.Binding.Role != fleet.ConnectorPeer || connector.Binding.InstallationID != h.Reference.InstallationID {
		return zero, artifact.ErrDownloadUnavailable
	}
	authenticated, e := p.Connectors.AuthenticatePeer(ctx, connector)
	if e != nil {
		return zero, e
	}
	call, stop := context.WithDeadline(ctx, authenticated.ValidUntil)
	defer stop()
	w, v, e := p.worker(call, h)
	if e != nil || w.Worker.Binding.ClusterID != connector.Binding.ClusterID {
		return zero, artifact.ErrDownloadUnavailable
	}
	var certificate value.WorkerCertificate
	switch w.Worker.Intent.Parent.Purpose {
	case value.AcquisitionDownload:
		if p.Certificates == nil {
			return zero, artifact.ErrInvalid
		}
		certificate, e = p.Certificates.ReadNativeWorkerCertificate(call, h.Reference.SessionID, h.Reference.WorkerID, h.WorkerLeaf)
	case value.AcquisitionProjection:
		certificate, e = p.Projection.ReadProjectionWorkerCertificate(call, h.Reference.QueryID, h.Reference.WorkerID, h.WorkerLeaf)
	default:
		return zero, artifact.ErrInvalid
	}
	if e != nil || !bytes.Equal(certificate.DER, h.WorkerLeaf) {
		return zero, artifact.ErrDownloadUnavailable
	}
	certs := make([]*x509.Certificate, 0, 1+len(certificate.ChainDER))
	for _, der := range append([][]byte{certificate.DER}, certificate.ChainDER...) {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return zero, artifact.ErrDownloadUnavailable
		}
		certs = append(certs, c)
	}
	peer, e := v.verifyCertificates(certs)
	if e != nil || peer != certificate.Peer || peer.PeerID != w.Worker.Binding.PodUID {
		return zero, artifact.ErrDownloadUnavailable
	}
	origin, e := p.Origins.CheckAcquisition(call, h.Reference.InstallationID, w.Worker.Intent.Parent, h.Reference.WorkerID, peer, h.WorkerToken)
	if e != nil {
		return zero, e
	}
	if !origin.Lease.Operation.CurrentValid(p.Now()) || origin.Lease.Operation.Path.ConnectorClusterID != connector.Binding.ClusterID || origin.Lease.Operation.Path.AcquisitionClusterID != w.Worker.Intent.Profile.ClusterID || origin.Lease.Operation.Path.WorkerConfiguration != w.Worker.Intent.Profile.Configuration || nativeWireRef(origin.Lease.Operation.Reference) != h.Reference || origin.Proof.Binding != w.Worker.Binding {
		return zero, artifact.ErrDownloadUnavailable
	}
	origin.Lease.Until = identity.Earlier(origin.Lease.Until, identity.Earlier(authenticated.ValidUntil, w.FreshUntil))
	if !origin.Lease.Valid(p.Now()) || call.Err() != nil {
		return zero, artifact.ErrDownloadExpired
	}
	return origin, nil
}
func nativeWireRef(r value.NativeReference) contracts.NativeReference {
	return contracts.NativeReference{InstallationID: r.InstallationID, SessionID: r.SessionID, QueryID: r.QueryID, WorkerID: r.WorkerID, OperationID: r.OperationID, Fence: r.Fence}
}

// RecheckWorkerNative and RecheckForwardedNative retain the original proof and
// deadline. They revalidate current peer registry/worker/operation on each frame;
// they never repeat or extend a consumed Pod proof from its wire token.
func (p *NativePeerChecks) RecheckWorkerNative(ctx context.Context, state *tls.ConnectionState, original evidence.NativeOrigin) (value.NativeLease, error) {
	h := contracts.NativeHello{Reference: nativeWireRef(original.Lease.Operation.Reference)}
	w, v, e := p.worker(ctx, h)
	if e != nil {
		return value.NativeLease{}, e
	}
	peer, e := v.Verify(state)
	if e != nil || !original.Lease.Operation.CurrentValid(p.Now()) || original.Lease.Operation.Path.AcquisitionClusterID != w.Worker.Intent.Profile.ClusterID || original.Lease.Operation.Path.WorkerConfiguration != w.Worker.Intent.Profile.Configuration || peer != original.Proof.Peer || w.Worker.Binding != original.Proof.Binding {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	lease, e := p.Origins.Recheck(ctx, original)
	if e != nil {
		return lease, e
	}
	lease.Until = identity.Earlier(lease.Until, w.FreshUntil)
	if !lease.Valid(p.Now()) || ctx.Err() != nil {
		return value.NativeLease{}, artifact.ErrDownloadExpired
	}
	return lease, nil
}
func (p *NativePeerChecks) RecheckForwardedNative(ctx context.Context, state *tls.ConnectionState, original evidence.NativeOrigin) (value.NativeLease, error) {
	if p == nil || p.ConnectorVerifier == nil || p.Connectors == nil {
		return value.NativeLease{}, artifact.ErrInvalid
	}
	connector, e := p.ConnectorVerifier.Verify(state)
	if e != nil || !original.Lease.Operation.CurrentValid(p.Now()) || connector.Binding.ClusterID != original.Lease.Operation.Path.ConnectorClusterID || connector.Binding.Role != fleet.ConnectorPeer || connector.Binding.ClusterID != original.Proof.Binding.ClusterID || connector.Binding.InstallationID != original.Proof.Binding.InstallationID {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	authenticated, e := p.Connectors.AuthenticatePeer(ctx, connector)
	if e != nil {
		return value.NativeLease{}, e
	}
	lease, e := p.Origins.Recheck(ctx, original)
	if e != nil {
		return lease, e
	}
	lease.Until = identity.Earlier(lease.Until, authenticated.ValidUntil)
	if !lease.Valid(p.Now()) || ctx.Err() != nil {
		return value.NativeLease{}, artifact.ErrDownloadExpired
	}
	return lease, nil
}
