package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerObservationPin is the installed delegation for one original owner
// workload. It is not learned from a leaf, Hello, current Deployment or SQL row.
// The exact template and image use the existing API-defaulted template digest.
type OwnerObservationPin struct {
	RootID, SourceUID                             string
	Pool                                          OwnerPool
	TemplateDigest, ImageDigest, ProtectionDigest artifact.Digest
}

func (p OwnerObservationPin) Valid() bool {
	return authorization.UUID(p.RootID) && authorization.UUID(p.SourceUID) && p.Pool.Valid() && p.Pool.NativeBootstrap == OwnerBootstrapProfile && p.TemplateDigest != (artifact.Digest{}) && p.ImageDigest != (artifact.Digest{}) && p.ProtectionDigest != (artifact.Digest{})
}

// OwnerObservationRequest selects only the server's own public peer facts.
// It cannot contain a workload target, labels, user credential or effect.
type OwnerObservationRequest struct {
	RootID, ID, Challenge string
	RequestedAt, NotAfter time.Time
}

func (r OwnerObservationRequest) Valid(now time.Time) bool {
	return authorization.UUID(r.RootID) && authorization.UUID(r.ID) && authorization.UUID(r.Challenge) && identity.Fresh(r.RequestedAt, r.NotAfter, now, 5*time.Second)
}

type OwnerObservationWorkload struct {
	Pin                    OwnerObservationPin
	Binding                OwnerBinding
	Pod, ReplicaSetUID     string
	WorkloadDigest         artifact.Digest
	ObservedAt, FreshUntil time.Time
}

func (w OwnerObservationWorkload) Valid(now time.Time) bool {
	p, b := w.Pin.Pool, w.Binding
	return w.Pin.Valid() && b.Valid() && b.InstallationID == p.InstallationID && b.ClusterID == p.ClusterID && b.IssuerEpoch == p.IssuerEpoch && identity.Text(w.Pod, 253) && authorization.UUID(w.ReplicaSetUID) && w.WorkloadDigest != (artifact.Digest{}) && identity.Fresh(w.ObservedAt, w.FreshUntil, now, 5*time.Second)
}

// OwnerObservation is a delegated current observation bound to one TLS stream.
// A decoded value alone cannot authenticate a peer. The consumer must derive
// ConnectionBinding from its actual TLS exporter, match its pre-read candidate
// set and independently check current SQL registration and accepted roots.
type OwnerObservation struct {
	Request                OwnerObservationRequest
	ConnectionBinding      artifact.Digest
	Connector              PeerCertificate
	Owner                  AuthenticatedOwner
	Workload               OwnerObservationWorkload
	ObservedAt, FreshUntil time.Time
}

func (o OwnerObservation) Valid(now time.Time) bool {
	w, a := o.Workload, o.Owner
	if !o.Request.Valid(now) || o.ConnectionBinding == (artifact.Digest{}) || !o.Connector.Valid(now) || o.Connector.Binding.Role != ConnectorPeer || !a.Valid(now) || a.Certificate.Usage != "server" || !w.Valid(now) || o.Request.RootID != w.Pin.RootID || a.Certificate.Binding != w.Binding || a.Pool != w.Pin.Pool || a.ConfigurationRevision.UID != w.Pin.SourceUID || a.Pod != w.Pod || a.ReplicaSetUID != w.ReplicaSetUID || a.ProtectionDigest != w.Pin.ProtectionDigest || o.Connector.Binding.InstallationID != a.Pool.InstallationID {
		return false
	}
	if !identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second) || o.ObservedAt.Before(o.Request.RequestedAt) || o.ObservedAt.Before(a.VerifiedAt) || o.ObservedAt.Before(w.ObservedAt) {
		return false
	}
	for _, end := range []time.Time{o.Request.NotAfter, a.ValidUntil, w.FreshUntil, o.Connector.NotAfter} {
		if o.FreshUntil.After(end) {
			return false
		}
	}
	return true
}

// Matches never manufactures a new interval. The local caller retains the
// original request and independent pin while verifying the actual connection.
func (o OwnerObservation) Matches(r OwnerObservationRequest, p OwnerObservationPin, connection artifact.Digest, connector PeerCertificate, owner OwnerCertificate, now time.Time) bool {
	return o.Valid(now) && o.Request.RootID == r.RootID && o.Request.ID == r.ID && o.Request.Challenge == r.Challenge && o.Request.RequestedAt.Equal(r.RequestedAt) && o.Request.NotAfter.Equal(r.NotAfter) && o.Workload.Pin == p && o.ConnectionBinding == connection && o.Connector == connector && o.Owner.Certificate == owner
}
