package mtls

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func ownerObservationRequest(w contracts.OwnerObservationRequest, now time.Time) (value.OwnerObservationRequest, error) {
	start, a := time.Parse(time.RFC3339Nano, w.RequestedAt)
	end, b := time.Parse(time.RFC3339Nano, w.NotAfter)
	r := value.OwnerObservationRequest{RootID: w.RootID, ID: w.ID, Challenge: w.Challenge, RequestedAt: start, NotAfter: end}
	if a != nil || b != nil || w.Format != contracts.OwnerObservationFormat || !r.Valid(now) || start.Format(time.RFC3339Nano) != w.RequestedAt || end.Format(time.RFC3339Nano) != w.NotAfter {
		return value.OwnerObservationRequest{}, value.ErrDenied
	}
	return r, nil
}
func ownerObservationRequestWire(r value.OwnerObservationRequest) contracts.OwnerObservationRequest {
	return contracts.OwnerObservationRequest{Format: contracts.OwnerObservationFormat, RootID: r.RootID, ID: r.ID, Challenge: r.Challenge, RequestedAt: r.RequestedAt.Format(time.RFC3339Nano), NotAfter: r.NotAfter.Format(time.RFC3339Nano)}
}
func ownerObservationPinDigest(p value.OwnerObservationPin) (artifact.Digest, error) {
	if !p.Valid() {
		return artifact.Digest{}, value.ErrInvalid
	}
	b, e := json.Marshal(p)
	if e != nil {
		return artifact.Digest{}, value.ErrInvalid
	}
	c := jsontext.Value(b)
	if c.Canonicalize() != nil {
		return artifact.Digest{}, value.ErrInvalid
	}
	h := sha256.New()
	h.Write([]byte("asservat-owner-observation-pin/v1\x00"))
	h.Write(c)
	var out artifact.Digest
	copy(out[:], h.Sum(nil))
	return out, nil
}

// Both endpoints call this over their actual completed TLS state. It never
// accepts an exporter value supplied in a request as a connection capability.
func ownerObservationConnection(s *tls.ConnectionState, r value.OwnerObservationRequest) (artifact.Digest, error) {
	if s == nil || !s.HandshakeComplete || s.DidResume || s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != "h2" || len(s.VerifiedChains) == 0 {
		return artifact.Digest{}, value.ErrDenied
	}
	b, e := contracts.EncodeOwnerObservationRequest(ownerObservationRequestWire(r))
	if e != nil {
		return artifact.Digest{}, value.ErrDenied
	}
	context := sha256.Sum256(b)
	material, e := s.ExportKeyingMaterial("EXPORTER-Asservat-Owner-Observation-v1", context[:], 32)
	if e != nil || len(material) != 32 {
		return artifact.Digest{}, value.ErrDenied
	}
	defer clear(material)
	var out artifact.Digest
	copy(out[:], material)
	if out == (artifact.Digest{}) {
		return out, value.ErrDenied
	}
	return out, nil
}
func ownerObservationHex(d artifact.Digest) string { return hex.EncodeToString(d[:]) }
func ownerObservationTime(s string) time.Time {
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil || t.Format(time.RFC3339Nano) != s {
		return time.Time{}
	}
	return t
}
func ownerObservationReplyWire(v value.OwnerObservation) (contracts.OwnerObservationReply, error) {
	pin, e := ownerObservationPinDigest(v.Workload.Pin)
	if e != nil {
		return contracts.OwnerObservationReply{}, e
	}
	f := func(t time.Time) string { return t.Format(time.RFC3339Nano) }
	return contracts.OwnerObservationReply{Format: contracts.OwnerObservationFormat, Request: ownerObservationRequestWire(v.Request), ConnectionBinding: ownerObservationHex(v.ConnectionBinding), ConnectorLeaf: ownerObservationHex(v.Connector.Digest), OwnerLeaf: ownerObservationHex(v.Owner.Certificate.Digest), PinDigest: ownerObservationHex(pin), EnrollmentID: v.Owner.EnrollmentID, Pod: v.Owner.Pod, ReplicaSetUID: v.Owner.ReplicaSetUID, Configuration: contracts.APIContextRevision{UID: v.Owner.ConfigurationRevision.UID, Generation: v.Owner.ConfigurationRevision.Generation, Digest: ownerObservationHex(v.Owner.ConfigurationRevision.Digest)}, ProtectionDigest: ownerObservationHex(v.Owner.ProtectionDigest), WorkloadDigest: ownerObservationHex(v.Workload.WorkloadDigest), OwnerObservedAt: f(v.Owner.VerifiedAt), OwnerFreshUntil: f(v.Owner.ValidUntil), WorkloadObservedAt: f(v.Workload.ObservedAt), WorkloadFreshUntil: f(v.Workload.FreshUntil), ObservedAt: f(v.ObservedAt), FreshUntil: f(v.FreshUntil)}, nil
}
func parseOwnerObservationReply(w contracts.OwnerObservationReply, p value.OwnerObservationPin, peer value.PeerCertificate, owner value.OwnerCertificate, now time.Time) (value.OwnerObservation, error) {
	var zero value.OwnerObservation
	pin, e := ownerObservationPinDigest(p)
	if e != nil || w.Format != contracts.OwnerObservationFormat || w.PinDigest != ownerObservationHex(pin) || w.ConnectorLeaf != ownerObservationHex(peer.Digest) || w.OwnerLeaf != ownerObservationHex(owner.Digest) {
		return zero, value.ErrDenied
	}
	r, e := ownerObservationRequest(w.Request, now)
	if e != nil {
		return zero, e
	}
	out := value.OwnerObservation{Request: r, ConnectionBinding: contextStartDigest(w.ConnectionBinding), Connector: peer, Owner: value.AuthenticatedOwner{Certificate: owner, EnrollmentID: w.EnrollmentID, Pool: p.Pool, Pod: w.Pod, ReplicaSetUID: w.ReplicaSetUID, ConfigurationRevision: identity.Revision{UID: w.Configuration.UID, Generation: w.Configuration.Generation, Digest: contextStartDigest(w.Configuration.Digest)}, ProtectionDigest: contextStartDigest(w.ProtectionDigest), VerifiedAt: ownerObservationTime(w.OwnerObservedAt), ValidUntil: ownerObservationTime(w.OwnerFreshUntil)}, Workload: value.OwnerObservationWorkload{Pin: p, Binding: owner.Binding, Pod: w.Pod, ReplicaSetUID: w.ReplicaSetUID, WorkloadDigest: contextStartDigest(w.WorkloadDigest), ObservedAt: ownerObservationTime(w.WorkloadObservedAt), FreshUntil: ownerObservationTime(w.WorkloadFreshUntil)}, ObservedAt: ownerObservationTime(w.ObservedAt), FreshUntil: ownerObservationTime(w.FreshUntil)}
	if !out.Valid(now) {
		return zero, value.ErrDenied
	}
	return out, nil
}
