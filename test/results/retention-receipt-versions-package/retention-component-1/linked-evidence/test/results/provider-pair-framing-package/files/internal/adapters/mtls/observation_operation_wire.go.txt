package mtls

import (
	"crypto/sha256"
	"crypto/tls"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func observationOperationRequestWire(r value.OwnerObservationRequest) contracts.ObservationOperationRequest {
	return contracts.ObservationOperationRequest{Format: contracts.OwnerObservationOperationFormat, RootID: r.RootID, ID: r.ID, Challenge: r.Challenge, RequestedAt: r.RequestedAt.UTC().Format(time.RFC3339Nano), NotAfter: r.NotAfter.UTC().Format(time.RFC3339Nano)}
}

// This separate exporter domain prevents a v1 full-proof conversation from
// supplying the weaker-but-explicit v2 bracket correlations. Actual TLS state,
// request and original installed selection remain constructor inputs.
func observationOperationConnection(s *tls.ConnectionState, r value.OwnerObservationRequest) (artifact.Digest, error) {
	if s == nil || !s.HandshakeComplete || s.DidResume || s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != "h2" || len(s.VerifiedChains) == 0 {
		return artifact.Digest{}, value.ErrDenied
	}
	b, e := contracts.EncodeObservationOperationRequest(observationOperationRequestWire(r))
	if e != nil {
		return artifact.Digest{}, value.ErrDenied
	}
	context := sha256.Sum256(b)
	material, e := s.ExportKeyingMaterial("EXPORTER-Asservat-Owner-Observation-v2", context[:], 32)
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

func connectorOperationReplyWire(v value.ConnectorObservationOperationValue, p value.ConnectorObservationPin, now time.Time) (contracts.ConnectorObservationOperationReply, error) {
	var zero contracts.ConnectorObservationOperationReply
	n := v.Native
	pin, e := connectorObservationPinDigest(p)
	if e != nil || !v.Matches(p, n.Request, n.Ordinal, now) {
		return zero, value.ErrDenied
	}
	f := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	s, w := n.Source.Observation, n.Workload
	return contracts.ConnectorObservationOperationReply{Format: contracts.ConnectorObservationOperationFormat, Request: observationOperationRequestWire(n.Request), Ordinal: n.Ordinal, BracketID: v.BracketID, ConnectionBinding: ownerObservationHex(v.ConnectionBinding), ConnectorLeaf: ownerObservationHex(v.Certificate.Digest), PinDigest: ownerObservationHex(pin), PodUID: w.Process.PodUID, ProcessEpoch: w.Process.ProcessEpoch, Pod: w.Pod, ReplicaSetUID: w.ReplicaSetUID, Configuration: contracts.APIContextRevision{UID: s.Profile.Revision.UID, Generation: s.Profile.Revision.Generation, Digest: ownerObservationHex(s.Profile.Revision.Digest)}, BackingRevision: s.Backing.Revision, BackingDigest: ownerObservationHex(s.Backing.Digest), SourceDigest: ownerObservationHex(s.Backing.SourceDigest), NativeStartedAt: f(n.NativeStartedAt), NativeUntil: f(n.NativeUntil), ValueObservedAt: f(n.ValueObservedAt), SourceFreshUntil: f(s.FreshUntil), WorkloadDigest: ownerObservationHex(w.WorkloadDigest), WorkloadFreshUntil: f(w.FreshUntil), Final: n.Final}, nil
}

func parseConnectorOperationReply(w contracts.ConnectorObservationOperationReply, p value.ConnectorObservationPin, leaf value.ConnectorCredentialCertificate, request value.OwnerObservationRequest, ordinal int, channel artifact.Digest, now time.Time) (value.ConnectorObservationOperationValue, error) {
	var zero value.ConnectorObservationOperationValue
	pin, e := connectorObservationPinDigest(p)
	if e != nil || w.Format != contracts.ConnectorObservationOperationFormat || w.PinDigest != ownerObservationHex(pin) || w.ConnectorLeaf != ownerObservationHex(leaf.Digest) || w.Ordinal != ordinal || channel == (artifact.Digest{}) || w.ConnectionBinding != ownerObservationHex(channel) || w.Request != observationOperationRequestWire(request) {
		return zero, value.ErrDenied
	}
	profile := p.Profile.Clone()
	profile.Revision = identity.Revision{UID: w.Configuration.UID, Generation: w.Configuration.Generation, Digest: contextStartDigest(w.Configuration.Digest)}
	start, end, observed := ownerObservationTime(w.NativeStartedAt), ownerObservationTime(w.NativeUntil), ownerObservationTime(w.ValueObservedAt)
	source := value.ConnectorIdentitySource{Roles: p.Roles, Observation: value.ConnectorCredentialObservation{Profile: profile, Backing: value.ConnectorBackingObservation{Revision: w.BackingRevision, Digest: contextStartDigest(w.BackingDigest), SourceDigest: contextStartDigest(w.SourceDigest)}, ObservedAt: observed, FreshUntil: ownerObservationTime(w.SourceFreshUntil)}}
	work := value.ConnectorObservationWorkload{Process: value.ConnectorProcessIdentity{Binding: profile.Binding, PodUID: w.PodUID, ProcessEpoch: w.ProcessEpoch}, Pod: w.Pod, ReplicaSetUID: w.ReplicaSetUID, TemplateDigest: p.TemplateDigest, ImageDigest: p.ImageDigest, ProtectionDigest: p.ProtectionDigest, WorkloadDigest: contextStartDigest(w.WorkloadDigest), ObservedAt: start, FreshUntil: ownerObservationTime(w.WorkloadFreshUntil)}
	out := value.ConnectorObservationOperationValue{Native: value.ConnectorObservationNativeValue{Request: request, Ordinal: ordinal, Source: source, Workload: work, NativeStartedAt: start, NativeUntil: end, ValueObservedAt: observed, Final: w.Final}, BracketID: w.BracketID, ConnectionBinding: channel, Certificate: leaf}
	if !out.Matches(p, request, ordinal, now) {
		return zero, value.ErrDenied
	}
	return out, nil
}

func restrictConnectorOperationValue(v value.ConnectorObservationOperationValue, end time.Time) value.ConnectorObservationOperationValue {
	v = v.Clone()
	v.Native.NativeUntil = identity.Earlier(v.Native.NativeUntil, end)
	v.Native.Source.Observation.FreshUntil = identity.Earlier(v.Native.Source.Observation.FreshUntil, end)
	v.Native.Workload.FreshUntil = identity.Earlier(v.Native.Workload.FreshUntil, end)
	return v
}
