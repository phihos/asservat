package mtls

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func connectorObservationPinDigest(p value.ConnectorObservationPin) (artifact.Digest, error) {
	if !p.Valid() {
		return artifact.Digest{}, value.ErrInvalid
	}
	b, e := json.Marshal(p)
	if e != nil {
		return artifact.Digest{}, value.ErrInvalid
	}
	canonical := jsontext.Value(b)
	if canonical.Canonicalize() != nil {
		return artifact.Digest{}, value.ErrInvalid
	}
	h := sha256.New()
	h.Write([]byte("asservat-connector-observation-pin/v1\x00"))
	h.Write(canonical)
	var out artifact.Digest
	copy(out[:], h.Sum(nil))
	return out, nil
}

func connectorObservationReplyWire(v value.ConnectorObservation, p value.ConnectorObservationPin) (contracts.ConnectorObservationReply, error) {
	pin, e := connectorObservationPinDigest(p)
	if e != nil || !v.Matches(p, v.ObservedAt) {
		return contracts.ConnectorObservationReply{}, value.ErrInvalid
	}
	f := func(t time.Time) string { return t.Format(time.RFC3339Nano) }
	s, w := v.Source.Observation, v.Workload
	return contracts.ConnectorObservationReply{Format: contracts.ConnectorObservationFormat, Request: ownerObservationRequestWire(v.Request), Ordinal: v.Ordinal, ConnectionBinding: ownerObservationHex(v.ConnectionBinding), ConnectorLeaf: ownerObservationHex(v.Certificate.Digest), PinDigest: ownerObservationHex(pin), PodUID: w.Process.PodUID, ProcessEpoch: w.Process.ProcessEpoch, Pod: w.Pod, ReplicaSetUID: w.ReplicaSetUID, Configuration: contracts.APIContextRevision{UID: s.Profile.Revision.UID, Generation: s.Profile.Revision.Generation, Digest: ownerObservationHex(s.Profile.Revision.Digest)}, BackingRevision: s.Backing.Revision, BackingDigest: ownerObservationHex(s.Backing.Digest), SourceDigest: ownerObservationHex(s.Backing.SourceDigest), SourceObservedAt: f(s.ObservedAt), SourceFreshUntil: f(s.FreshUntil), WorkloadDigest: ownerObservationHex(w.WorkloadDigest), WorkloadObservedAt: f(w.ObservedAt), WorkloadFreshUntil: f(w.FreshUntil), ObservedAt: f(v.ObservedAt), FreshUntil: f(v.FreshUntil)}, nil
}

// The caller supplies the actual verified TLS leaf, original installed pin,
// request, expected ordinal and locally derived exporter. None comes from wire.
func parseConnectorObservationReply(w contracts.ConnectorObservationReply, p value.ConnectorObservationPin, leaf value.ConnectorCredentialCertificate, request value.OwnerObservationRequest, ordinal int, channel artifact.Digest, now time.Time) (value.ConnectorObservation, error) {
	var zero value.ConnectorObservation
	pin, e := connectorObservationPinDigest(p)
	if e != nil || w.Format != contracts.ConnectorObservationFormat || w.PinDigest != ownerObservationHex(pin) || w.ConnectorLeaf != ownerObservationHex(leaf.Digest) || w.Ordinal != ordinal || channel == (artifact.Digest{}) || w.ConnectionBinding != ownerObservationHex(channel) || w.Request != ownerObservationRequestWire(request) {
		return zero, value.ErrDenied
	}
	profile := p.Profile.Clone()
	profile.Revision = identity.Revision{UID: w.Configuration.UID, Generation: w.Configuration.Generation, Digest: contextStartDigest(w.Configuration.Digest)}
	source := value.ConnectorIdentitySource{Roles: p.Roles, Observation: value.ConnectorCredentialObservation{Profile: profile, Backing: value.ConnectorBackingObservation{Revision: w.BackingRevision, Digest: contextStartDigest(w.BackingDigest), SourceDigest: contextStartDigest(w.SourceDigest)}, ObservedAt: ownerObservationTime(w.SourceObservedAt), FreshUntil: ownerObservationTime(w.SourceFreshUntil)}}
	workload := value.ConnectorObservationWorkload{Process: value.ConnectorProcessIdentity{Binding: profile.Binding, PodUID: w.PodUID, ProcessEpoch: w.ProcessEpoch}, Pod: w.Pod, ReplicaSetUID: w.ReplicaSetUID, TemplateDigest: p.TemplateDigest, ImageDigest: p.ImageDigest, ProtectionDigest: p.ProtectionDigest, WorkloadDigest: contextStartDigest(w.WorkloadDigest), ObservedAt: ownerObservationTime(w.WorkloadObservedAt), FreshUntil: ownerObservationTime(w.WorkloadFreshUntil)}
	out := value.ConnectorObservation{Request: request, Ordinal: ordinal, ConnectionBinding: channel, Certificate: leaf, Source: source, Workload: workload, ObservedAt: ownerObservationTime(w.ObservedAt), FreshUntil: ownerObservationTime(w.FreshUntil)}
	if !out.Matches(p, now) {
		return zero, value.ErrDenied
	}
	return out, nil
}
