package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorObservationPin is independently installed delegation to an exact
// regional workload. A channel, certificate or received proof cannot supply it.
// The original profile is provenance; later independently accepted revisions
// are compatible only when these issuer, workload and role pins stay fixed.
type ConnectorObservationPin struct {
	Profile ConnectorCredentialProfile
	Roles   ConnectorIdentityRoles
	// Profile.ProtectionDigest pins the connector configuration-source guard;
	// ProtectionDigest here pins the distinct private workload namespace guard.
	TemplateDigest, ImageDigest, ProtectionDigest artifact.Digest
}

func (p ConnectorObservationPin) Valid() bool {
	return p.Profile.Valid() && !p.Profile.Suspended && !p.Profile.Retiring && p.Roles.Valid() && p.TemplateDigest != (artifact.Digest{}) && p.ImageDigest != (artifact.Digest{}) && p.ProtectionDigest != (artifact.Digest{})
}
func (p ConnectorObservationPin) Clone() ConnectorObservationPin {
	p.Profile = p.Profile.Clone()
	return p
}

// Compatible checks only immutable installed scope. It neither accepts the
// supplied revision nor renews source authority; current SQL49 checks do that.
// An original generation with changed bytes is never a compatible revision.
func (p ConnectorObservationPin) Compatible(s ConnectorIdentitySource) bool {
	if !p.Valid() || s.Roles != p.Roles || !s.Observation.Backing.Valid() {
		return false
	}
	actual := s.Observation.Profile
	if actual.Revision.UID != p.Profile.Revision.UID || actual.Revision.Generation < p.Profile.Revision.Generation || !actual.Revision.Valid() || actual.Revision.Generation == p.Profile.Revision.Generation && actual.Revision != p.Profile.Revision {
		return false
	}
	actual.Revision = p.Profile.Revision
	return actual.Equal(p.Profile)
}

// ConnectorObservationWorkload is a separate exact template observation, not
// the enrollment attester's general live-workload digest. It grants no capture
// or effect authority and contains no token, token hash, CSR or private key.
type ConnectorObservationWorkload struct {
	Process                                                       ConnectorProcessIdentity
	Pod, ReplicaSetUID                                            string
	TemplateDigest, ImageDigest, ProtectionDigest, WorkloadDigest artifact.Digest
	ObservedAt, FreshUntil                                        time.Time
}

func (w ConnectorObservationWorkload) Matches(p ConnectorObservationPin, now time.Time) bool {
	return p.Valid() && w.Process.Valid() && w.Process.Binding == p.Profile.Binding && identity.Text(w.Pod, 253) && authorization.UUID(w.ReplicaSetUID) && w.TemplateDigest == p.TemplateDigest && w.ImageDigest == p.ImageDigest && w.ProtectionDigest == p.ProtectionDigest && w.WorkloadDigest != (artifact.Digest{}) && identity.Fresh(w.ObservedAt, w.FreshUntil, now, 5*time.Second)
}

// ConnectorObservation is fresh local evidence on one actual TLS conversation.
// Source is reconstructed from the independent installed pin and exact received
// current revision/backing, never from caller-supplied roots or role names.
// The receiver must still check the exact activated SQL leaf/process and source.
type ConnectorObservation struct {
	Request                OwnerObservationRequest
	Ordinal                int
	ConnectionBinding      artifact.Digest
	Certificate            ConnectorCredentialCertificate
	Source                 ConnectorIdentitySource
	Workload               ConnectorObservationWorkload
	ObservedAt, FreshUntil time.Time
}

const ConnectorObservationMaximumChecks = 4 // two original reads around each of the two exact SQL registry checks

// ConnectorObservationAttestation retains the full source checked by the local
// native attester, including exact role names. It stays in the local process;
// the minimized remote reply omits token/CSR material and all role/root bytes.
type ConnectorObservationAttestation struct {
	Proof  ConnectorProcessProof
	Source ConnectorIdentitySource
}

func (a ConnectorObservationAttestation) Matches(p ConnectorObservationPin, now time.Time) bool {
	return a.Proof.Valid(now) && a.Source.Valid(now) && p.Compatible(a.Source) &&
		a.Proof.Configuration.SameSource(a.Source.Observation) &&
		a.Proof.ProtectionDigest == p.ProtectionDigest &&
		!a.Proof.FreshUntil.After(a.Source.Observation.FreshUntil)
}

func (o ConnectorObservation) Matches(p ConnectorObservationPin, now time.Time) bool {
	if !p.Valid() || !o.Request.Valid(now) || o.Request.RootID != p.Profile.RootID || o.Ordinal < 1 || o.Ordinal > ConnectorObservationMaximumChecks || o.ConnectionBinding == (artifact.Digest{}) || !o.Certificate.Valid(now) || o.Certificate.Usage != "client" || o.Certificate.Binding != p.Profile.Binding || !p.Compatible(o.Source) || !o.Source.Valid(now) || !o.Source.Observation.Valid(now) || !o.Workload.Matches(p, now) || !identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second) {
		return false
	}
	if o.ObservedAt.Before(o.Request.RequestedAt) || o.ObservedAt.Before(o.Source.Observation.ObservedAt) || o.ObservedAt.Before(o.Workload.ObservedAt) {
		return false
	}
	for _, until := range []time.Time{o.Request.NotAfter, o.Source.Observation.FreshUntil, o.Workload.FreshUntil, o.Certificate.NotAfter} {
		if o.FreshUntil.After(until) {
			return false
		}
	}
	return true
}
