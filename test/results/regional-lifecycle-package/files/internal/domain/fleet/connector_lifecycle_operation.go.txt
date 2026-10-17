package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorLifecyclePurpose is a closed local enrollment/signing purpose. It
// grants no SQL, issuer or observation-channel authority and has no wire form.
type ConnectorLifecyclePurpose string

const (
	ConnectorLifecycleEnroll ConnectorLifecyclePurpose = "enroll"
	ConnectorLifecycleClient ConnectorLifecyclePurpose = "client-sign"
	ConnectorLifecycleServer ConnectorLifecyclePurpose = "server-sign"
)

// ConnectorLifecyclePhase names actual native work, not a fresh authority
// interval. Initial and Final are independent complete native observations;
// BeforeEffect and BeforeActivation are actual current-value/token/chain reads
// under the original enforcement proof. A stored acknowledged result may skip
// BeforeEffect. Only the private operation owner can advance its phase.
type ConnectorLifecyclePhase uint8

const (
	ConnectorLifecycleInitial ConnectorLifecyclePhase = iota + 1
	ConnectorLifecycleBeforeEffect
	ConnectorLifecycleBeforeActivation
	ConnectorLifecycleFinal
)

type ConnectorLifecycleBinding struct {
	ID                    string
	Purpose               ConnectorLifecyclePurpose
	Process               ConnectorProcessIdentity
	RequestedAt, NotAfter time.Time
}

func (b ConnectorLifecycleBinding) Valid(now time.Time) bool {
	return authorization.UUID(b.ID) && b.Process.Valid() &&
		(b.Purpose == ConnectorLifecycleEnroll || b.Purpose == ConnectorLifecycleClient || b.Purpose == ConnectorLifecycleServer) &&
		identity.Fresh(b.RequestedAt, b.NotAfter, now, 5*time.Second)
}

// ConnectorLifecycleObservation is a correlation/result value, never a factory
// for retained native authority. Original always retains the initial complete
// proof and its original dates; Source has the actual current value-read dates.
// FinalProof exists only after a second independent complete native observation.
// Until can only shorten those original/request/current/final bounds.
type ConnectorLifecycleObservation struct {
	Binding    ConnectorLifecycleBinding
	Phase      ConnectorLifecyclePhase
	Original   ConnectorProcessProof
	Source     ConnectorIdentitySource
	FinalProof *ConnectorProcessProof
	Until      time.Time
}

func (o ConnectorLifecycleObservation) Valid(now time.Time) bool {
	p := o.Original
	s := o.Source.Observation
	if !o.Binding.Valid(now) || o.Phase < ConnectorLifecycleInitial || o.Phase > ConnectorLifecycleFinal ||
		!p.Valid(now) || p.Process != o.Binding.Process || p.ObservedAt.Before(o.Binding.RequestedAt) || p.FreshUntil.After(o.Binding.NotAfter) ||
		!o.Source.Valid(now) || !s.SameSource(p.Configuration) || s.ObservedAt.Before(p.ObservedAt) ||
		!now.Before(o.Until) || o.Until.After(o.Binding.NotAfter) || o.Until.After(p.FreshUntil) || o.Until.After(s.FreshUntil) {
		return false
	}
	if o.Phase != ConnectorLifecycleFinal {
		return o.FinalProof == nil
	}
	f := o.FinalProof
	return f != nil && f.Valid(now) && sameConnectorLifecycleFacts(p, *f) &&
		!f.ObservedAt.Before(p.ObservedAt) && !f.FreshUntil.After(p.FreshUntil) && !o.Until.After(f.FreshUntil)
}

// Continues compares immutable original observations rather than treating two
// independently valid values with equal correlation IDs as the same operation.
// The consuming coordinator must additionally retain the same private handle.
func (o ConnectorLifecycleObservation) Continues(prior ConnectorLifecycleObservation) bool {
	a, b := o.Binding, prior.Binding
	if a.ID != b.ID || a.Purpose != b.Purpose || a.Process != b.Process || !a.RequestedAt.Equal(b.RequestedAt) || !a.NotAfter.Equal(b.NotAfter) ||
		!sameConnectorLifecycleFacts(o.Original, prior.Original) || !sameConnectorLifecycleDates(o.Original, prior.Original) ||
		o.Source.Roles != prior.Source.Roles || !o.Source.Observation.SameSource(prior.Source.Observation) ||
		o.Source.Observation.ObservedAt.Before(prior.Source.Observation.ObservedAt) || o.Until.After(prior.Until) {
		return false
	}
	return prior.Phase == ConnectorLifecycleInitial && (o.Phase == ConnectorLifecycleBeforeEffect || o.Phase == ConnectorLifecycleBeforeActivation) ||
		prior.Phase == ConnectorLifecycleBeforeEffect && o.Phase == ConnectorLifecycleBeforeActivation ||
		prior.Phase == ConnectorLifecycleBeforeActivation && o.Phase == ConnectorLifecycleFinal
}

func (o ConnectorLifecycleObservation) Clone() ConnectorLifecycleObservation {
	o.Original = o.Original.Clone()
	o.Source.Observation.Profile = o.Source.Observation.Profile.Clone()
	if o.FinalProof != nil {
		p := o.FinalProof.Clone()
		o.FinalProof = &p
	}
	return o
}

func sameConnectorLifecycleFacts(a, b ConnectorProcessProof) bool {
	return a.Process == b.Process && a.Configuration.SameSource(b.Configuration) &&
		a.Pod == b.Pod && a.ReplicaSet == b.ReplicaSet && a.ReplicaSetUID == b.ReplicaSetUID &&
		a.ClientKeyDigest == b.ClientKeyDigest && a.ServerKeyDigest == b.ServerKeyDigest &&
		a.TokenDigest == b.TokenDigest && a.WorkloadDigest == b.WorkloadDigest && a.ProtectionDigest == b.ProtectionDigest
}

func sameConnectorLifecycleDates(a, b ConnectorProcessProof) bool {
	return a.ObservedAt.Equal(b.ObservedAt) && a.FreshUntil.Equal(b.FreshUntil) &&
		a.Configuration.ObservedAt.Equal(b.Configuration.ObservedAt) && a.Configuration.FreshUntil.Equal(b.Configuration.FreshUntil)
}
