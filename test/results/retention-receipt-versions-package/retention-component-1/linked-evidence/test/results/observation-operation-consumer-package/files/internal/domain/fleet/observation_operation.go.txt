package fleet

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// These values describe ADR150's operation-owned native observations. They do
// not construct an operation, authenticate TLS, or replace a general full
// source/authentication port. Only the concrete native reader owns that state.
type OwnerObservationNativeFacts struct {
	Request                OwnerObservationRequest
	Pin                    OwnerObservationPin
	Peers                  []OwnerObservationNativePeer
	ObservedAt, FreshUntil time.Time
	Final                  bool
}
type OwnerObservationNativePeer struct {
	Binding            OwnerBinding
	Pod, ReplicaSetUID string
	Addresses          []string
	WorkloadDigest     artifact.Digest
}

func (v OwnerObservationNativeFacts) Clone() OwnerObservationNativeFacts {
	v.Peers = slices.Clone(v.Peers)
	for i := range v.Peers {
		v.Peers[i].Addresses = slices.Clone(v.Peers[i].Addresses)
	}
	return v
}

func (v OwnerObservationNativeFacts) Valid(now time.Time) bool {
	if !v.Request.Valid(now) || !v.Pin.Valid() || v.Request.RootID != v.Pin.RootID || len(v.Peers) < 1 || len(v.Peers) > 2 || !identity.Fresh(v.ObservedAt, v.FreshUntil, now, 5*time.Second) || v.ObservedAt.Before(v.Request.RequestedAt) || v.FreshUntil.After(v.Request.NotAfter) {
		return false
	}
	for i, p := range v.Peers {
		e := OwnerEndpoint{Binding: p.Binding, Pool: v.Pin.Pool, Pod: p.Pod, ReplicaSetUID: p.ReplicaSetUID, Addresses: p.Addresses, ObservedAt: v.ObservedAt, FreshUntil: v.FreshUntil}
		if !e.Valid(now) || p.WorkloadDigest == (artifact.Digest{}) || i > 0 && p.Binding == v.Peers[0].Binding {
			return false
		}
	}
	return true
}

// ValueObservedAt names this actual complete source-value read. NativeStartedAt
// always names the first bracket; even the final bracket cannot renew it.
type ConnectorObservationNativeValue struct {
	Request         OwnerObservationRequest
	Ordinal         int
	Source          ConnectorIdentitySource
	Workload        ConnectorObservationWorkload
	NativeStartedAt time.Time
	NativeUntil     time.Time
	ValueObservedAt time.Time
	Final           bool
}

func (v ConnectorObservationNativeValue) Clone() ConnectorObservationNativeValue {
	v.Source.Observation.Profile = v.Source.Observation.Profile.Clone()
	return v
}

func SameOwnerObservationRequest(a, b OwnerObservationRequest) bool {
	return a.RootID == b.RootID && a.ID == b.ID && a.Challenge == b.Challenge && a.RequestedAt.Equal(b.RequestedAt) && a.NotAfter.Equal(b.NotAfter)
}

func (v ConnectorObservationNativeValue) Matches(p ConnectorObservationPin, request OwnerObservationRequest, ordinal int, now time.Time) bool {
	s, w := v.Source.Observation, v.Workload
	if !SameOwnerObservationRequest(v.Request, request) || !request.Valid(now) || request.RootID != p.Profile.RootID || ordinal < 1 || ordinal > ConnectorObservationMaximumChecks || v.Ordinal != ordinal || v.Final != (ordinal == ConnectorObservationMaximumChecks) || !p.Compatible(v.Source) || !v.Source.Valid(now) || !w.Matches(p, now) || !identity.Fresh(v.NativeStartedAt, v.NativeUntil, now, 5*time.Second) {
		return false
	}
	return !v.NativeStartedAt.Before(request.RequestedAt) && !v.NativeUntil.After(request.NotAfter) &&
		w.ObservedAt.Equal(v.NativeStartedAt) && !w.FreshUntil.After(v.NativeUntil) &&
		s.ObservedAt.Equal(v.ValueObservedAt) && !v.ValueObservedAt.Before(v.NativeStartedAt) &&
		!s.FreshUntil.After(v.NativeUntil)
}

// Correlations received over the actual v2 channel remain public values. They
// cannot manufacture native authority or be fed to a v1 source port. The
// consumer separately verifies the real exporter/leaf and current SQL state.
type ConnectorObservationOperationValue struct {
	Native            ConnectorObservationNativeValue
	BracketID         string
	ConnectionBinding artifact.Digest
	Certificate       ConnectorCredentialCertificate
}

func (v ConnectorObservationOperationValue) Clone() ConnectorObservationOperationValue {
	v.Native = v.Native.Clone()
	return v
}

func (v ConnectorObservationOperationValue) Matches(p ConnectorObservationPin, request OwnerObservationRequest, ordinal int, now time.Time) bool {
	return authorization.UUID(v.BracketID) && v.ConnectionBinding != (artifact.Digest{}) && v.Certificate.Valid(now) && v.Certificate.Usage == "client" && v.Certificate.Binding == p.Profile.Binding && v.Native.Matches(p, request, ordinal, now) && !v.Native.NativeUntil.After(v.Certificate.NotAfter)
}

// Until intersects already observed bounds; it neither observes nor refreshes
// anything. Consumers must retain their original caller/socket bounds as well.
func (v ConnectorObservationOperationValue) Until() time.Time {
	n := v.Native
	end := identity.Earlier(n.Request.NotAfter, n.NativeUntil)
	end = identity.Earlier(end, n.Source.Observation.FreshUntil)
	end = identity.Earlier(end, n.Workload.FreshUntil)
	return identity.Earlier(end, v.Certificate.NotAfter)
}

// Continues compares the actual value and private-operation correlations, not
// a new proof. A caller must also require Matches for the expected ordinal.
func (v ConnectorObservationOperationValue) Continues(first ConnectorObservationOperationValue) bool {
	a, b := first.Native, v.Native
	x, y := a.Workload, b.Workload
	return v.BracketID == first.BracketID && v.ConnectionBinding == first.ConnectionBinding && v.Certificate == first.Certificate &&
		SameOwnerObservationRequest(a.Request, b.Request) && a.NativeStartedAt.Equal(b.NativeStartedAt) && !b.NativeUntil.After(a.NativeUntil) && !b.ValueObservedAt.Before(a.ValueObservedAt) &&
		a.Source.Roles == b.Source.Roles && a.Source.Observation.SameSource(b.Source.Observation) && !b.Source.Observation.FreshUntil.After(a.Source.Observation.FreshUntil) &&
		x.Process == y.Process && x.Pod == y.Pod && x.ReplicaSetUID == y.ReplicaSetUID && x.TemplateDigest == y.TemplateDigest && x.ImageDigest == y.ImageDigest && x.ProtectionDigest == y.ProtectionDigest && x.WorkloadDigest == y.WorkloadDigest && x.ObservedAt.Equal(y.ObservedAt) && !y.FreshUntil.After(x.FreshUntil)
}
