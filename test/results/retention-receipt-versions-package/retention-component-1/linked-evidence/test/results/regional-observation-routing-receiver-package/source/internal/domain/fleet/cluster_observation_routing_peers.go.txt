package fleet

import "time"

// ClusterObservationRoutingPeers contains one fresh same-cluster delegation
// check over actual mutual TLS. It is not a wire credential, candidate list or
// source-observation result. The concrete adapter checks both original owner
// workloads and their independent current registry/route/native protection.
type ClusterObservationRoutingPeers struct {
	Query                          ClusterObservationLocatorQuery
	Pin                            OwnerObservationPin
	Sender, Holder                 AuthenticatedOwner
	SenderWorkload, HolderWorkload OwnerObservationWorkload
	Interval                       ClusterObservationInterval
}

func (p ClusterObservationRoutingPeers) Valid(now time.Time) bool {
	if !p.Query.Valid(now) || !p.Pin.Valid() || p.Pin.Pool.NativeCandidateLimit == 0 || p.Query.RootID != p.Pin.RootID || !p.Interval.Valid(now) || p.Interval.ObservedAt.Before(p.Query.RequestedAt) || p.Interval.FreshUntil.After(p.Query.NotAfter) || p.Sender.Certificate.Usage != "client" || p.Holder.Certificate.Usage != "server" || p.Sender.ConfigurationRevision != p.Holder.ConfigurationRevision {
		return false
	}
	for _, pair := range []struct {
		owner    AuthenticatedOwner
		workload OwnerObservationWorkload
	}{{p.Sender, p.SenderWorkload}, {p.Holder, p.HolderWorkload}} {
		o, w := pair.owner, pair.workload
		if !o.Valid(now) || !w.Valid(now) || o.Pool != p.Pin.Pool || w.Pin != p.Pin || o.ConfigurationRevision.UID != p.Pin.SourceUID || o.ProtectionDigest != p.Pin.ProtectionDigest || w.Binding != o.Certificate.Binding || w.Pod != o.Pod || w.ReplicaSetUID != o.ReplicaSetUID || p.Interval.ObservedAt.Before(o.VerifiedAt) || p.Interval.ObservedAt.Before(w.ObservedAt) || p.Interval.FreshUntil.After(o.ValidUntil) || p.Interval.FreshUntil.After(w.FreshUntil) {
			return false
		}
	}
	return true
}

// SamePeers compares immutable identity/source facts across independent checks;
// it deliberately never replaces or extends the first observation interval.
func (p ClusterObservationRoutingPeers) SamePeers(other ClusterObservationRoutingPeers) bool {
	if p.Query.RequestID != other.Query.RequestID || p.Query.Challenge != other.Query.Challenge || p.Query.RootID != other.Query.RootID || p.Query.ClusterID != other.Query.ClusterID || !p.Query.RequestedAt.Equal(other.Query.RequestedAt) || !p.Query.NotAfter.Equal(other.Query.NotAfter) || p.Pin != other.Pin {
		return false
	}
	same := func(a, b AuthenticatedOwner, aw, bw OwnerObservationWorkload) bool {
		return a.Certificate == b.Certificate && a.EnrollmentID == b.EnrollmentID && a.Pool == b.Pool && a.Pod == b.Pod && a.ReplicaSetUID == b.ReplicaSetUID && a.ConfigurationRevision == b.ConfigurationRevision && a.ProtectionDigest == b.ProtectionDigest && aw.Pin == bw.Pin && aw.Binding == bw.Binding && aw.Pod == bw.Pod && aw.ReplicaSetUID == bw.ReplicaSetUID && aw.WorkloadDigest == bw.WorkloadDigest
	}
	return same(p.Sender, other.Sender, p.SenderWorkload, other.SenderWorkload) && same(p.Holder, other.Holder, p.HolderWorkload, other.HolderWorkload)
}
