package fleet

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
