package contracts

func localRoutingValues() (ClusterObservationLocalLocatorQuery, ClusterObservationLocalClaim) {
	q, c := operationRoutingValues()
	return ClusterObservationLocalLocatorQuery{PodUID: q.RootID, Query: q}, ClusterObservationLocalClaim{Format: ClusterObservationLocalClaimFormat, PodUID: q.RootID, Request: c.Request, Locator: c.Locator}
}
