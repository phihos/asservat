package contracts

// These fixed v2 endpoints are selected by original installed configuration.
// The metadata payloads, frame kinds and limits remain unchanged. A request or
// unsupported frame cannot negotiate an alternate purpose or fall back to v1.
const (
	ClusterObservationOperationExchangePath  = "/internal/cluster-observation/exchange/v2"
	ClusterObservationOperationExchangeMedia = "application/vnd.asservat.cluster-observation-exchange.v2"
)
