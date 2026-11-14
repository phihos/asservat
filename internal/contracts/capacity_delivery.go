package contracts

// Bounds of one connector's capacity delivery (ADR-330): the namespaces of
// its cluster that carry a capacity selector key and their capacity
// workloads, metadata only.
const (
	CapacityDeliveryMaxBytes   = 2 << 20
	CapacityDeliveryNamespaces = 512
	CapacityDeliveryWorkloads  = 4096
)

// CapacityDelivery is a mode=cluster connector's capacity observation of its
// own cluster (ADR-330): every namespace carrying at least one of the
// offered capacity keys (Labels holds only those keys) with its
// Deployments, StatefulSets and unowned Pods. It names no cluster: the hub
// attributes it to the connector's authenticated cluster.
type CapacityDelivery struct {
	Namespaces []DeliveredCapacityNamespace `json:"namespaces"`
}

type DeliveredCapacityNamespace struct {
	Name            string                      `json:"name"`
	UID             string                      `json:"uid"`
	ResourceVersion string                      `json:"resourceVersion"`
	Labels          map[string]string           `json:"labels"`
	Workloads       []DeliveredCapacityWorkload `json:"workloads"`
}

type DeliveredCapacityWorkload struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
}
