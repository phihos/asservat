package contracts

// Original private worker may probe only the two fixed capacity CRDs without
// persisting. Independent capacity admission must still reject each dry-run.
type OwnerDeploymentCapacityProbe struct {
	ServiceAccount WorkerObjectReference `json:"serviceAccount"`
}
