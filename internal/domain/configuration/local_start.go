package configuration

// LocalStartAdministration is protected installation configuration. Separate
// capacity/execution Kubernetes identities prevent the consumer minting Ready
// reservations. Initial cleanup deliberately has no delete permission.
type LocalStartAdministration struct {
	Name                        string
	ControlNamespace            NamespaceRef
	CapacityUser, ExecutionUser string
}
