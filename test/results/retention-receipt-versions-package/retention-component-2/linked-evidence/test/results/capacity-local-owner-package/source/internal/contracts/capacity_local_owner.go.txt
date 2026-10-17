package contracts

// CapacityLocalOwner is derived from the original protected owner source and
// positively launched identity projection. It carries only public installation
// inputs. The same capacity manifest/public-digest/Secret-receipt checks cover
// this complete value; it cannot select a URL, credential or alternate issuer.
// Pool is the exact original owner-pool.json wire, including its public roots.
type CapacityLocalOwner struct {
	Source     WorkerObjectReference `json:"source"`
	Pool       OwnerConfiguration    `json:"pool"`
	Deployment OwnerDeployment       `json:"deployment"`
}
