package presentation

// LocalClusterName names the hub's own cluster in mode=combined. Joined
// clusters use their Helm `clusters[].name` (ADR-335 D4).
const LocalClusterName = "local"

// ClusterNames maps the configured cluster names to their IDs and back.
// Public inputs name clusters; IDs stay provenance.
type ClusterNames struct {
	ids, names map[string]string
}

// NewClusterNames takes name→ID pairs; a duplicate name or ID keeps the first.
func NewClusterNames(byName map[string]string) ClusterNames {
	c := ClusterNames{ids: map[string]string{}, names: map[string]string{}}
	for name, id := range byName {
		if _, dup := c.names[id]; dup || name == "" || id == "" {
			continue
		}
		c.ids[name], c.names[id] = id, name
	}
	return c
}

// ID returns the cluster ID of a configured name.
func (c ClusterNames) ID(name string) (string, bool) {
	id, ok := c.ids[name]
	return id, ok
}

// Name returns the configured name of a cluster ID.
func (c ClusterNames) Name(id string) (string, bool) {
	name, ok := c.names[id]
	return name, ok
}
