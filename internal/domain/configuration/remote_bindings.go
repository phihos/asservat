package configuration

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// RemoteBindings is the latest complete AccessBinding list of one workload
// cluster joined with mode: cluster, delivered by its connector (ADR-329).
// The hub sets ClusterID from the connector's authenticated cluster
// credential, never from the payload, and ObservedAt from its own clock when
// it admitted the delivering conversation, before the connector's LIST.
type RemoteBindings struct {
	ClusterID  string
	ObservedAt time.Time
	Digest     artifact.Digest // stored delivery digest returned by the hub reader
	Bindings   []Binding
}

// BindingInCluster reports whether b is an AccessBinding of cluster whose
// scope is exactly its own namespace (ADR-329).
func BindingInCluster(b Binding, cluster string) bool {
	r := b.Resource
	return r.ClusterID == cluster && identity.Text(r.Namespace, 63) && identity.Text(r.NamespaceUID, 64) && b.Scope.ClusterID == cluster && b.Scope.Namespace == NamespaceRef{Name: r.Namespace, UID: r.NamespaceUID} &&
		r.Kind == "AccessBinding" && identity.Text(r.Name, 253) && identity.Text(r.UID, 64) && identity.Text(r.ResourceVersion, 128) && r.Generation > 0 && r.Generation <= 2147483647 && r.SpecDigest != (artifact.Digest{})
}

// Valid checks the identity of a delivery: bindings with unique UIDs and
// names, each in its own namespace of the cluster.
func (d RemoteBindings) Valid() bool {
	if !authorization.UUID(d.ClusterID) || d.ObservedAt.IsZero() {
		return false
	}
	uids, names := map[string]bool{}, map[string]bool{}
	for _, b := range d.Bindings {
		key := b.Resource.Namespace + "/" + b.Resource.Name
		if !BindingInCluster(b, d.ClusterID) || uids[b.Resource.UID] || names[key] {
			return false
		}
		uids[b.Resource.UID], names[key] = true, true
	}
	return true
}
