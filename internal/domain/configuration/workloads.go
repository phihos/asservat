package configuration

import (
	"cmp"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// MaxObservedWorkloads bounds one workload journal (ADR-247); more selected
// workloads make it unavailable, never partial.
const MaxObservedWorkloads = 4096

// WorkloadKinds are the controllers a workloadMetadata source reads.
var WorkloadKinds = []string{"Deployment", "StatefulSet"}

// WorkloadSelection is what one connector workload journal follows: the
// Deployments and StatefulSets of a cluster matching Selector (server-side
// label selector), reduced to Keys.
type WorkloadSelection struct {
	Selector map[string]string
	Keys     NamespaceKeys
}

func (s WorkloadSelection) Valid() bool {
	if len(s.Selector) == 0 || len(s.Selector) > 16 || !s.Keys.Valid() || len(s.Keys.Labels)+len(s.Keys.Annotations) == 0 {
		return false
	}
	for k, v := range s.Selector {
		if !identity.Text(k, 317) || len(v) > 63 || !slices.Contains(s.Keys.Labels, k) {
			return false
		}
	}
	return true
}

func (s WorkloadSelection) Equal(o WorkloadSelection) bool {
	return SelectionKey(s) == SelectionKey(o) && len(s.Selector) == len(o.Selector) && slices.Equal(s.Keys.Labels, o.Keys.Labels) && slices.Equal(s.Keys.Annotations, o.Keys.Annotations)
}

// ObservedWorkload is one Deployment or StatefulSet reduced to the observed
// keys, like ObservedNamespace (value digests only). Namespace is resolved
// by the connector to its current UID.
type ObservedWorkload struct {
	Kind      string
	Namespace NamespaceRef
	ObservedNamespace
}

func (w ObservedWorkload) Ref() WorkloadRef {
	return WorkloadRef{Kind: w.Kind, Name: w.Name, UID: w.UID}
}

func (w ObservedWorkload) Valid(k NamespaceKeys, live bool) bool {
	return slices.Contains(WorkloadKinds, w.Kind) && identity.Text(w.Namespace.Name, 63) && identity.Text(w.Namespace.UID, 64) && w.ObservedNamespace.Valid(k, live)
}

// WorkloadList is one complete journal state of a selection.
type WorkloadList struct {
	ClusterID, Journal string
	Selection          WorkloadSelection
	ObservedAt         time.Time
	Workloads          []ObservedWorkload
}

// WorkloadObservation is the accepted, minimized workload observation of a
// permission batch: selection, workload names, UIDs and value digests.
type WorkloadObservation struct {
	ClusterID string
	Selection WorkloadSelection
	Workloads []ObservedWorkload
}

func (o WorkloadObservation) Valid() bool {
	if !authorization.UUID(o.ClusterID) || !o.Selection.Valid() || len(o.Workloads) > MaxObservedWorkloads {
		return false
	}
	for i, w := range o.Workloads {
		if !w.Valid(o.Selection.Keys, false) || i > 0 && o.Workloads[i-1].UID >= w.UID {
			return false
		}
	}
	return true
}

// WorkloadObservationsValid bounds a batch's workload observations to 32 in
// ascending (cluster, selection) order without duplicates.
func WorkloadObservationsValid(v []WorkloadObservation) bool {
	if len(v) > 32 {
		return false
	}
	for i, o := range v {
		if !o.Valid() || i > 0 && compareWorkloadObservation(v[i-1], o) >= 0 {
			return false
		}
	}
	return true
}

func compareWorkloadObservation(a, b WorkloadObservation) int {
	if c := cmp.Compare(a.ClusterID, b.ClusterID); c != 0 {
		return c
	}
	return cmp.Compare(SelectionKey(a.Selection), SelectionKey(b.Selection))
}

// SelectionKey is a stable text form of a selection.
func SelectionKey(s WorkloadSelection) string {
	out := ""
	keys := make([]string, 0, len(s.Selector))
	for k := range s.Selector {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		out += k + "=" + s.Selector[k] + ","
	}
	out += "|"
	for _, k := range s.Keys.Labels {
		out += k + ","
	}
	out += "|"
	for _, k := range s.Keys.Annotations {
		out += k + ","
	}
	return out
}

// WorkloadGrant is one workload a source currently grants to Subjects.
type WorkloadGrant struct {
	Namespace       NamespaceRef
	Workload        WorkloadRef
	ResourceVersion string
	Subjects        []Subject
}
