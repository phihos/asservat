package configuration

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// NamespaceObserver lists and watches one cluster's namespaces, reduced to
// the requested keys (ADR-242). It is an observation port: no result is
// accepted configuration or a permission grant by itself.
type NamespaceObserver interface {
	ListNamespaces(context.Context, value.NamespaceKeys) (value.NamespaceList, error)
	// WatchNamespaces resumes from an opaque cursor. io.EOF is a clean end
	// of a finite session; value.ErrChanged means the history is gone and a
	// new LIST is needed.
	WatchNamespaces(context.Context, string, value.NamespaceKeys) (NamespaceWatch, error)
}
type NamespaceWatch interface {
	Next(context.Context) (value.NamespaceEvent, error)
	Close()
}

// ValueDigest is the lower-case hex SHA-256 recorded for an observed metadata
// value; "" for a value that can never map.
func ValueDigest(v string) string {
	if !identity.Text(v, 256) {
		return ""
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// SourceKeys returns the metadata keys of the namespaceMetadata sources of
// cluster: their selector labels and mapping keys, sorted and distinct. All
// such sources count, enabled or not, so that a staged source can be
// previewed against the same observation.
func SourceKeys(sources []value.Source, cluster string) value.NamespaceKeys {
	var k value.NamespaceKeys
	for _, s := range sources {
		if s.Type != "namespaceMetadata" || s.ClusterID != cluster {
			continue
		}
		for key := range s.NamespaceSelector {
			k.Labels = append(k.Labels, key)
		}
		switch s.Mapping.Field {
		case "label":
			k.Labels = append(k.Labels, s.Mapping.Key)
		case "annotation":
			k.Annotations = append(k.Annotations, s.Mapping.Key)
		}
	}
	slices.Sort(k.Labels)
	slices.Sort(k.Annotations)
	k.Labels, k.Annotations = slices.Compact(k.Labels), slices.Compact(k.Annotations)
	return k
}

func validRole(role string) bool {
	return role == "workload-maintainer" || role == "evidence-reader" || role == "evidence-owner" || role == "action-approver"
}

// NamespaceGrants evaluates one PermissionSource against a namespace
// observation of cluster observed ("" when unknown) exactly as the
// reconciler accepts it (REQ-PER-003, ADR-242). A namespaceMetadata source
// maps the configured label or annotation through an explicit value map.
// Values select only the source's fixed groups, never roles, issuers or other
// settings; a missing, unknown, malformed or oversized value grants nothing.
// The protection mode is the administrator's statement (administratorManaged)
// or the Helm-rendered admission policy (admissionEnforced); Asservat does
// not prove either at runtime. A namespace that is terminating, excluded or
// outside the selector is never granted.
func NamespaceGrants(s value.Source, observed string, o *value.NamespaceObservation) ([]value.NamespaceGrant, string) {
	if !s.Enabled || s.Resource.Deleting {
		return nil, value.SourceDisabled
	}
	m := s.Mapping
	if s.Type != "namespaceMetadata" || m.Mode != "valueMap" || len(m.Values) == 0 || s.Protection.Mode != "administratorManaged" && s.Protection.Mode != "admissionEnforced" ||
		observed != "" && s.ClusterID != observed || !authorization.UUID(s.ClusterID) || !validRole(s.Role) {
		return nil, value.SourceUnsupported
	}
	if o == nil {
		return nil, value.MetadataUnavailable
	}
	if o.ClusterID != s.ClusterID {
		return nil, value.SourceUnsupported
	}
	keys := SourceKeys([]value.Source{s}, s.ClusterID)
	for _, k := range keys.Labels {
		if !slices.Contains(o.Keys.Labels, k) {
			return nil, value.MetadataNotObserved
		}
	}
	for _, k := range keys.Annotations {
		if !slices.Contains(o.Keys.Annotations, k) {
			return nil, value.MetadataNotObserved
		}
	}
	groups := mappingGroups(m)
	selector := map[string]string{}
	for k, v := range s.NamespaceSelector {
		selector[k] = ValueDigest(v)
	}
	var out []value.NamespaceGrant
	for _, n := range o.Namespaces {
		if n.Deleting || slices.Contains(s.ExcludedNamespaces, n.Name) {
			continue
		}
		matched := true
		for k, d := range selector {
			if v, ok := n.Labels[k]; !ok || d == "" || v != d {
				matched = false
				break
			}
		}
		values := n.Annotations
		if m.Field == "label" {
			values = n.Labels
		}
		v, ok := values[m.Key]
		if !matched || !ok || v == "" || len(groups[v]) == 0 {
			continue
		}
		out = append(out, value.NamespaceGrant{Namespace: value.NamespaceRef{Name: n.Name, UID: n.UID}, ResourceVersion: n.ResourceVersion, Subjects: slices.Clone(groups[v])})
	}
	return out, ""
}

// SourceBasis is the accepted basis of one grant. The source object and the
// namespace's resourceVersion (ObservationVersion) are both provenance; the
// scope is the whole namespace.
func SourceBasis(s value.Source, g value.NamespaceGrant, continuous bool) value.PermissionBasis {
	b := value.PermissionBasis{Resource: s.Resource, Scope: value.Scope{ClusterID: s.ClusterID, Namespace: g.Namespace}, Effect: "Allow", Subjects: slices.Clone(g.Subjects), Roles: []string{s.Role}, ObservationVersion: g.ResourceVersion, Continuous: continuous}
	b.ScopeDigest = PermissionScopeDigest(b)
	return b
}

// mappingGroups maps value digests to the source's groups. An empty issuer
// is the installation's issuer (filled in when the batch is prepared).
func mappingGroups(m value.Mapping) map[string][]value.Subject {
	groups := map[string][]value.Subject{}
	for v, ids := range m.Values {
		d := ValueDigest(v)
		if d == "" || len(ids) == 0 {
			continue
		}
		for _, id := range ids {
			if identity.Text(id, 256) && !slices.Contains(groups[d], value.Subject{Kind: "Group", Issuer: m.Issuer, ID: id}) {
				groups[d] = append(groups[d], value.Subject{Kind: "Group", Issuer: m.Issuer, ID: id})
			}
		}
		slices.SortFunc(groups[d], func(a, b value.Subject) int { return cmp.Compare(a.ID, b.ID) })
	}
	return groups
}
