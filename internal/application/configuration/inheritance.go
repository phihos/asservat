package configuration

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"

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

// NamespaceGrants evaluates a source without guard or directory evidence:
// guarded and group-ID sources are then unavailable (the impact preview).
func NamespaceGrants(s value.Source, observed string, o *value.NamespaceObservation) ([]value.NamespaceGrant, string) {
	return NamespaceGrantsWith(s, observed, o, value.SourceEvidence{})
}

// NamespaceGrantsWith evaluates one PermissionSource against a namespace
// observation of cluster observed ("" when unknown) exactly as the
// reconciler accepts it (REQ-PER-003, ADR-242, ADR-247). A namespaceMetadata
// source maps the configured label or annotation through an explicit value
// map or, in groupID mode, to the stable group ID it names when that ID is in
// the administrator-configured group directory of the source's issuer.
// Values select only the source's fixed issuer-scoped groups, never roles,
// issuers or other settings; a missing, unknown, malformed or oversized value
// grants nothing. administratorManaged protection rests on the
// administrator's attestation; admissionEnforced protection additionally
// needs a current proof that the guard named by guardRef protects every
// selector and mapping key. Without a current proof or directory the source
// is unavailable (kept, granting nothing). A namespace that is terminating,
// excluded or outside the selector is never granted.
func NamespaceGrantsWith(s value.Source, observed string, o *value.NamespaceObservation, ev value.SourceEvidence) ([]value.NamespaceGrant, string) {
	if !s.Enabled || s.Resource.Deleting {
		return nil, value.SourceDisabled
	}
	m := s.Mapping
	valueMap, groupID := m.Mode == "valueMap", m.Mode == "groupID"
	guarded := s.Protection.Mode == "admissionEnforced"
	if s.Type != "namespaceMetadata" || !valueMap && !groupID || s.Protection.Mode != "administratorManaged" && !guarded || !identity.Text(s.Protection.ReviewRef, 256) ||
		guarded && !identity.Text(s.Protection.GuardRef, 256) ||
		observed != "" && s.ClusterID != observed || !authorization.UUID(s.ClusterID) || !validRole(s.Role) || !identity.Text(m.Issuer, 2048) ||
		s.MaxNamespaces < 1 || s.MaxNamespaces > 1000 || valueMap && (len(m.Values) == 0 || len(m.Values) > 128) || groupID && len(m.Values) != 0 {
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
	if guarded {
		if reason := guardCovers(ev.Guard, s.Protection.GuardRef, s.ClusterID, keys, ev.Now); reason != "" {
			return nil, reason
		}
	}
	groups, reason := mappingGroups(m, ev)
	if reason != "" {
		return nil, reason
	}
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
	if len(out) > s.MaxNamespaces {
		return nil, value.SourceTooManyNamespaces
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

// mappingGroups maps value digests to the source's issuer-scoped groups:
// the explicit value map, or in groupID mode the configured directory's IDs.
func mappingGroups(m value.Mapping, ev value.SourceEvidence) (map[string][]value.Subject, string) {
	groups := map[string][]value.Subject{}
	if m.Mode == "groupID" {
		d := ev.Directory
		if !d.Current(ev.Now) || d.Issuer != m.Issuer {
			return nil, value.DirectoryUnavailable
		}
		for _, id := range d.Groups {
			if digest := ValueDigest(id); digest != "" && !strings.Contains(id, ",") {
				groups[digest] = []value.Subject{{Kind: "Group", Issuer: m.Issuer, ID: id}}
			}
		}
	}
	for v, ids := range m.Values {
		d := ValueDigest(v)
		if d == "" || len(ids) == 0 || !identity.Strings(ids, 16, 256) {
			continue
		}
		for _, id := range ids {
			groups[d] = append(groups[d], value.Subject{Kind: "Group", Issuer: m.Issuer, ID: id})
		}
		slices.SortFunc(groups[d], func(a, b value.Subject) int { return cmp.Compare(a.ID, b.ID) })
	}
	return groups, ""
}

// guardCovers requires a current proof of the named guard of cluster that
// protects every key.
func guardCovers(g *value.NamespaceGuardProof, name, cluster string, keys value.NamespaceKeys, now time.Time) string {
	if !g.Current(now) || g.ClusterID != cluster {
		return value.GuardUnavailable
	}
	if g.Name != name {
		return value.SourceUnsupported
	}
	for _, k := range keys.Labels {
		if !slices.Contains(g.LabelKeys, k) {
			return value.SourceUnsupported
		}
	}
	for _, k := range keys.Annotations {
		if !slices.Contains(g.AnnotationKeys, k) {
			return value.SourceUnsupported
		}
	}
	return ""
}
