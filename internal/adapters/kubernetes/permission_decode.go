package kubernetes

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"time"

	wire "asservat.local/asservat/api/v1alpha1"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"k8s.io/apimachinery/pkg/util/validation"
)

//go:embed permission-schemas/*.json
var permissionSchemas embed.FS

type permissionLoader struct{}

func (permissionLoader) Load(string) (any, error) { return nil, value.ErrInvalid }

type permissionValidator struct {
	bindingSchema, clusterBindingSchema, sourceSchema, identitySchema, retentionSchema, browserSchema *jsonschema.Schema
	// clusters maps cluster names to IDs (ADR-335 D4): the hub's own
	// cluster is LocalClusterName, joined clusters their values name.
	clusters map[string]string
}

// LocalClusterName names the hub's own cluster in PermissionSources and
// ClusterAccessBindings (as Rancher names the cluster it runs in).
const LocalClusterName = "local"

func newPermissionValidator() (*permissionValidator, error) {
	c := jsonschema.NewCompiler()
	c.UseLoader(permissionLoader{})
	c.AssertFormat()
	files, err := permissionSchemas.ReadDir("permission-schemas")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	for _, f := range files {
		b, err := permissionSchemas.ReadFile("permission-schemas/" + f.Name())
		if err != nil {
			return nil, value.ErrUnavailable
		}
		var v map[string]any
		if json.Unmarshal(b, &v) != nil {
			return nil, value.ErrUnavailable
		}
		id, ok := v["$id"].(string)
		if !ok || c.AddResource(id, v) != nil {
			return nil, value.ErrUnavailable
		}
	}
	b, err := c.Compile("https://asservat.io/spec/v1/access-binding.schema.json#/properties/spec")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	cb, err := c.Compile("https://asservat.io/spec/v1/cluster-access-binding.schema.json#/properties/spec")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	s, err := c.Compile("https://asservat.io/spec/v1/permission-source.schema.json#/properties/spec")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	i, err := c.Compile("https://asservat.io/spec/v1/identity-settings.schema.json")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	r, err := c.Compile("https://asservat.io/spec/v1/retention-policy.schema.json#/properties/spec")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	browser, err := c.Compile("https://asservat.io/spec/v1/browser-settings.schema.json")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &permissionValidator{bindingSchema: b, clusterBindingSchema: cb, sourceSchema: s, identitySchema: i, retentionSchema: r, browserSchema: browser}, nil
}

// Bound syntax before allocation/schema evaluation; reject duplicate keys,
// invalid UTF-8, trailing JSON and excessive depth. No source content in errors.
func permissionJSON(b []byte, maxBytes, maxTokens int) error {
	if len(b) == 0 || len(b) > maxBytes {
		return value.ErrLimit
	}
	d := jsontext.NewDecoder(bytes.NewReader(b))
	for tokens := 0; ; tokens++ {
		token, err := d.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return value.ErrUnavailable
		}
		if tokens >= maxTokens || d.StackDepth() > 32 {
			return value.ErrLimit
		}
		if token.Kind() == '0' {
			if len(token.String()) > 20 {
				return value.ErrLimit
			}
			if _, err := strconv.ParseInt(token.String(), 10, 64); err != nil {
				return value.ErrUnavailable
			}
		}
	}
	if !json.Valid(b) {
		return value.ErrUnavailable
	}
	return nil
}

func decodePermissionSpec(b []byte, s *jsonschema.Schema, out any) (artifact.Digest, error) {
	if err := permissionJSON(b, 64<<10, 16384); err != nil {
		return artifact.Digest{}, err
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil || s.Validate(v) != nil {
		return artifact.Digest{}, value.ErrUnavailable
	}
	if json.Unmarshal(b, out) != nil {
		return artifact.Digest{}, value.ErrUnavailable
	}
	canonical := jsontext.Value(bytes.Clone(b))
	if canonical.Canonicalize() != nil {
		return artifact.Digest{}, value.ErrUnavailable
	}
	return artifact.Digest(sha256.Sum256(canonical)), nil
}

type permissionObject struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   json.RawMessage `json:"metadata"`
	Spec       json.RawMessage `json:"spec"`
}
type permissionMetadata struct {
	Name, Namespace, UID, RV string
	Generation               int64
	Deleting                 bool
	Labels, Annotations      map[string]string
	// Created is metadata.creationTimestamp (zero when absent); it orders a
	// binding against its namespace's incarnation (ADR-329).
	Created time.Time
}

// Exact map keys avoid encoding/json's case-insensitive field matching for
// authority identity. Extra Kubernetes fields/status may exist but are ignored.
func objectEnvelope(b []byte) (permissionObject, error) {
	var fields map[string]json.RawMessage
	var out permissionObject
	if json.Unmarshal(b, &fields) != nil {
		return out, value.ErrUnavailable
	}
	if json.Unmarshal(fields["apiVersion"], &out.APIVersion) != nil || json.Unmarshal(fields["kind"], &out.Kind) != nil {
		return out, value.ErrUnavailable
	}
	out.Metadata, out.Spec = fields["metadata"], fields["spec"]
	return out, nil
}

// decodeObjectMetadata decodes a custom object's metadata; a cluster-scoped
// object (namespaced false) has no namespace.
func decodeObjectMetadata(b []byte, namespaced bool) (permissionMetadata, error) {
	return decodeMetadataOf(b, false, namespaced)
}

func decodeMetadata(b []byte, namespace bool) (permissionMetadata, error) {
	return decodeMetadataOf(b, namespace, true)
}

func decodeMetadataOf(b []byte, namespace, namespaced bool) (permissionMetadata, error) {
	var fields map[string]json.RawMessage
	var out permissionMetadata
	if json.Unmarshal(b, &fields) != nil {
		return out, value.ErrUnavailable
	}
	for key, dst := range map[string]*string{"name": &out.Name, "uid": &out.UID, "resourceVersion": &out.RV} {
		if json.Unmarshal(fields[key], dst) != nil || !identity.Text(*dst, 256) {
			return out, value.ErrUnavailable
		}
	}
	if !identity.Text(out.UID, 64) || !identity.Text(out.RV, 128) || len(validation.IsDNS1123Subdomain(out.Name)) != 0 {
		return out, value.ErrUnavailable
	}
	if !namespace {
		if namespaced && (json.Unmarshal(fields["namespace"], &out.Namespace) != nil || len(validation.IsDNS1123Label(out.Namespace)) != 0) || json.Unmarshal(fields["generation"], &out.Generation) != nil || out.Generation < 1 {
			return out, value.ErrUnavailable
		}
	} else {
		if len(validation.IsDNS1123Label(out.Name)) != 0 {
			return out, value.ErrUnavailable
		}
		for key, dst := range map[string]*map[string]string{"labels": &out.Labels, "annotations": &out.Annotations} {
			if b, ok := fields[key]; ok && json.Unmarshal(b, dst) != nil {
				return out, value.ErrUnavailable
			}
		}
	}
	if raw, exists := fields["creationTimestamp"]; exists && string(raw) != "null" {
		if json.Unmarshal(raw, &out.Created) != nil {
			return out, value.ErrUnavailable
		}
	}
	if raw, exists := fields["deletionTimestamp"]; exists && string(raw) != "null" {
		var stamp time.Time
		if json.Unmarshal(raw, &stamp) != nil || stamp.IsZero() {
			return out, value.ErrUnavailable
		}
		out.Deleting = true
	}
	return out, nil
}

func issuerValid(s string) bool {
	u, err := url.Parse(s)
	return err == nil && identity.Text(s, 2048) && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
func namespaceRefValid(n value.NamespaceRef) bool {
	return len(validation.IsDNS1123Label(n.Name)) == 0 && identity.Text(n.UID, 64)
}
func selectorValid(labels map[string]string) bool {
	for k, v := range labels {
		if len(validation.IsQualifiedName(k)) != 0 || len(validation.IsValidLabelValue(v)) != 0 {
			return false
		}
	}
	return true
}

func (v *permissionValidator) binding(object permissionObject, ref value.Resource) (value.Binding, error) {
	var spec wire.AccessBindingSpec
	digest, err := decodePermissionSpec(object.Spec, v.bindingSchema, &spec)
	if err != nil {
		return value.Binding{}, err
	}
	ref.SpecDigest = digest
	// ADR-329: the binding grants within its own namespace of the observed
	// cluster. A proposed spec (preview) has no placement yet; its caller
	// supplies the scope.
	b := value.Binding{Resource: ref, Effect: spec.Effect, Roles: spec.Roles, Scope: value.Scope{ClusterID: ref.ClusterID, Namespace: value.NamespaceRef{Name: ref.Namespace, UID: ref.NamespaceUID}}}
	if ref.ClusterID != "" && (!authorization.UUID(b.Scope.ClusterID) || !namespaceRefValid(b.Scope.Namespace)) {
		return value.Binding{}, value.ErrUnavailable
	}
	if b.Subjects, err = subjects(spec.Subjects); err != nil {
		return value.Binding{}, err
	}
	seen := map[string]bool{}
	for _, w := range spec.Workloads {
		ref := value.WorkloadRef{Kind: w.Kind, Name: w.Name, UID: w.UID}
		if len(validation.IsDNS1123Subdomain(w.Name)) != 0 || w.UID != "" && !identity.Text(w.UID, 64) || seen[w.Kind+"/"+w.Name] {
			return value.Binding{}, value.ErrUnavailable
		}
		seen[w.Kind+"/"+w.Name] = true
		b.Scope.Workloads = append(b.Scope.Workloads, ref)
	}
	if b.NotAfter, err = notAfter(spec.NotAfter); err != nil {
		return value.Binding{}, err
	}
	if spec.Automation != nil {
		a := spec.Automation
		b.Automation = &authorization.AutomationEnvelope{AllowedActions: a.AllowedActions, MaxLifetimeSeconds: a.MaxLifetimeSeconds, MaxExecutions: a.MaxExecutions, MaxBytes: a.MaxBytes, MaxObservedBytes: a.MaxObservedBytes, MaxObservedEvents: a.MaxObservedEvents}
		if !b.Automation.Valid() {
			return value.Binding{}, value.ErrUnavailable
		}
	}
	return b, nil
}

// subjects decodes authored subjects; an omitted issuer stays empty and is
// the installation's issuer (ADR-335 D4).
func subjects(in []wire.Subject) ([]value.Subject, error) {
	var out []value.Subject
	for _, s := range in {
		if s.Issuer != "" && !issuerValid(s.Issuer) || !identity.Text(s.ID, 256) {
			return nil, value.ErrUnavailable
		}
		out = append(out, value.Subject{Kind: s.Kind, Issuer: s.Issuer, ID: s.ID})
	}
	return out, nil
}

func notAfter(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, value.ErrUnavailable
	}
	return t, nil
}

// clusterBindings decodes one ClusterAccessBinding of the hub cluster into
// one binding per cluster it covers, each over AllNamespaces narrowed by its
// namespaceSelector (ADR-335 D14). Omitted clusters are the binding's own
// cluster; "*" is every known cluster. A spec that fails validation becomes
// one invalid binding that grants and denies nothing.
func (v *permissionValidator) clusterBindings(object permissionObject, ref value.Resource) []value.Binding {
	invalid := func() []value.Binding {
		ref.SpecDigest = artifact.Digest(sha256.Sum256(object.Spec))
		return []value.Binding{{Resource: ref, Invalid: true, Scope: value.Scope{ClusterID: ref.ClusterID, Namespace: value.AllNamespaces}}}
	}
	var spec wire.ClusterAccessBindingSpec
	digest, err := decodePermissionSpec(object.Spec, v.clusterBindingSchema, &spec)
	if err != nil {
		return invalid()
	}
	ref.SpecDigest = digest
	subjects, err := subjects(spec.Subjects)
	if err != nil {
		return invalid()
	}
	expires, err := notAfter(spec.NotAfter)
	if err != nil {
		return invalid()
	}
	var selector map[string]string
	if spec.NamespaceSelector != nil && len(spec.NamespaceSelector.MatchLabels) > 0 {
		selector = spec.NamespaceSelector.MatchLabels
	}
	if !selectorValid(selector) {
		return invalid()
	}
	clusters := []string{ref.ClusterID}
	if len(spec.Clusters) > 0 {
		clusters = nil
		for _, name := range spec.Clusters {
			if name == "*" {
				clusters = slices.AppendSeq(clusters, maps.Values(v.clusters))
			} else if id, ok := v.clusters[name]; ok {
				clusters = append(clusters, id)
			}
		}
	}
	slices.Sort(clusters)
	var out []value.Binding
	for _, cluster := range slices.Compact(clusters) {
		r := ref
		r.ClusterID = cluster
		out = append(out, value.Binding{Resource: r, Effect: spec.Effect, Subjects: subjects, Roles: spec.Roles, NotAfter: expires, NamespaceSelector: selector, Scope: value.Scope{ClusterID: cluster, Namespace: value.AllNamespaces}})
	}
	return out
}

// observedBinding decodes an observed binding. A spec that fails validation
// grants and denies nothing: any namespace writer can store one (ADR-329), so
// it must not stop the cluster's permission stream. Neither does a binding
// that could not be placed in its namespace (empty NamespaceUID). It keeps its identity
// with the digest of its raw spec, so the journal still sees each change.
func (v *permissionValidator) observedBinding(object permissionObject, ref value.Resource) value.Binding {
	b, err := v.binding(object, ref)
	if err == nil && ref.NamespaceUID != "" {
		return b
	}
	ref.SpecDigest = artifact.Digest(sha256.Sum256(object.Spec))
	return value.Binding{Resource: ref, Invalid: true, Scope: value.Scope{ClusterID: ref.ClusterID, Namespace: value.NamespaceRef{Name: ref.Namespace, UID: ref.NamespaceUID}}}
}

// AccessBindingSpecDecoder decodes a proposed AccessBinding spec with the same
// embedded schema and checks as observed bindings (ADR-237 impact preview).
// The returned binding carries the canonical spec digest; it is never an
// observed or accepted object.
type AccessBindingSpecDecoder struct{ validator *permissionValidator }

func NewAccessBindingSpecDecoder() (*AccessBindingSpecDecoder, error) {
	v, err := newPermissionValidator()
	if err != nil {
		return nil, err
	}
	return &AccessBindingSpecDecoder{v}, nil
}

func (d *AccessBindingSpecDecoder) DecodeAccessBindingSpec(spec []byte) (value.Binding, error) {
	if d == nil || d.validator == nil {
		return value.Binding{}, value.ErrUnavailable
	}
	b, err := d.validator.binding(permissionObject{Spec: spec}, value.Resource{Kind: "AccessBinding"})
	if err != nil {
		return value.Binding{}, value.ErrInvalid
	}
	return b, nil
}

// DecodePermissionSourceSpec decodes a proposed PermissionSource spec with the
// observed source schema and checks (ADR-237).
func (d *AccessBindingSpecDecoder) DecodePermissionSourceSpec(spec []byte) (value.Source, error) {
	if d == nil || d.validator == nil {
		return value.Source{}, value.ErrUnavailable
	}
	s, err := d.validator.source(permissionObject{Spec: spec}, value.Resource{Kind: "PermissionSource"})
	if err != nil {
		return value.Source{}, value.ErrInvalid
	}
	return s, nil
}

func (v *permissionValidator) source(object permissionObject, ref value.Resource) (value.Source, error) {
	var spec wire.PermissionSourceSpec
	digest, err := decodePermissionSpec(object.Spec, v.sourceSchema, &spec)
	if err != nil {
		return value.Source{}, err
	}
	ref.SpecDigest = digest
	// An unknown cluster name leaves ClusterID empty: the source grants
	// nothing until that cluster is registered.
	s := value.Source{Resource: ref, Enabled: spec.Enabled, Type: spec.Type, ClusterID: v.clusters[spec.Cluster], Role: spec.Role, ExcludedNamespaces: spec.ExcludedNamespaces}
	if spec.NamespaceSelector != nil {
		s.NamespaceSelector = spec.NamespaceSelector.MatchLabels
	}
	if !selectorValid(s.NamespaceSelector) {
		return value.Source{}, value.ErrUnavailable
	}
	for _, n := range s.ExcludedNamespaces {
		if len(validation.IsDNS1123Label(n)) != 0 {
			return value.Source{}, value.ErrUnavailable
		}
	}
	if spec.Protection != nil {
		s.Protection = value.Protection{Mode: spec.Protection.Mode, ReviewRef: spec.Protection.ReviewRef, GuardRef: spec.Protection.GuardRef}
	}
	if m := spec.MetadataMapping; m != nil {
		if len(validation.IsQualifiedName(m.Key)) != 0 || m.Issuer != "" && !issuerValid(m.Issuer) {
			return value.Source{}, value.ErrUnavailable
		}
		for key := range m.Values {
			if !identity.Text(key, 256) {
				return value.Source{}, value.ErrUnavailable
			}
		}
		s.Mapping = value.Mapping{Field: m.Field, Key: m.Key, Mode: m.Mode, Issuer: m.Issuer, Values: m.Values}
	}
	if w := spec.WorkloadSelector; w != nil {
		if !selectorValid(w.MatchLabels) {
			return value.Source{}, value.ErrUnavailable
		}
		s.WorkloadSelector = w.MatchLabels
	}
	// ADR-245: the decision-time source fields; the reference names a local
	// record of the target cluster's connector, never an address or plugin.
	if spec.IdentityMappingRef != "" && len(validation.IsDNS1123Label(spec.IdentityMappingRef)) != 0 {
		return value.Source{}, value.ErrUnavailable
	}
	s.IdentityMappingRef = spec.IdentityMappingRef
	if p := spec.AdmissionParity; p != nil {
		s.AdmissionParity = value.AdmissionParity{Mode: p.Mode, ReviewRef: p.ReviewRef, AdapterRef: p.AdapterRef}
	}
	if r := spec.AccessReview; r != nil {
		s.AccessReviewCheck = r.Check
	}
	return s, nil
}
