package kubernetes

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"net/url"
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

type permissionValidator struct{ bindingSchema, sourceSchema, identitySchema, workTrustSchema, fleetSchema, retentionSchema, retentionTopologySchema, browserSchema, submissionSchema, witnessSchema *jsonschema.Schema }

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
	s, err := c.Compile("https://asservat.io/spec/v1/permission-source.schema.json#/properties/spec")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	i, err := c.Compile("https://asservat.io/spec/v1/identity-settings.schema.json")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	w, err := c.Compile("https://asservat.io/spec/v1/work-trust.schema.json")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	f, err := c.Compile("https://asservat.io/spec/v1/fleet-settings.schema.json")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	r, err := c.Compile("https://asservat.io/spec/v1/retention-policy.schema.json#/properties/spec")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	t, err := c.Compile("https://asservat.io/spec/v1/retention-topology.schema.json")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	browser, err := c.Compile("https://asservat.io/spec/v1/browser-settings.schema.json")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	submission, err := c.Compile("https://asservat.io/spec/v1/submission-trust.schema.json")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	witness, err := c.Compile("https://asservat.io/spec/v1/installation-witness.schema.json")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &permissionValidator{b, s, i, w, f, r, t, browser, submission, witness}, nil
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

func decodeMetadata(b []byte, namespace bool) (permissionMetadata, error) {
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
		if json.Unmarshal(fields["namespace"], &out.Namespace) != nil || len(validation.IsDNS1123Label(out.Namespace)) != 0 || json.Unmarshal(fields["generation"], &out.Generation) != nil || out.Generation < 1 {
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
	b := value.Binding{Resource: ref, Effect: spec.Effect, Roles: spec.Roles, Scope: value.Scope{ClusterID: spec.Scope.ClusterID, Namespace: value.NamespaceRef{Name: spec.Scope.NamespaceRef.Name, UID: spec.Scope.NamespaceRef.UID}}}
	if !authorization.UUID(b.Scope.ClusterID) || !namespaceRefValid(b.Scope.Namespace) {
		return value.Binding{}, value.ErrUnavailable
	}
	for _, s := range spec.Subjects {
		if !issuerValid(s.Issuer) || !identity.Text(s.ID, 256) {
			return value.Binding{}, value.ErrUnavailable
		}
		b.Subjects = append(b.Subjects, value.Subject{Kind: s.Kind, Issuer: s.Issuer, ID: s.ID})
	}
	seen := map[string]bool{}
	for _, w := range spec.Scope.Workloads {
		if len(validation.IsDNS1123Subdomain(w.Name)) != 0 || !identity.Text(w.UID, 64) || seen[w.UID] {
			return value.Binding{}, value.ErrUnavailable
		}
		seen[w.UID] = true
		b.Scope.Workloads = append(b.Scope.Workloads, value.WorkloadRef{Kind: w.Kind, Name: w.Name, UID: w.UID})
	}
	if spec.NotAfter != "" {
		b.NotAfter, err = time.Parse(time.RFC3339Nano, spec.NotAfter)
		if err != nil {
			return value.Binding{}, value.ErrUnavailable
		}
	}
	if spec.Automation != nil {
		a := spec.Automation
		b.Automation = &authorization.AutomationEnvelope{AllowedActions: a.AllowedActions, MaxLifetimeSeconds: a.MaxLifetimeSeconds, MaxExecutions: a.MaxExecutions, MaxBytes: a.MaxBytes, MaxObservedBytes: a.MaxObservedBytes}
		if !b.Automation.Valid() {
			return value.Binding{}, value.ErrUnavailable
		}
	}
	return b, nil
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
	s := value.Source{Resource: ref, Enabled: spec.Enabled, Type: spec.Type, ClusterID: spec.ClusterID, Role: spec.Role, NamespaceSelector: spec.NamespaceSelector.MatchLabels, ExcludedNamespaces: spec.ExcludedNamespaces, MaxDecisionAge: time.Duration(spec.MaxDecisionAgeSeconds) * time.Second, MaxNamespaces: spec.MaxNamespaces}
	if !authorization.UUID(s.ClusterID) || !selectorValid(s.NamespaceSelector) {
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
		if len(validation.IsQualifiedName(m.Key)) != 0 || !issuerValid(m.Issuer) {
			return value.Source{}, value.ErrUnavailable
		}
		for key, groups := range m.Values {
			if !identity.Text(key, 256) || !identity.Strings(groups, 16, 256) {
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
