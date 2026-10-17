package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"math"
	"strconv"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed policy-schemas/*.json
var policySchemas embed.FS

// PolicySourceClient observes one concrete source. Neither a matching source
// digest nor CRD status supplies signed acceptance, resolved scope or authority.
type PolicySourceClient struct {
	client                  *PermissionClient
	installation, name, uid string
	namespace               cfg.NamespaceRef
	schema                  *jsonschema.Schema
}

var _ app.PolicySourceReader = (*PolicySourceClient)(nil)

func NewPolicySourceClient(client *PermissionClient, installation string, namespace cfg.NamespaceRef, name, uid string) (*PolicySourceClient, error) {
	if client == nil || !authorization.UUID(installation) || !namespaceRefValid(namespace) || !installationRefValid(name, uid) {
		return nil, value.ErrInvalid
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(permissionLoader{})
	c.AssertFormat()
	files, e := policySchemas.ReadDir("policy-schemas")
	if e != nil {
		return nil, value.ErrUnavailable
	}
	for _, f := range files {
		b, e := policySchemas.ReadFile("policy-schemas/" + f.Name())
		if e != nil {
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
	schema, e := c.Compile("https://asservat.io/spec/v1/policy.schema.json#/properties/spec")
	if e != nil {
		return nil, value.ErrUnavailable
	}
	return &PolicySourceClient{client, installation, name, uid, namespace, schema}, nil
}

// Resource ratios legitimately contain fractions. Keep the stricter integer
// permission decoder unchanged; this bounded decoder permits finite portable
// JSON numbers and standard RFC 8785 canonicalization only.
func policyJSON(b []byte, maxBytes int) error {
	if len(b) == 0 || len(b) > maxBytes {
		return value.ErrInvalid
	}
	d := jsontext.NewDecoder(bytes.NewReader(b))
	for n := 0; ; n++ {
		token, e := d.ReadToken()
		if e == io.EOF {
			break
		}
		if e != nil || n >= 131072 || d.StackDepth() > 32 {
			return value.ErrInvalid
		}
		if token.Kind() == '0' {
			if len(token.String()) > 64 {
				return value.ErrInvalid
			}
			v, e := strconv.ParseFloat(token.String(), 64)
			if e != nil || math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 9007199254740991 {
				return value.ErrInvalid
			}
		}
	}
	if !json.Valid(b) {
		return value.ErrInvalid
	}
	return nil
}

func (c *PolicySourceClient) PolicySource(ctx context.Context) (value.PolicySource, error) {
	var zero value.PolicySource
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := c.client.now().UTC().Truncate(time.Microsecond)
	ns, e := c.client.namespace(ctx, c.namespace)
	if e != nil || ns.Deleting {
		return zero, value.ErrUnavailable
	}
	b, e := c.client.api.Get().AbsPath("/apis/asservat.io/v1alpha1/namespaces/" + c.namespace.Name + "/debugpolicies/" + c.name).MaxRetries(0).DoRaw(ctx)
	if e != nil || policyJSON(b, permissionPageBytes) != nil {
		return zero, value.ErrUnavailable
	}
	o, e := objectEnvelope(b)
	if e != nil || o.APIVersion != "asservat.io/v1alpha1" || o.Kind != "DebugPolicy" {
		return zero, value.ErrUnavailable
	}
	m, e := decodeMetadata(o.Metadata, false)
	if e != nil || m.Name != c.name || m.Namespace != c.namespace.Name || m.UID != c.uid || policyJSON(o.Spec, 64<<10) != nil {
		return zero, value.ErrUnavailable
	}
	spec, e := jsonschema.UnmarshalJSON(bytes.NewReader(o.Spec))
	if e != nil || c.schema.Validate(spec) != nil {
		return zero, value.ErrUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(o.Spec, &fields) != nil {
		return zero, value.ErrUnavailable
	}
	var target struct {
		Namespace string `json:"namespace"`
	}
	if json.Unmarshal(fields["target"], &target) != nil || target.Namespace != c.namespace.Name {
		return zero, value.ErrUnavailable
	}
	var suspended bool
	if raw, ok := fields["suspended"]; ok && json.Unmarshal(raw, &suspended) != nil {
		return zero, value.ErrUnavailable
	}
	full := jsontext.Value(bytes.Clone(o.Spec))
	if full.Canonicalize() != nil {
		return zero, value.ErrUnavailable
	}
	for _, excluded := range []string{"grantRef", "sharing", "resultAccess", "suspended", "reason", "idempotencyKey"} {
		delete(fields, excluded)
	}
	if _, exists := fields["recordingSaves"]; !exists {
		fields["recordingSaves"] = json.RawMessage(`{"enabled":false}`)
	}
	intent, e := json.Marshal(fields)
	if e != nil {
		return zero, value.ErrUnavailable
	}
	canonical := jsontext.Value(intent)
	if canonical.Canonicalize() != nil {
		return zero, value.ErrUnavailable
	}
	out := value.PolicySource{InstallationID: c.installation, ClusterID: c.client.clusterID, NamespaceUID: c.namespace.UID, Name: m.Name, Revision: identity.Revision{UID: m.UID, Generation: m.Generation, Digest: artifact.Digest(sha256.Sum256(full))}, ResourceVersion: m.RV, ObservedAt: started, FreshUntil: started.Add(5 * time.Second), CollectionDigest: artifact.Digest(sha256.Sum256(canonical)), Suspended: suspended, Deleted: m.Deleting}
	if c.client.current(ctx, started, 5*time.Second) != nil || !out.Valid(c.client.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
