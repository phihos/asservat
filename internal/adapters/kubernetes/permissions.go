package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

const (
	permissionPageBytes  = 2 << 20
	permissionTotalBytes = 8 << 20
	permissionPageSize   = 64
	permissionMaxObjects = 1024 // Per kind; overflow is unavailable, never partial.
)

// PermissionClient reads an explicit cluster endpoint. The hub reader lists
// only its pinned control namespace; workload readers need only namespace GET.
// Neither constructor nor successful reads attest RBAC/admission qualification.
type PermissionClient struct {
	api         rest.Interface
	clusterID   string
	control     value.NamespaceRef
	now         func() time.Time
	validator   *permissionValidator
	workerToken *configurationWorkerTokenTransport
}

var _ port.PermissionReader = (*PermissionClient)(nil)
var _ port.NamespaceReader = (*PermissionClient)(nil)

type permissionTransport struct{ http.RoundTripper }

func (t permissionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	v, err := t.RoundTripper.RoundTrip(r)
	if v != nil && v.Body != nil {
		v.Body = &boundedBody{v.Body, permissionPageBytes + 1}
	}
	return v, err
}

func NewPermissionClient(config *rest.Config, clusterID string, control value.NamespaceRef, now func() time.Time) (*PermissionClient, error) {
	if config == nil || config.Insecure || now == nil || !authorization.UUID(clusterID) || !namespaceRefValid(control) {
		return nil, value.ErrInvalid
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		return nil, err
	}
	v, err := newPermissionValidator()
	if err != nil {
		return nil, err
	}
	return &PermissionClient{api: api, clusterID: clusterID, control: control, now: now, validator: v}, nil
}

// newBoundedAPI supplies transport restrictions shared by the narrow adapters.
// Each adapter retains its own response/domain validation and resource paths.
func newBoundedAPI(config *rest.Config) (rest.Interface, error) {
	if config == nil || config.Insecure {
		return nil, value.ErrInvalid
	}
	u, err := url.Parse(config.Host)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, value.ErrInvalid
	}
	c := rest.CopyConfig(config)
	c.Timeout, c.QPS, c.Burst = 5*time.Second, 20, 20
	c.WarningHandlerWithContext = rest.NoWarnings{}
	c.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	c.DisableCompression = true
	c.ContentConfig = rest.ContentConfig{GroupVersion: &schema.GroupVersion{}, NegotiatedSerializer: scheme.Codecs.WithoutConversion(), ContentType: "application/json", AcceptContentTypes: "application/json"}
	c.Wrap(func(t http.RoundTripper) http.RoundTripper { return permissionTransport{t} })
	httpClient, err := rest.HTTPClientFor(c)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return value.ErrUnavailable }
	api, err := rest.UnversionedRESTClientForConfigAndClient(c, httpClient)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return api, nil
}

func permissionError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
		return value.ErrDenied
	}
	if apierrors.IsNotFound(err) {
		return value.ErrChanged
	}
	return value.ErrUnavailable
}
func (c *PermissionClient) current(ctx context.Context, start time.Time, maxAge time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	n := c.now()
	if n.Before(start) || !n.Before(start.Add(maxAge)) {
		return value.ErrUnavailable
	}
	return nil
}
func (c *PermissionClient) raw(ctx context.Context, path string, params map[string]string) ([]byte, error) {
	r := c.api.Get().AbsPath(path).MaxRetries(0)
	for k, v := range params {
		r.Param(k, v)
	}
	b, err := r.DoRaw(ctx)
	if err != nil {
		return nil, permissionError(ctx, err)
	}
	if err = permissionJSON(b, permissionPageBytes, 131072); err != nil {
		return nil, err
	}
	return b, nil
}

func (c *PermissionClient) namespace(ctx context.Context, ref value.NamespaceRef) (permissionMetadata, error) {
	b, err := c.raw(ctx, "/api/v1/namespaces/"+ref.Name, nil)
	if err != nil {
		return permissionMetadata{}, err
	}
	o, err := objectEnvelope(b)
	if err != nil || o.APIVersion != "v1" || o.Kind != "Namespace" {
		return permissionMetadata{}, value.ErrUnavailable
	}
	m, err := decodeMetadata(o.Metadata, true)
	if err != nil {
		return permissionMetadata{}, err
	}
	if m.Name != ref.Name || m.UID != ref.UID {
		return permissionMetadata{}, value.ErrChanged
	}
	return m, nil
}

type permissionListMetadata struct{ ResourceVersion, Continue string }

func listEnvelope(b []byte, kind string) (permissionListMetadata, []json.RawMessage, error) {
	var fields map[string]json.RawMessage
	var out permissionListMetadata
	var items []json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return out, nil, value.ErrUnavailable
	}
	var version, k string
	if json.Unmarshal(fields["apiVersion"], &version) != nil || version != "asservat.io/v1alpha1" || json.Unmarshal(fields["kind"], &k) != nil || k != kind+"List" {
		return out, nil, value.ErrUnavailable
	}
	var metadata map[string]json.RawMessage
	if json.Unmarshal(fields["metadata"], &metadata) != nil || json.Unmarshal(metadata["resourceVersion"], &out.ResourceVersion) != nil || !identity.Text(out.ResourceVersion, 128) {
		return out, nil, value.ErrUnavailable
	}
	if b, ok := metadata["continue"]; ok {
		if json.Unmarshal(b, &out.Continue) != nil || len(out.Continue) > 4096 {
			return out, nil, value.ErrUnavailable
		}
	}
	if json.Unmarshal(fields["items"], &items) != nil || items == nil {
		return out, nil, value.ErrUnavailable
	}
	return out, items, nil
}

func (c *PermissionClient) list(ctx context.Context, kind, plural string, start time.Time, budget *int) (string, []permissionObject, []value.Resource, error) {
	var objects []permissionObject
	var refs []value.Resource
	rv, continuation := "", ""
	seenUID, seenName, seenContinue := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for page := 0; page < 32; page++ {
		if err := c.current(ctx, start, 5*time.Second); err != nil {
			return "", nil, nil, err
		}
		params := map[string]string{"limit": strconv.Itoa(permissionPageSize)}
		if continuation != "" {
			params["continue"] = continuation
		}
		// No selectors and no resourceVersion=0: authoritative denies require
		// a complete, most-recent list with consistent pagination.
		b, err := c.raw(ctx, "/apis/asservat.io/v1alpha1/namespaces/"+c.control.Name+"/"+plural, params)
		if err != nil {
			return "", nil, nil, err
		}
		*budget -= len(b)
		if *budget < 0 {
			return "", nil, nil, value.ErrLimit
		}
		meta, items, err := listEnvelope(b, kind)
		if err != nil {
			return "", nil, nil, err
		}
		if rv != "" && rv != meta.ResourceVersion {
			return "", nil, nil, value.ErrUnavailable
		}
		rv = meta.ResourceVersion
		if len(items) > permissionPageSize || len(objects)+len(items) > permissionMaxObjects {
			return "", nil, nil, value.ErrLimit
		}
		for _, item := range items {
			o, err := objectEnvelope(item)
			if err != nil || o.APIVersion != "asservat.io/v1alpha1" || o.Kind != kind {
				return "", nil, nil, value.ErrUnavailable
			}
			m, err := decodeMetadata(o.Metadata, false)
			if err != nil || m.Namespace != c.control.Name || seenUID[m.UID] || seenName[m.Name] {
				return "", nil, nil, value.ErrUnavailable
			}
			seenUID[m.UID], seenName[m.Name] = true, true
			objects = append(objects, o)
			refs = append(refs, value.Resource{ClusterID: c.clusterID, Namespace: m.Namespace, NamespaceUID: c.control.UID, Kind: kind, Name: m.Name, UID: m.UID, ResourceVersion: m.RV, Generation: m.Generation, Deleting: m.Deleting})
		}
		if meta.Continue == "" {
			return rv, objects, refs, nil
		}
		if seenContinue[meta.Continue] {
			return "", nil, nil, value.ErrUnavailable
		}
		seenContinue[meta.Continue] = true
		continuation = meta.Continue
	}
	return "", nil, nil, value.ErrLimit
}

// PermissionSnapshot discards incomplete lists (including 410). A binding error
// fails the snapshot because denies are unknown; allow-only source failures do
// not discard independently complete bindings, and are explicitly marked.
// List freshness starts BEFORE the first API read and is never reset per page.
// A fresh list is not evidence of continuous assignment history after a gap.
func (c *PermissionClient) PermissionSnapshot(ctx context.Context) (value.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.now()
	ns, err := c.namespace(ctx, c.control)
	if err != nil {
		return value.Snapshot{}, err
	}
	if ns.Deleting {
		return value.Snapshot{}, value.ErrChanged
	}
	budget := permissionTotalBytes
	rv, objects, refs, err := c.list(ctx, "AccessBinding", "accessbindings", start, &budget)
	if err != nil {
		return value.Snapshot{}, err
	}
	out := value.Snapshot{ClusterID: c.clusterID, ControlNamespace: c.control, BindingResourceVersion: rv, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}
	for i, o := range objects {
		b, err := c.validator.binding(o, refs[i])
		if err != nil {
			return value.Snapshot{}, err
		}
		out.Bindings = append(out.Bindings, b)
	}
	rv, objects, refs, err = c.list(ctx, "PermissionSource", "permissionsources", start, &budget)
	if err == nil {
		out.SourcesComplete = true
		out.SourceResourceVersion = rv
		for i, o := range objects {
			s, err := c.validator.source(o, refs[i])
			if err != nil {
				out.InvalidSources = append(out.InvalidSources, refs[i])
				continue
			}
			out.Sources = append(out.Sources, s)
		}
	}
	ns, err = c.namespace(ctx, c.control)
	if err != nil {
		return value.Snapshot{}, err
	}
	if ns.Deleting {
		return value.Snapshot{}, value.ErrChanged
	}
	if err = c.current(ctx, start, 5*time.Second); err != nil {
		return value.Snapshot{}, err
	}
	return out, nil
}

func (c *PermissionClient) NamespaceMetadata(ctx context.Context, q value.NamespaceQuery) (value.NamespaceMetadata, error) {
	if !namespaceRefValid(q.Namespace) || len(q.LabelKeys)+len(q.AnnotationKeys) > 32 {
		return value.NamespaceMetadata{}, value.ErrInvalid
	}
	for _, keys := range [][]string{q.LabelKeys, q.AnnotationKeys} {
		seen := map[string]bool{}
		for _, k := range keys {
			if len(validation.IsQualifiedName(k)) != 0 || seen[k] {
				return value.NamespaceMetadata{}, value.ErrInvalid
			}
			seen[k] = true
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.now()
	ns, err := c.namespace(ctx, q.Namespace)
	if err != nil {
		return value.NamespaceMetadata{}, err
	}
	out := value.NamespaceMetadata{ClusterID: c.clusterID, Namespace: q.Namespace, ResourceVersion: ns.RV, ObservedAt: start, FreshUntil: start.Add(30 * time.Second), Deleting: ns.Deleting, Labels: map[string]string{}, Annotations: map[string]string{}}
	for _, copy := range []struct {
		keys     []string
		src, dst map[string]string
	}{{q.LabelKeys, ns.Labels, out.Labels}, {q.AnnotationKeys, ns.Annotations, out.Annotations}} {
		for _, k := range copy.keys {
			if v, ok := copy.src[k]; ok {
				if len(v) > 256 {
					return value.NamespaceMetadata{}, value.ErrLimit
				}
				copy.dst[k] = v
			}
		}
	}
	if err = c.current(ctx, start, 5*time.Second); err != nil {
		return value.NamespaceMetadata{}, err
	}
	return out, nil
}

// NewPermissionClientFrom shares c's API connection and identity for another
// pinned control namespace. It confers nothing beyond c's credential.
// SharesLimiter reports whether both clients spend one client-side rate
// limiter. Components that each need their own fixed budget are checked with
// it; a NewPermissionClientFrom copy always shares its original's limiter.
func (c *PermissionClient) SharesLimiter(o *PermissionClient) bool {
	return c != nil && o != nil && c.api.GetRateLimiter() == o.api.GetRateLimiter()
}

func NewPermissionClientFrom(c *PermissionClient, control value.NamespaceRef) (*PermissionClient, error) {
	if c == nil || !namespaceRefValid(control) {
		return nil, value.ErrInvalid
	}
	out := *c
	out.control = control
	return &out, nil
}
