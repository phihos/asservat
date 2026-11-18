package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"sync"
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
	"k8s.io/client-go/util/flowcontrol"
)

// Keep at most 2 MiB per Kubernetes response. LIST retries the same cursor
// with a smaller page when the objects and their metadata exceed this budget.
const (
	permissionPageBytes = 2 << 20
	permissionPageSize  = 64
)

// PermissionClient reads an explicit cluster endpoint. The hub reader lists
// the cluster's AccessBindings in every namespace (ADR-329) and the
// PermissionSources of its control namespace; workload readers need only
// namespace GET. Successful reads attest no RBAC/admission qualification.
type PermissionClient struct {
	api         rest.Interface
	watchAPI    rest.Interface
	clusterID   string
	control     value.NamespaceRef
	now         func() time.Time
	validator   *permissionValidator
	workerToken *configurationWorkerTokenTransport
	bindings    *bindingNamespaces
}

// bindingNamespaces remembers each observed AccessBinding's namespace UID by
// binding UID (ADR-329). A binding exists only in the namespace incarnation
// it was created in, so the mapping never changes; a namespace created after
// the binding is a later incarnation and is refused.
type bindingNamespaces struct {
	mu        sync.Mutex
	byBinding map[string]value.NamespaceRef
}

var _ port.PermissionReader = (*PermissionClient)(nil)
var _ port.NamespaceReader = (*PermissionClient)(nil)

type permissionTransport struct{ http.RoundTripper }

func (t permissionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	v, err := t.RoundTripper.RoundTrip(r)
	// Successful watches apply the same byte budget independently to each event.
	if v != nil && v.Body != nil && (v.StatusCode != http.StatusOK || r.URL.Query().Get("watch") != "true") {
		v.Body = &boundedBody{v.Body, permissionPageBytes + 1}
	}
	return v, err
}

func NewPermissionClient(config *rest.Config, clusterID string, control value.NamespaceRef, now func() time.Time) (*PermissionClient, error) {
	if config == nil || config.Insecure || now == nil || !authorization.UUID(clusterID) || !namespaceRefValid(control) {
		return nil, value.ErrInvalid
	}
	api, watch, err := boundedRESTClients(config, true)
	if err != nil {
		return nil, err
	}
	v, err := newPermissionValidator()
	if err != nil {
		return nil, err
	}
	v.clusters = map[string]string{LocalClusterName: clusterID}
	return &PermissionClient{api: api, watchAPI: watch, clusterID: clusterID, control: control, now: now, validator: v, bindings: &bindingNamespaces{byBinding: map[string]value.NamespaceRef{}}}, nil
}

// WithClusterNames returns c resolving the joined clusters' names (values
// clusters[].name to clusterID) in PermissionSources and
// ClusterAccessBindings, besides LocalClusterName for its own cluster.
func (c *PermissionClient) WithClusterNames(names map[string]string) *PermissionClient {
	out := *c
	v := *c.validator
	v.clusters = map[string]string{LocalClusterName: c.clusterID}
	for name, id := range names {
		if name != LocalClusterName && authorization.UUID(id) {
			v.clusters[name] = id
		}
	}
	out.validator = &v
	return &out
}

// newBoundedAPI supplies transport restrictions shared by the narrow adapters.
// Each adapter retains its own response/domain validation and resource paths.
func newBoundedAPI(config *rest.Config) (*rest.RESTClient, error) {
	api, _, err := boundedRESTClients(config, false)
	return api, err
}

func boundedRESTClients(config *rest.Config, watch bool) (*rest.RESTClient, *rest.RESTClient, error) {
	if config == nil || config.Insecure {
		return nil, nil, value.ErrInvalid
	}
	u, err := url.Parse(config.Host)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, nil, value.ErrInvalid
	}
	c := rest.CopyConfig(config)
	// Fixed 20/20, except the one explicit ADR-208 opening budget that the
	// installer's one-shot commands request; each client keeps its own limiter.
	if c.QPS != OpeningQPS || c.Burst != OpeningBurst {
		c.QPS, c.Burst = 20, 20
	} else if c.RateLimiter == nil {
		// The same bucket, counted for the installer's per-step diagnostics.
		c.RateLimiter = measuredLimiter{flowcontrol.NewTokenBucketRateLimiter(OpeningQPS, OpeningBurst)}
		c.Wrap(func(t http.RoundTripper) http.RoundTripper { return measuredTransport{t} })
	}
	c.Timeout = 5 * time.Second
	c.WarningHandlerWithContext = rest.NoWarnings{}
	c.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	c.DisableCompression = true
	c.ContentConfig = rest.ContentConfig{GroupVersion: &schema.GroupVersion{}, NegotiatedSerializer: scheme.Codecs.WithoutConversion(), ContentType: "application/json", AcceptContentTypes: "application/json"}
	c.Wrap(func(t http.RoundTripper) http.RoundTripper { return permissionTransport{t} })
	httpClient, err := rest.HTTPClientFor(c)
	if err != nil {
		return nil, nil, value.ErrUnavailable
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return value.ErrUnavailable }
	api, err := rest.UnversionedRESTClientForConfigAndClient(c, httpClient)
	if err != nil {
		return nil, nil, value.ErrUnavailable
	}
	if !watch {
		return api, nil, nil
	}
	// An ordinary request is bounded from start to finish. A watch shares
	// its transport, credentials, redirect policy and rate limiter, while
	// the watch opener bounds time to the response headers.
	c.RateLimiter = api.GetRateLimiter()
	streamHTTP := &http.Client{Transport: httpClient.Transport, CheckRedirect: httpClient.CheckRedirect, Jar: httpClient.Jar}
	stream, err := rest.UnversionedRESTClientForConfigAndClient(c, streamHTTP)
	if err != nil {
		return nil, nil, value.ErrUnavailable
	}
	return api, stream, nil
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
		if errors.Is(err, ErrContextUnavailable) {
			return nil, value.ErrLimit
		}
		return nil, permissionError(ctx, err)
	}
	if len(b) > permissionPageBytes {
		return nil, value.ErrLimit
	}
	if err = permissionJSON(b, permissionPageBytes, 0); err != nil {
		return nil, value.ErrUnavailable
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
	return listEnvelopeOf(b, "asservat.io/v1alpha1", kind)
}

func listEnvelopeOf(b []byte, apiVersion, kind string) (permissionListMetadata, []json.RawMessage, error) {
	var fields map[string]json.RawMessage
	var out permissionListMetadata
	var items []json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return out, nil, value.ErrUnavailable
	}
	var version, k string
	if json.Unmarshal(fields["apiVersion"], &version) != nil || version != apiVersion || json.Unmarshal(fields["kind"], &k) != nil || k != kind+"List" {
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

// cached returns a binding's remembered namespace.
func (c *PermissionClient) cached(m permissionMetadata) (value.NamespaceRef, bool) {
	if c.bindings == nil {
		return value.NamespaceRef{}, false
	}
	c.bindings.mu.Lock()
	defer c.bindings.mu.Unlock()
	ref, ok := c.bindings.byBinding[m.UID]
	return ref, ok && ref.Name == m.Namespace
}

// A complete LIST shares each namespace observation across its unplaced
// bindings. The confirming LIST then uses the remembered binding identities.
func (c *PermissionClient) placeBindings(ctx context.Context, bindings []permissionMetadata) error {
	namespaces := make(map[string]permissionMetadata)
	for _, binding := range bindings {
		if _, err := c.placeBinding(ctx, binding, namespaces); err != nil {
			return err
		}
	}
	return nil
}

// placeBinding pins the namespace UID to the binding's own incarnation. A
// missing or younger namespace, or missing creation time, leaves the UID empty.
func (c *PermissionClient) placeBinding(ctx context.Context, m permissionMetadata, namespaces map[string]permissionMetadata) (value.NamespaceRef, error) {
	if ref, ok := c.cached(m); ok {
		return ref, nil
	}
	if c.bindings == nil {
		return value.NamespaceRef{}, value.ErrUnavailable
	}
	ns, known := namespaces[m.Namespace]
	if !known {
		var err error
		ns, err = c.bindingNamespace(ctx, m.Namespace)
		if err != nil && !errors.Is(err, value.ErrChanged) {
			return value.NamespaceRef{}, err
		}
		if namespaces != nil {
			namespaces[m.Namespace] = ns
		}
	}
	ref := value.NamespaceRef{Name: m.Namespace}
	if ns.Name == m.Namespace && !ns.Created.IsZero() && !m.Created.IsZero() && !ns.Created.After(m.Created) {
		ref.UID = ns.UID
	}
	c.bindings.mu.Lock()
	defer c.bindings.mu.Unlock()
	if known, ok := c.bindings.byBinding[m.UID]; ok {
		return known, nil
	}
	c.bindings.byBinding[m.UID] = ref
	return ref, nil
}

func (c *PermissionClient) bindingNamespace(ctx context.Context, name string) (permissionMetadata, error) {
	b, err := c.raw(ctx, "/api/v1/namespaces/"+name, nil)
	if err != nil {
		return permissionMetadata{}, err
	}
	o, err := objectEnvelope(b)
	if err != nil || o.APIVersion != "v1" || o.Kind != "Namespace" {
		return permissionMetadata{}, value.ErrUnavailable
	}
	ns, err := decodeMetadata(o.Metadata, true)
	if err != nil {
		return permissionMetadata{}, err
	}
	return permissionMetadata{Name: ns.Name, UID: ns.UID, Created: ns.Created}, nil
}

// listPath is a kind's LIST path: every namespace for AccessBindings
// (ADR-329), the cluster for ClusterAccessBindings, the control namespace
// for PermissionSources.
func (c *PermissionClient) listPath(plural string) string {
	if plural == "accessbindings" || plural == "clusteraccessbindings" {
		return "/apis/asservat.io/v1alpha1/" + plural
	}
	return "/apis/asservat.io/v1alpha1/namespaces/" + c.control.Name + "/" + plural
}

// list returns the complete LIST of one kind. Bindings whose namespace is not
// yet known are returned in unplaced, and the LIST then is not complete.
func (c *PermissionClient) list(ctx context.Context, kind, plural string) (string, []permissionObject, []value.Resource, []permissionMetadata, error) {
	var objects []permissionObject
	var refs []value.Resource
	var unplaced []permissionMetadata
	rv, continuation := "", ""
	pageSize := permissionPageSize
	seenUID, seenName, seenContinue := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for {
		// Each REST request has an I/O timeout. Kubernetes binds continuation
		// pages to the initial LIST revision, however long the whole LIST takes.
		params := map[string]string{"limit": strconv.Itoa(pageSize)}
		if continuation != "" {
			params["continue"] = continuation
		}
		// No selectors and no resourceVersion=0: authoritative denies require
		// a complete, most-recent list with consistent pagination.
		b, err := c.raw(ctx, c.listPath(plural), params)
		if errors.Is(err, value.ErrLimit) && pageSize > 1 {
			pageSize /= 2
			continue
		}
		if err != nil {
			return "", nil, nil, nil, err
		}
		meta, items, err := listEnvelope(b, kind)
		if err != nil {
			return "", nil, nil, nil, err
		}
		if rv != "" && rv != meta.ResourceVersion {
			return "", nil, nil, nil, value.ErrUnavailable
		}
		rv = meta.ResourceVersion
		if len(items) > pageSize {
			return "", nil, nil, nil, value.ErrLimit
		}
		for _, item := range items {
			o, err := objectEnvelope(item)
			if err != nil || o.APIVersion != "asservat.io/v1alpha1" || o.Kind != kind {
				return "", nil, nil, nil, value.ErrUnavailable
			}
			m, err := decodeObjectMetadata(o.Metadata, kind != value.ClusterAccessBindingKind)
			key := m.Namespace + "/" + m.Name
			if err != nil || kind == "PermissionSource" && m.Namespace != c.control.Name || seenUID[m.UID] || seenName[key] {
				return "", nil, nil, nil, value.ErrUnavailable
			}
			seenUID[m.UID], seenName[key] = true, true
			namespace := c.control
			if kind == "AccessBinding" {
				ref, ok := c.cached(m)
				if !ok {
					unplaced = append(unplaced, m)
					continue
				}
				namespace = ref
			}
			objects = append(objects, o)
			refs = append(refs, value.Resource{ClusterID: c.clusterID, Namespace: m.Namespace, NamespaceUID: namespace.UID, Kind: kind, Name: m.Name, UID: m.UID, ResourceVersion: m.RV, Generation: m.Generation, Deleting: m.Deleting})
		}
		if meta.Continue == "" {
			return rv, objects, refs, unplaced, nil
		}
		if seenContinue[meta.Continue] {
			return "", nil, nil, nil, value.ErrUnavailable
		}
		seenContinue[meta.Continue] = true
		continuation = meta.Continue
	}
}

// PermissionSnapshot discards incomplete lists (including 410). A binding error
// fails the snapshot because the denies are unknown. Allow-only sources are
// observed independently by PermissionSources.
// List freshness starts BEFORE the first API read and is never reset per page.
// A fresh list is not evidence of continuous assignment history after a gap.
//
// ADR-329: bindings live in every namespace. A LIST that finds bindings whose
// namespace UID is not yet known places them (bounded, outside the window)
// and lists once more; only a LIST without unplaced bindings is a snapshot.
func (c *PermissionClient) PermissionSnapshot(ctx context.Context) (value.Snapshot, error) {
	s, unplaced, err := c.snapshot(ctx)
	if err != nil || len(unplaced) == 0 {
		return s, err
	}
	if err = c.placeBindings(ctx, unplaced); err != nil {
		return value.Snapshot{}, err
	}
	if s, unplaced, err = c.snapshot(ctx); err == nil && len(unplaced) != 0 {
		return value.Snapshot{}, value.ErrUnavailable
	}
	return s, err
}

func (c *PermissionClient) snapshot(ctx context.Context) (value.Snapshot, []permissionMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.now()
	rv, objects, refs, unplaced, err := c.list(ctx, "AccessBinding", "accessbindings")
	if err != nil {
		return value.Snapshot{}, nil, err
	}
	if len(unplaced) != 0 {
		return value.Snapshot{}, unplaced, nil
	}
	out := value.Snapshot{ClusterID: c.clusterID, ControlNamespace: c.control, BindingResourceVersion: rv, ObservedAt: start}
	for i, o := range objects {
		out.Bindings = append(out.Bindings, c.validator.observedBinding(o, refs[i]))
	}
	// ClusterAccessBindings deny as well, so an incomplete LIST fails the
	// snapshot like AccessBindings.
	cluster, err := c.ClusterAccessBindings(ctx)
	if err != nil {
		return value.Snapshot{}, nil, err
	}
	out.ClusterBindings, out.ClusterBindingResourceVersion = cluster.ClusterBindings, cluster.ClusterBindingResourceVersion
	ns, err := c.namespace(ctx, c.control)
	if err != nil {
		return value.Snapshot{}, nil, err
	}
	if ns.Deleting {
		return value.Snapshot{}, nil, value.ErrChanged
	}
	if err = c.current(ctx, start, 5*time.Second); err != nil {
		return value.Snapshot{}, nil, err
	}
	return out, nil, nil
}

// ClusterAccessBindings follows the cluster-scoped collection independently
// of the ordered namespaced watch.
func (c *PermissionClient) ClusterAccessBindings(ctx context.Context) (value.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.now()
	rv, objects, refs, _, err := c.list(ctx, value.ClusterAccessBindingKind, "clusteraccessbindings")
	if err != nil {
		return value.Snapshot{}, err
	}
	out := value.Snapshot{ClusterID: c.clusterID, ClusterBindingResourceVersion: rv, ObservedAt: start}
	for i, o := range objects {
		out.ClusterBindings = append(out.ClusterBindings, c.validator.clusterBindings(o, refs[i])...)
	}
	if err = c.current(ctx, start, 5*time.Second); err != nil {
		return value.Snapshot{}, err
	}
	return out, nil
}

// PermissionSources independently reads the optional allow-only configuration.
func (c *PermissionClient) PermissionSources(ctx context.Context) (value.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.now()
	rv, objects, refs, _, err := c.list(ctx, "PermissionSource", "permissionsources")
	if err != nil {
		return value.Snapshot{}, err
	}
	out := value.Snapshot{SourceResourceVersion: rv, SourcesComplete: true}
	for i, o := range objects {
		source, err := c.validator.source(o, refs[i])
		if err != nil {
			out.InvalidSources = append(out.InvalidSources, refs[i])
			continue
		}
		out.Sources = append(out.Sources, source)
	}
	if err := c.current(ctx, start, 5*time.Second); err != nil {
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
	out := value.NamespaceMetadata{ClusterID: c.clusterID, Namespace: q.Namespace, ResourceVersion: ns.RV, ObservedAt: start, FreshUntil: identity.Check(start, identity.Recheck).Until(), Deleting: ns.Deleting, Labels: map[string]string{}, Annotations: map[string]string{}}
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
