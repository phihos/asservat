package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	serializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/streaming"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ADR-242 namespace observation bounds. A cluster with more namespaces, or a
// longer LIST, is unavailable for inheritance, never partially observed.
const (
	namespacePageSize   = 200
	namespaceMaxPages   = 80
	namespaceTotalBytes = 64 << 20
	// A session shorter than the client's five-second request timeout; each
	// clean end renews the observation's freshness.
	namespaceWatchSeconds = "2"
)

var _ port.NamespaceObserver = (*PermissionClient)(nil)

func namespaceKeysValid(k value.NamespaceKeys) bool {
	if !k.Valid() || len(k.Labels)+len(k.Annotations) == 0 {
		return false
	}
	for _, keys := range [][]string{k.Labels, k.Annotations} {
		for _, key := range keys {
			if len(validation.IsQualifiedName(key)) != 0 {
				return false
			}
		}
	}
	return true
}

// reduceNamespace keeps only the observed keys, each value as its digest.
func reduceNamespace(m permissionMetadata, k value.NamespaceKeys) value.ObservedNamespace {
	n := value.ObservedNamespace{Name: m.Name, UID: m.UID, ResourceVersion: m.RV, Deleting: m.Deleting}
	pick := func(keys []string, source map[string]string) map[string]string {
		var out map[string]string
		for _, key := range keys {
			if v, ok := source[key]; ok {
				if out == nil {
					out = map[string]string{}
				}
				out[key] = port.ValueDigest(v)
			}
		}
		return out
	}
	n.Labels, n.Annotations = pick(k.Labels, m.Labels), pick(k.Annotations, m.Annotations)
	return n
}

// namespaceObject decodes one namespace from a LIST item (core list items
// carry no type) or a watch event (which does).
func namespaceObject(raw []byte, k value.NamespaceKeys) (value.ObservedNamespace, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return value.ObservedNamespace{}, value.ErrUnavailable
	}
	for key, want := range map[string]string{"apiVersion": "v1", "kind": "Namespace"} {
		var got string
		if v, ok := fields[key]; ok && (json.Unmarshal(v, &got) != nil || got != want) {
			return value.ObservedNamespace{}, value.ErrUnavailable
		}
	}
	m, err := decodeMetadata(fields["metadata"], true)
	if err != nil {
		return value.ObservedNamespace{}, value.ErrUnavailable
	}
	return reduceNamespace(m, k), nil
}

// ListNamespaces reads every namespace of this client's cluster at one
// collection resourceVersion, without selectors or resourceVersion=0, and
// returns those carrying an observed key. ObservedAt precedes the first page.
func (c *PermissionClient) ListNamespaces(ctx context.Context, keys value.NamespaceKeys) (value.NamespaceList, error) {
	if !namespaceKeysValid(keys) {
		return value.NamespaceList{}, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out := value.NamespaceList{ClusterID: c.clusterID, Keys: keys, ObservedAt: c.now()}
	budget, continuation := namespaceTotalBytes, ""
	seenUID, seenName, seenContinue := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for page := 0; page < namespaceMaxPages; page++ {
		params := map[string]string{"limit": strconv.Itoa(namespacePageSize)}
		if continuation != "" {
			params["continue"] = continuation
		}
		b, err := c.raw(ctx, "/api/v1/namespaces", params)
		if err != nil {
			return value.NamespaceList{}, err
		}
		if budget -= len(b); budget < 0 {
			return value.NamespaceList{}, value.ErrLimit
		}
		meta, items, err := listEnvelopeOf(b, "v1", "Namespace")
		if err != nil || out.ResourceVersion != "" && out.ResourceVersion != meta.ResourceVersion || len(items) > namespacePageSize {
			return value.NamespaceList{}, value.ErrUnavailable
		}
		out.ResourceVersion = meta.ResourceVersion
		for _, item := range items {
			n, err := namespaceObject(item, keys)
			if err != nil || seenUID[n.UID] || seenName[n.Name] {
				return value.NamespaceList{}, value.ErrUnavailable
			}
			seenUID[n.UID], seenName[n.Name] = true, true
			if len(n.Labels)+len(n.Annotations) == 0 {
				continue
			}
			if len(out.Namespaces) == value.MaxObservedNamespaces {
				return value.NamespaceList{}, value.ErrLimit
			}
			out.Namespaces = append(out.Namespaces, n)
		}
		if meta.Continue == "" {
			return out, ctx.Err()
		}
		if seenContinue[meta.Continue] {
			return value.NamespaceList{}, value.ErrUnavailable
		}
		seenContinue[meta.Continue] = true
		continuation = meta.Continue
	}
	return value.NamespaceList{}, value.ErrLimit
}

type namespaceWatch struct {
	client  *PermissionClient
	keys    value.NamespaceKeys
	decoder streaming.Decoder
	cancel  context.CancelFunc
	mu      sync.Mutex
}

func (w *namespaceWatch) Close() { w.cancel(); w.decoder.Close() }

// WatchNamespaces opens one finite watch session from rv. A server ERROR
// event (such as expired history) is value.ErrChanged; a transport failure is
// value.ErrUnavailable and may be resumed from the same cursor.
func (c *PermissionClient) WatchNamespaces(ctx context.Context, rv string, keys value.NamespaceKeys) (port.NamespaceWatch, error) {
	if !identity.Text(rv, 128) || rv == "0" || !namespaceKeysValid(keys) {
		return nil, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	r := c.api.Get().AbsPath("/api/v1/namespaces").MaxRetries(0).Param("watch", "true").Param("resourceVersion", rv).Param("allowWatchBookmarks", "true").Param("timeoutSeconds", namespaceWatchSeconds)
	body, err := r.Stream(ctx)
	if err != nil {
		mapped := permissionError(ctx, err)
		switch {
		case apierrors.IsGone(err) || apierrors.IsResourceExpired(err):
			mapped = value.ErrChanged
		case errors.Is(mapped, value.ErrChanged):
			// A 404 is not expired history; resume or relist later.
			mapped = value.ErrUnavailable
		}
		cancel()
		return nil, mapped
	}
	return &namespaceWatch{client: c, keys: keys, decoder: streaming.NewDecoder(serializer.Framer.NewFrameReader(body), permissionEventDecoder{}), cancel: cancel}, nil
}

func (w *namespaceWatch) Next(ctx context.Context) (value.NamespaceEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() != nil {
		return value.NamespaceEvent{}, ctx.Err()
	}
	stop := context.AfterFunc(ctx, w.Close)
	defer stop()
	var event metav1.WatchEvent
	_, _, err := w.decoder.Decode(nil, &event)
	if err != nil || ctx.Err() != nil {
		w.Close()
		if ctx.Err() == nil && errors.Is(err, io.EOF) {
			return value.NamespaceEvent{}, io.EOF
		}
		return value.NamespaceEvent{}, value.ErrUnavailable
	}
	fail := func() (value.NamespaceEvent, error) { w.Close(); return value.NamespaceEvent{}, value.ErrChanged }
	switch event.Type {
	case "BOOKMARK":
		var fields map[string]json.RawMessage
		var metadata map[string]json.RawMessage
		var rv string
		if json.Unmarshal(event.Object.Raw, &fields) != nil || json.Unmarshal(fields["metadata"], &metadata) != nil || json.Unmarshal(metadata["resourceVersion"], &rv) != nil || !identity.Text(rv, 128) {
			return fail()
		}
		return value.NamespaceEvent{Type: "BOOKMARK", ResourceVersion: rv}, nil
	case "ADDED", "MODIFIED", "DELETED":
		n, err := namespaceObject(event.Object.Raw, w.keys)
		if err != nil {
			return fail()
		}
		return value.NamespaceEvent{Type: string(event.Type), ResourceVersion: n.ResourceVersion, Namespace: &n}, nil
	}
	// ERROR (for example 410 Gone) and unknown types end the history.
	return fail()
}
