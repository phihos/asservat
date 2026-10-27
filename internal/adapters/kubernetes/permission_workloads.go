package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
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

var _ port.WorkloadObserver = (*PermissionClient)(nil)

func workloadCollection(kind string) (string, bool) {
	switch kind {
	case "Deployment":
		return "/apis/apps/v1/deployments", true
	case "StatefulSet":
		return "/apis/apps/v1/statefulsets", true
	}
	return "", false
}

// workloadSelector is the server-side equality label selector of a
// selection; every key and value is validated, so it cannot be widened.
func workloadSelector(sel value.WorkloadSelection) (string, bool) {
	if !sel.Valid() || !namespaceKeysValid(sel.Keys) {
		return "", false
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(sel.Selector)) {
		v := sel.Selector[k]
		if len(validation.IsQualifiedName(k)) != 0 || len(validation.IsValidLabelValue(v)) != 0 || v == "" {
			return "", false
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ","), true
}

func reduceWorkload(m metav1.ObjectMeta, kind string, k value.NamespaceKeys) (value.ObservedWorkload, bool) {
	if len(validation.IsDNS1123Subdomain(m.Name)) != 0 || len(validation.IsDNS1123Label(m.Namespace)) != 0 || !identity.Text(string(m.UID), 64) || !identity.Text(m.ResourceVersion, 128) {
		return value.ObservedWorkload{}, false
	}
	n := reduceNamespace(permissionMetadata{Name: m.Name, UID: string(m.UID), RV: m.ResourceVersion, Deleting: m.DeletionTimestamp != nil, Labels: m.Labels, Annotations: m.Annotations}, k)
	return value.ObservedWorkload{Kind: kind, Namespace: value.NamespaceRef{Name: m.Namespace}, ObservedNamespace: n}, true
}

// ListWorkloads reads every selected workload of kind cluster-wide as
// PartialObjectMetadata at one collection resourceVersion (ADR-247).
func (c *PermissionClient) ListWorkloads(ctx context.Context, kind string, sel value.WorkloadSelection) (string, []value.ObservedWorkload, error) {
	path, ok := workloadCollection(kind)
	selector, valid := workloadSelector(sel)
	if !ok || !valid {
		return "", nil, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out []value.ObservedWorkload
	rv, continuation, budget := "", "", namespaceTotalBytes
	seen := map[string]bool{}
	for page := 0; page < namespaceMaxPages; page++ {
		r := c.api.Get().AbsPath(path).MaxRetries(0).SetHeader("Accept", capacityMetadataListAccept).Param("limit", strconv.Itoa(namespacePageSize)).Param("labelSelector", selector)
		if continuation != "" {
			r.Param("continue", continuation)
		}
		b, err := r.DoRaw(ctx)
		if err != nil {
			return "", nil, permissionError(ctx, err)
		}
		var list metav1.PartialObjectMetadataList
		if budget -= len(b); budget < 0 {
			return "", nil, value.ErrLimit
		}
		if json.Unmarshal(b, &list) != nil || list.APIVersion != "meta.k8s.io/v1" || list.Kind != "PartialObjectMetadataList" || !identity.Text(list.ResourceVersion, 128) || rv != "" && list.ResourceVersion != rv || len(list.Items) > namespacePageSize || list.Continue != "" && list.Continue == continuation {
			return "", nil, value.ErrUnavailable
		}
		rv = list.ResourceVersion
		for _, item := range list.Items {
			w, ok := reduceWorkload(item.ObjectMeta, kind, sel.Keys)
			if !ok || seen[w.UID] {
				return "", nil, value.ErrUnavailable
			}
			seen[w.UID] = true
			if len(out) == value.MaxObservedWorkloads {
				return "", nil, value.ErrLimit
			}
			out = append(out, w)
		}
		if list.Continue == "" {
			return rv, out, ctx.Err()
		}
		continuation = list.Continue
	}
	return "", nil, value.ErrLimit
}

type workloadWatch struct {
	kind    string
	keys    value.NamespaceKeys
	decoder streaming.Decoder
	cancel  context.CancelFunc
	mu      sync.Mutex
}

func (w *workloadWatch) Close() { w.cancel(); w.decoder.Close() }

// WatchWorkloads opens one finite watch session of kind from rv with the
// same selector, metadata only.
func (c *PermissionClient) WatchWorkloads(ctx context.Context, kind, rv string, sel value.WorkloadSelection) (port.WorkloadWatch, error) {
	path, ok := workloadCollection(kind)
	selector, valid := workloadSelector(sel)
	if !ok || !valid || !identity.Text(rv, 128) || rv == "0" {
		return nil, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	r := c.api.Get().AbsPath(path).MaxRetries(0).SetHeader("Accept", capacityMetadataAccept).Param("watch", "true").Param("labelSelector", selector).Param("resourceVersion", rv).Param("allowWatchBookmarks", "true").Param("timeoutSeconds", namespaceWatchSeconds)
	body, err := r.Stream(ctx)
	if err != nil {
		mapped := permissionError(ctx, err)
		switch {
		case apierrors.IsGone(err) || apierrors.IsResourceExpired(err):
			mapped = value.ErrChanged
		case errors.Is(mapped, value.ErrChanged):
			mapped = value.ErrUnavailable
		}
		cancel()
		return nil, mapped
	}
	return &workloadWatch{kind: kind, keys: sel.Keys, decoder: streaming.NewDecoder(serializer.Framer.NewFrameReader(body), permissionEventDecoder{}), cancel: cancel}, nil
}

func (w *workloadWatch) Next(ctx context.Context) (port.WorkloadEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() != nil {
		return port.WorkloadEvent{}, ctx.Err()
	}
	stop := context.AfterFunc(ctx, w.Close)
	defer stop()
	var event metav1.WatchEvent
	_, _, err := w.decoder.Decode(nil, &event)
	if err != nil || ctx.Err() != nil {
		w.Close()
		if ctx.Err() == nil && errors.Is(err, io.EOF) {
			return port.WorkloadEvent{}, io.EOF
		}
		return port.WorkloadEvent{}, value.ErrUnavailable
	}
	fail := func() (port.WorkloadEvent, error) { w.Close(); return port.WorkloadEvent{}, value.ErrChanged }
	var object metav1.PartialObjectMetadata
	if json.Unmarshal(event.Object.Raw, &object) != nil || object.APIVersion != "meta.k8s.io/v1" || object.Kind != "PartialObjectMetadata" || !identity.Text(object.ResourceVersion, 128) {
		return fail()
	}
	switch event.Type {
	case "BOOKMARK":
		return port.WorkloadEvent{Type: "BOOKMARK", ResourceVersion: object.ResourceVersion}, nil
	case "ADDED", "MODIFIED", "DELETED":
		wl, ok := reduceWorkload(object.ObjectMeta, w.kind, w.keys)
		if !ok {
			return fail()
		}
		return port.WorkloadEvent{Type: string(event.Type), ResourceVersion: wl.ResourceVersion, Workload: &wl}, nil
	}
	return fail()
}

// NamespaceUIDs lists every namespace name and UID of the cluster, metadata
// only, within the namespace observation bounds.
func (c *PermissionClient) NamespaceUIDs(ctx context.Context) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out := map[string]string{}
	continuation, budget := "", namespaceTotalBytes
	for page := 0; page < namespaceMaxPages; page++ {
		r := c.api.Get().AbsPath("/api/v1/namespaces").MaxRetries(0).SetHeader("Accept", capacityMetadataListAccept).Param("limit", strconv.Itoa(namespacePageSize))
		if continuation != "" {
			r.Param("continue", continuation)
		}
		b, err := r.DoRaw(ctx)
		if err != nil {
			return nil, permissionError(ctx, err)
		}
		var list metav1.PartialObjectMetadataList
		if budget -= len(b); budget < 0 {
			return nil, value.ErrLimit
		}
		if json.Unmarshal(b, &list) != nil || list.Kind != "PartialObjectMetadataList" || len(list.Items) > namespacePageSize || list.Continue != "" && list.Continue == continuation {
			return nil, value.ErrUnavailable
		}
		for _, n := range list.Items {
			if len(validation.IsDNS1123Label(n.Name)) != 0 || !identity.Text(string(n.UID), 64) || out[n.Name] != "" {
				return nil, value.ErrUnavailable
			}
			if n.DeletionTimestamp == nil {
				out[n.Name] = string(n.UID)
			}
		}
		if list.Continue == "" {
			return out, ctx.Err()
		}
		continuation = list.Continue
	}
	return nil, value.ErrLimit
}
