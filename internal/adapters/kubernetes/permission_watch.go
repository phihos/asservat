package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	serializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/streaming"
)

var _ port.BindingWatcher = (*PermissionClient)(nil)

// This decoder uses the Kubernetes streaming framer, then applies the same
// bounded strict JSON checks as the LIST reader before accepting any event.
type permissionEventDecoder struct{}

func (permissionEventDecoder) Decode(data []byte, _ *schema.GroupVersionKind, into runtime.Object) (runtime.Object, *schema.GroupVersionKind, error) {
	if err := permissionJSON(data, permissionPageBytes, 131072); err != nil {
		return nil, nil, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 2 || fields["type"] == nil || fields["object"] == nil {
		return nil, nil, value.ErrUnavailable
	}
	event, ok := into.(*metav1.WatchEvent)
	if !ok {
		return nil, nil, value.ErrInvalid
	}
	if json.Unmarshal(fields["type"], &event.Type) != nil {
		return nil, nil, value.ErrUnavailable
	}
	event.Object.Raw = append([]byte{}, fields["object"]...)
	return event, nil, nil
}

type permissionBindingWatch struct {
	client  *PermissionClient
	decoder streaming.Decoder
	cancel  context.CancelFunc
	mu      sync.Mutex
}

func (w *permissionBindingWatch) Close() { w.cancel(); w.decoder.Close() }
func (c *PermissionClient) WatchBindings(ctx context.Context, rv string) (port.BindingWatch, error) {
	if !identity.Text(rv, 128) || rv == "0" {
		return nil, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	start := c.now()
	ns, err := c.namespace(ctx, c.control)
	if err != nil || ns.Deleting {
		cancel()
		return nil, value.ErrChanged
	}
	r := c.api.Get().AbsPath("/apis/asservat.io/v1alpha1/namespaces/"+c.control.Name+"/accessbindings").MaxRetries(0).Param("watch", "true").Param("resourceVersion", rv).Param("allowWatchBookmarks", "true").Param("timeoutSeconds", "4")
	body, err := r.Stream(ctx)
	if err != nil {
		mapped := permissionError(ctx, err)
		cancel()
		return nil, mapped
	}
	if err = c.current(ctx, start, 5*time.Second); err != nil {
		body.Close()
		cancel()
		return nil, err
	}
	return &permissionBindingWatch{client: c, decoder: streaming.NewDecoder(serializer.Framer.NewFrameReader(body), permissionEventDecoder{}), cancel: cancel}, nil
}
func (w *permissionBindingWatch) Next(ctx context.Context) (value.BindingEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() != nil {
		return value.BindingEvent{}, ctx.Err()
	}
	stop := context.AfterFunc(ctx, w.Close)
	defer stop()
	var event metav1.WatchEvent
	_, _, err := w.decoder.Decode(nil, &event)
	if err != nil || ctx.Err() != nil {
		w.Close()
		if ctx.Err() == nil && errors.Is(err, io.EOF) {
			return value.BindingEvent{}, io.EOF
		}
		return value.BindingEvent{}, value.ErrUnavailable
	}
	fail := func() (value.BindingEvent, error) { w.Close(); return value.BindingEvent{}, value.ErrChanged }
	if event.Type == "ERROR" {
		return fail()
	}
	if event.Type == "BOOKMARK" {
		wire, err := objectEnvelope(event.Object.Raw)
		var metadata map[string]json.RawMessage
		var rv string
		if err != nil || wire.APIVersion != "asservat.io/v1alpha1" || wire.Kind != "AccessBinding" || json.Unmarshal(wire.Metadata, &metadata) != nil || json.Unmarshal(metadata["resourceVersion"], &rv) != nil || !identity.Text(rv, 128) {
			return fail()
		}
		// A bookmark can resume history, but cannot extend complete-deny freshness.
		return value.BindingEvent{Type: event.Type, ResourceVersion: rv}, nil
	}
	if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
		return fail()
	}
	o, err := objectEnvelope(event.Object.Raw)
	if err != nil || o.APIVersion != "asservat.io/v1alpha1" || o.Kind != "AccessBinding" {
		return fail()
	}
	m, err := decodeMetadata(o.Metadata, false)
	if err != nil || m.Namespace != w.client.control.Name {
		return fail()
	}
	ref := value.Resource{ClusterID: w.client.clusterID, Namespace: m.Namespace, NamespaceUID: w.client.control.UID, Kind: "AccessBinding", Name: m.Name, UID: m.UID, ResourceVersion: m.RV, Generation: m.Generation, Deleting: m.Deleting}
	binding, err := w.client.validator.binding(o, ref)
	if err != nil {
		return fail()
	}
	return value.BindingEvent{Type: event.Type, ResourceVersion: m.RV, Binding: &binding}, nil
}
