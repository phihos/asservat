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
)

var _ port.BindingWatcher = (*PermissionClient)(nil)

// JSON values on a watch can span HTTP chunks or arrive together. Limit
// reads to one event, replenishing only the bytes the decoder consumed.
// Bytes buffered ahead for the next event remain charged to that event.
type permissionWatchEvents struct {
	io.Closer
	limit *io.LimitedReader
	json  *json.Decoder
}

func newPermissionWatchEvents(body io.ReadCloser) *permissionWatchEvents {
	r := &io.LimitedReader{R: body, N: permissionPageBytes + 1}
	return &permissionWatchEvents{body, r, json.NewDecoder(r)}
}

func (d *permissionWatchEvents) next() (event metav1.WatchEvent, err error) {
	start := d.json.InputOffset()
	var data json.RawMessage
	if err = d.json.Decode(&data); err != nil {
		if d.limit.N == 0 {
			return event, value.ErrLimit
		}
		return event, err
	}
	d.limit.N += d.json.InputOffset() - start
	if err = permissionJSON(data, permissionPageBytes, 131072); err != nil {
		return event, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 2 || fields["type"] == nil || fields["object"] == nil || json.Unmarshal(fields["type"], &event.Type) != nil {
		return event, value.ErrUnavailable
	}
	event.Object.Raw = fields["object"]
	return event, nil
}

type permissionBindingWatch struct {
	client  *PermissionClient
	decoder *permissionWatchEvents
	cancel  context.CancelFunc
	mu      sync.Mutex
}

func (w *permissionBindingWatch) Close() { w.cancel(); w.decoder.Close() }
func (c *PermissionClient) WatchBindings(ctx context.Context, rv string) (port.BindingWatch, error) {
	if !identity.Text(rv, 128) || rv == "0" {
		return nil, value.ErrInvalid
	}
	ctx, cancel := context.WithCancel(ctx)
	// Bound establishing the watch; its healthy stream stays open until an
	// API watch restart or caller cancellation.
	opening := time.AfterFunc(5*time.Second, cancel)
	defer opening.Stop()
	start := c.now()
	ns, err := c.namespace(ctx, c.control)
	if err != nil || ns.Deleting {
		cancel()
		return nil, value.ErrChanged
	}
	r := c.watchAPI.Get().AbsPath(c.listPath("accessbindings")).MaxRetries(0).Param("watch", "true").Param("resourceVersion", rv).Param("allowWatchBookmarks", "true")
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
	return &permissionBindingWatch{client: c, decoder: newPermissionWatchEvents(body), cancel: cancel}, nil
}
func (w *permissionBindingWatch) Next(ctx context.Context) (value.BindingEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() != nil {
		return value.BindingEvent{}, ctx.Err()
	}
	stop := context.AfterFunc(ctx, w.Close)
	defer stop()
	event, err := w.decoder.next()
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
	if err != nil {
		return fail()
	}
	// ADR-329: a binding first seen here is placed in its namespace.
	namespace, err := w.client.placeBinding(ctx, m)
	if err != nil {
		return fail()
	}
	ref := value.Resource{ClusterID: w.client.clusterID, Namespace: m.Namespace, NamespaceUID: namespace.UID, Kind: "AccessBinding", Name: m.Name, UID: m.UID, ResourceVersion: m.RV, Generation: m.Generation, Deleting: m.Deleting}
	binding := w.client.validator.observedBinding(o, ref)
	return value.BindingEvent{Type: event.Type, ResourceVersion: m.RV, Binding: &binding}, nil
}
