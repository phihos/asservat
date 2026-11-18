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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) || errors.Is(err, io.ErrUnexpectedEOF) {
			return event, value.ErrInvalid
		}
		return event, err
	}
	d.limit.N += d.json.InputOffset() - start
	if err = permissionJSON(data, permissionPageBytes, 0); err != nil {
		if errors.Is(err, value.ErrLimit) {
			return event, err
		}
		return event, value.ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 2 || fields["type"] == nil || fields["object"] == nil || json.Unmarshal(fields["type"], &event.Type) != nil {
		return event, value.ErrInvalid
	}
	event.Object.Raw = fields["object"]
	return event, nil
}

// openWatch bounds the opening request. Once opened, the caller owns the
// sustained stream; each event is framed separately.
func (c *PermissionClient) openWatch(ctx context.Context, path, rv string, metadataOnly bool) (*permissionWatchEvents, context.CancelFunc, error) {
	if !identity.Text(rv, 128) || rv == "0" {
		return nil, nil, value.ErrInvalid
	}
	ctx, cancel := context.WithCancel(ctx)
	opening := time.AfterFunc(5*time.Second, cancel)
	defer opening.Stop()
	r := c.watchAPI.Get().AbsPath(path).MaxRetries(0).Param("watch", "true").Param("resourceVersion", rv).Param("allowWatchBookmarks", "true")
	if metadataOnly {
		r.SetHeader("Accept", "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1")
	}
	body, err := r.Stream(ctx)
	if err != nil {
		mapped := permissionError(ctx, err)
		if apierrors.IsGone(err) || apierrors.IsResourceExpired(err) {
			mapped = value.ErrChanged
		}
		cancel()
		return nil, nil, mapped
	}
	return newPermissionWatchEvents(body), cancel, nil
}

// WatchConfiguration follows metadata from the same LIST used for acceptance.
// A closed channel requires a new baseline. Normal EOF resumes at the last
// delivered resourceVersion.
func (c *PermissionClient) WatchConfiguration(ctx context.Context, resource, rv string) (port.SettingsWatch, error) {
	if resource != "accessbindings" && resource != "clusteraccessbindings" && resource != "permissionsources" {
		return port.SettingsWatch{}, value.ErrInvalid
	}
	path := c.listPath(resource)
	stream, cancel, err := c.openWatch(ctx, path, rv, true)
	if err != nil {
		return port.SettingsWatch{}, err
	}
	changed := make(chan struct{}, 1)
	lost := make(chan struct{})
	go func() {
		defer close(lost)
		for {
			event, err := stream.next()
			if err != nil {
				cancel()
				stream.Close()
				if !errors.Is(err, io.EOF) || ctx.Err() != nil {
					return
				}
				stream, cancel, err = c.openWatch(ctx, path, rv, true)
				if err != nil {
					return
				}
				continue
			}
			var obj metav1.PartialObjectMetadata
			if json.Unmarshal(event.Object.Raw, &obj) != nil || !identity.Text(obj.ResourceVersion, 128) {
				cancel()
				stream.Close()
				return
			}
			rv = obj.ResourceVersion
			switch event.Type {
			case "BOOKMARK":
				continue
			case "ADDED", "MODIFIED", "DELETED":
				select {
				case changed <- struct{}{}:
				default:
				}
				continue
			}
			cancel()
			stream.Close()
			return
		}
	}()
	return port.SettingsWatch{Changed: changed, Lost: lost}, nil
}

type permissionBindingWatch struct {
	client  *PermissionClient
	decoder *permissionWatchEvents
	cancel  context.CancelFunc
	mu      sync.Mutex
}

func (w *permissionBindingWatch) Close() { w.cancel(); w.decoder.Close() }
func (c *PermissionClient) WatchBindings(ctx context.Context, rv string) (port.BindingWatch, error) {
	stream, cancel, err := c.openWatch(ctx, c.listPath("accessbindings"), rv, false)
	if err != nil {
		return nil, err
	}
	return &permissionBindingWatch{client: c, decoder: stream, cancel: cancel}, nil
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
