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
	serializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/streaming"
)

var _ port.RetentionWatcher = (*RetentionClient)(nil)

type retentionPolicyWatch struct {
	client  *RetentionClient
	decoder streaming.Decoder
	cancel  context.CancelFunc
	mu      sync.Mutex
}

func (w *retentionPolicyWatch) Close() { w.cancel(); w.decoder.Close() }
func (c *RetentionClient) WatchRetentionPolicies(ctx context.Context, rv string) (port.RetentionWatch, error) {
	if !identity.Text(rv, 128) || rv == "0" {
		return nil, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	start := c.client.now()
	ns, err := c.client.namespace(ctx, c.client.control)
	if err != nil || ns.Deleting {
		cancel()
		return nil, value.ErrChanged
	}
	r := c.client.api.Get().AbsPath("/apis/asservat.io/v1alpha1/namespaces/"+c.client.control.Name+"/evidenceretentionpolicies").MaxRetries(0).Param("watch", "true").Param("resourceVersion", rv).Param("allowWatchBookmarks", "true").Param("timeoutSeconds", "3")
	body, err := r.Stream(ctx)
	if err != nil {
		mapped := permissionError(ctx, err)
		cancel()
		return nil, mapped
	}
	if err = c.client.current(ctx, start, 5*time.Second); err != nil {
		body.Close()
		cancel()
		return nil, err
	}
	return &retentionPolicyWatch{client: c, decoder: streaming.NewDecoder(serializer.Framer.NewFrameReader(body), permissionEventDecoder{}), cancel: cancel}, nil
}
func (w *retentionPolicyWatch) Next(ctx context.Context) (port.PolicyEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() != nil {
		return port.PolicyEvent{}, ctx.Err()
	}
	stop := context.AfterFunc(ctx, w.Close)
	defer stop()
	var event metav1.WatchEvent
	_, _, err := w.decoder.Decode(nil, &event)
	if err != nil || ctx.Err() != nil {
		w.Close()
		if ctx.Err() == nil && errors.Is(err, io.EOF) {
			return port.PolicyEvent{}, io.EOF
		}
		return port.PolicyEvent{}, value.ErrUnavailable
	}
	fail := func() (port.PolicyEvent, error) { w.Close(); return port.PolicyEvent{}, value.ErrChanged }
	if event.Type == "ERROR" {
		return fail()
	}
	if event.Type == "BOOKMARK" {
		wire, err := objectEnvelope(event.Object.Raw)
		var metadata map[string]json.RawMessage
		var rv string
		if err != nil || wire.APIVersion != "asservat.io/v1alpha1" || wire.Kind != "EvidenceRetentionPolicy" || json.Unmarshal(wire.Metadata, &metadata) != nil || json.Unmarshal(metadata["resourceVersion"], &rv) != nil || !identity.Text(rv, 128) {
			return fail()
		}
		// A bookmark resumes history but cannot renew complete-policy freshness.
		return port.PolicyEvent{Type: event.Type, ResourceVersion: rv}, nil
	}
	if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
		return fail()
	}
	o, err := objectEnvelope(event.Object.Raw)
	if err != nil || o.APIVersion != "asservat.io/v1alpha1" || o.Kind != "EvidenceRetentionPolicy" {
		return fail()
	}
	m, err := decodeMetadata(o.Metadata, false)
	if err != nil || m.Namespace != w.client.client.control.Name {
		return fail()
	}
	ref := value.Resource{ClusterID: w.client.client.clusterID, Namespace: m.Namespace, NamespaceUID: w.client.client.control.UID, Kind: "EvidenceRetentionPolicy", Name: m.Name, UID: m.UID, ResourceVersion: m.RV, Generation: m.Generation, Deleting: m.Deleting}
	policy, err := w.client.policy(o, ref)
	if err != nil {
		return fail()
	}
	return port.PolicyEvent{Type: event.Type, ResourceVersion: m.RV, Policy: &policy, Deleting: m.Deleting}, nil
}
