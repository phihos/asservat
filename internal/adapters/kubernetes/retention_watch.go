package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	port "asservat.local/asservat/internal/application/privacy"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	privacy "asservat.local/asservat/internal/domain/privacy"
)

type retentionPolicyWatch struct {
	client  *RetentionClient
	decoder *permissionWatchEvents
	cancel  context.CancelFunc
}

func (w *retentionPolicyWatch) Close() { w.cancel(); w.decoder.Close() }

// WatchRetentionPolicies watches from rv until the API server ends the
// request (io.EOF from Next).
func (c *RetentionClient) WatchRetentionPolicies(ctx context.Context, rv string) (port.RetentionWatch, error) {
	if !identity.Text(rv, 128) {
		return nil, value.ErrInvalid
	}
	stream, cancel, err := c.client.openWatch(ctx, c.client.listPath("evidenceretentionpolicies"), rv, false)
	if err != nil {
		return nil, err
	}
	return &retentionPolicyWatch{c, stream, cancel}, nil
}

func (w *retentionPolicyWatch) Next(ctx context.Context) (port.RetentionEvent, error) {
	stop := context.AfterFunc(ctx, w.Close)
	defer stop()
	event, err := w.decoder.next()
	if err != nil {
		if ctx.Err() == nil && errors.Is(err, io.EOF) {
			return port.RetentionEvent{}, io.EOF
		}
		return port.RetentionEvent{}, value.ErrUnavailable
	}
	o, err := objectEnvelope(event.Object.Raw)
	if err != nil || o.APIVersion != "asservat.io/v1alpha1" || o.Kind != "EvidenceRetentionPolicy" {
		// ERROR events (for example 410 Gone) carry a Status: list again.
		return port.RetentionEvent{}, value.ErrChanged
	}
	if event.Type == "BOOKMARK" {
		var metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		}
		if json.Unmarshal(o.Metadata, &metadata) != nil || !identity.Text(metadata.ResourceVersion, 128) {
			return port.RetentionEvent{}, value.ErrChanged
		}
		return port.RetentionEvent{Type: event.Type, ResourceVersion: metadata.ResourceVersion}, nil
	}
	if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
		return port.RetentionEvent{}, value.ErrChanged
	}
	m, err := decodeMetadata(o.Metadata, false)
	if err != nil || m.Namespace != w.client.client.control.Name {
		return port.RetentionEvent{}, value.ErrChanged
	}
	out := port.RetentionEvent{Type: event.Type, ResourceVersion: m.RV, Policy: privacy.ScopedPolicy{Name: m.Name, Policy: privacy.Policy{Revision: identity.Revision{UID: m.UID, Generation: m.Generation}}}}
	if event.Type == "DELETED" {
		return out, nil
	}
	ref := value.Resource{ClusterID: w.client.client.clusterID, Namespace: m.Namespace, NamespaceUID: w.client.client.control.UID, Kind: "EvidenceRetentionPolicy", Name: m.Name, UID: m.UID, ResourceVersion: m.RV, Generation: m.Generation, Deleting: m.Deleting}
	out.Policy = w.client.policy(o, ref)
	return out, nil
}
