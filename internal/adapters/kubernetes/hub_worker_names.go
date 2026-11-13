package kubernetes

import (
	"context"

	value "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/rest"
)

// ReadNamespaceUID reads a namespace's UID by name: an N value of the
// Helm-native installation, used where SQL rows key on it.
func ReadNamespaceUID(ctx context.Context, config *rest.Config, name string) (string, error) {
	api, err := newBoundedAPI(config)
	if err != nil || ctx == nil {
		return "", value.ErrInvalid
	}
	b, err := api.Get().AbsPath("/api/v1/namespaces/" + name).MaxRetries(0).Do(ctx).Raw()
	if err != nil {
		return "", value.ErrUnavailable
	}
	o, err := objectEnvelope(b)
	if err != nil || o.APIVersion != "v1" || o.Kind != "Namespace" {
		return "", value.ErrUnavailable
	}
	m, err := decodeMetadata(o.Metadata, true)
	if err != nil || m.Name != name || m.UID == "" {
		return "", value.ErrUnavailable
	}
	return m.UID, nil
}

// ConfigMapUID reads a ConfigMap's UID by name in the client's control
// namespace (an N value; the source readers still compare it on every read).
func (c *PermissionClient) ConfigMapUID(ctx context.Context, name string) (string, error) {
	if c == nil || ctx == nil {
		return "", value.ErrInvalid
	}
	b, err := c.raw(ctx, "/api/v1/namespaces/"+c.control.Name+"/configmaps/"+name, nil)
	if err != nil {
		return "", err
	}
	o, err := objectEnvelope(b)
	if err != nil || o.APIVersion != "v1" || o.Kind != "ConfigMap" {
		return "", value.ErrUnavailable
	}
	m, err := decodeMetadata(o.Metadata, true)
	if err != nil || m.Name != name || m.UID == "" {
		return "", value.ErrUnavailable
	}
	return m.UID, nil
}
