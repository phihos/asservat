package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

// ObjectUID reads one object's metadata.uid by API path under ordinary RBAC
// (Helm-native startup, field class N). The value keys SQL rows; reading it
// proves nothing about who may write the object.
func ObjectUID(ctx context.Context, config *rest.Config, path string) (string, error) {
	api, err := newBoundedAPI(config)
	if err != nil {
		return "", err
	}
	return ObjectUIDFrom(ctx, &PermissionClient{api: api, now: time.Now}, path)
}

// NamespaceUID reads the named namespace's UID.
func NamespaceUID(ctx context.Context, config *rest.Config, namespace string) (string, error) {
	if len(validation.IsDNS1123Label(namespace)) != 0 {
		return "", value.ErrInvalid
	}
	return ObjectUID(ctx, config, "/api/v1/namespaces/"+namespace)
}

// ConfigMapUID reads the UID of a ConfigMap in the client's namespace.
func ConfigMapUID(ctx context.Context, config *rest.Config, namespace, name string) (string, error) {
	if len(validation.IsDNS1123Label(namespace)) != 0 || len(validation.IsDNS1123Subdomain(name)) != 0 {
		return "", value.ErrInvalid
	}
	return ObjectUID(ctx, config, "/api/v1/namespaces/"+namespace+"/configmaps/"+name)
}

// NewNamedClusterCatalogSource reads the cluster catalog ConfigMap under
// ordinary RBAC; uid is the object's UID as read by name at startup, so a
// replaced catalog reads as changed.
func NewNamedClusterCatalogSource(client *PermissionClient, name, uid string) (*ClusterCatalogSource, error) {
	if client == nil || !installationRefValid(name, uid) || !authorization.UUID(uid) {
		return nil, artifact.ErrInvalid
	}
	return &ClusterCatalogSource{client: client, name: name, uid: uid}, nil
}

// ReadWorkerProfile reads the worker profile ConfigMap name of the client's
// namespace with the worker configuration source's own parse; installation
// and epoch are the IDs Secret's. The profile only selects; consumers still
// require SQL's current audited revision to equal it (ADR-070).
func ReadWorkerProfile(ctx context.Context, client *PermissionClient, name, installation, epoch string) (authorization.DownloadWorkerProfile, error) {
	var zero authorization.DownloadWorkerProfile
	if client == nil || ctx == nil || len(validation.IsDNS1123Subdomain(name)) != 0 {
		return zero, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	uid, err := ObjectUIDFrom(ctx, client, "/api/v1/namespaces/"+client.control.Name+"/configmaps/"+name)
	if err != nil {
		return zero, err
	}
	data, _, err := client.installationConfig(ctx, name, uid)
	if err != nil || len(data) != 1 {
		return zero, artifact.ErrInvalid
	}
	out, err := workerConfiguration(ctx, client, []byte(data["worker-profile.json"]), uid, installation, epoch)
	if err != nil {
		return zero, err
	}
	return out.Profile, nil
}

// ObjectUIDFrom is ObjectUID over an existing client's transport.
func ObjectUIDFrom(ctx context.Context, client *PermissionClient, path string) (string, error) {
	if client == nil {
		return "", value.ErrInvalid
	}
	b, err := client.raw(ctx, path, nil)
	if err != nil {
		return "", err
	}
	defer clear(b)
	var object struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if json.Unmarshal(b, &object) != nil || !authorization.UUID(object.Metadata.UID) {
		return "", value.ErrInvalid
	}
	return object.Metadata.UID, nil
}
