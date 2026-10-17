package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// ClusterCredentialSecret stores the ADR-168 key in exactly one named Secret
// with an installer-pinned UID, using resourceVersion compare-and-swap. The
// connector's account needs only get/update on this resource name.
type ClusterCredentialSecret struct {
	api                  rest.Interface
	namespace, name, uid string
}

var _ fleetapp.ClusterCredentialSecretStore = (*ClusterCredentialSecret)(nil)

const clusterCredentialSecretKey = "cluster-credential.json"

func NewClusterCredentialSecret(api rest.Interface, namespace, name, uid string) (*ClusterCredentialSecret, error) {
	if api == nil || !identity.Text(namespace, 63) || !identity.Text(name, 253) || !identity.Text(uid, 64) {
		return nil, value.ErrClusterCredentialDenied
	}
	return &ClusterCredentialSecret{api, namespace, name, uid}, nil
}

// NewClusterCredentialSecretForConfig uses the shared bounded API client
// (fixed timeout, 20 QPS/burst, no proxy or redirect) of the given identity.
func NewClusterCredentialSecretForConfig(config *rest.Config, namespace, name, uid string) (*ClusterCredentialSecret, error) {
	api, err := newBoundedAPI(config)
	if err != nil {
		return nil, value.ErrClusterCredentialDenied
	}
	return NewClusterCredentialSecret(api, namespace, name, uid)
}

func (s *ClusterCredentialSecret) path() string {
	return "/api/v1/namespaces/" + s.namespace + "/secrets/" + s.name
}

func (s *ClusterCredentialSecret) read(ctx context.Context) (*core.Secret, fleetapp.ClusterCredentialSecret, error) {
	var state fleetapp.ClusterCredentialSecret
	raw, err := s.api.Get().AbsPath(s.path()).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return nil, state, value.ErrClusterCredentialDenied
	}
	var object core.Secret
	if strictGuardJSON(raw, &object) != nil || object.UID != types.UID(s.uid) || object.Name != s.name || object.Namespace != s.namespace || !identity.Text(object.ResourceVersion, 128) {
		return nil, state, value.ErrClusterCredentialDenied
	}
	d := json.NewDecoder(bytes.NewReader(object.Data[clusterCredentialSecretKey]))
	d.DisallowUnknownFields()
	if d.Decode(&state) != nil || d.More() || !state.Valid() {
		return nil, fleetapp.ClusterCredentialSecret{}, value.ErrClusterCredentialDenied
	}
	return &object, state, nil
}

func (s *ClusterCredentialSecret) ReadClusterCredential(ctx context.Context) (fleetapp.ClusterCredentialSecret, string, error) {
	object, state, err := s.read(ctx)
	if err != nil {
		return state, "", err
	}
	for _, b := range object.Data {
		defer clear(b)
	}
	return state, object.ResourceVersion, nil
}

func (s *ClusterCredentialSecret) WriteClusterCredential(ctx context.Context, version string, next fleetapp.ClusterCredentialSecret) (string, error) {
	if !next.Valid() || !identity.Text(version, 128) {
		return "", value.ErrClusterCredentialDenied
	}
	object, _, err := s.read(ctx)
	if err != nil || object.ResourceVersion != version {
		return "", value.ErrClusterCredentialDenied
	}
	body, err := json.Marshal(next)
	if err != nil {
		return "", value.ErrClusterCredentialDenied
	}
	defer clear(body)
	update := object.DeepCopy()
	update.Data = map[string][]byte{clusterCredentialSecretKey: body}
	raw, err := s.api.Put().AbsPath(s.path()).Param("fieldValidation", "Strict").Body(update).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return "", value.ErrClusterCredentialDenied // a conflict or unknown outcome: reread before any request
	}
	var observed core.Secret
	if strictGuardJSON(raw, &observed) != nil || observed.UID != object.UID || observed.ResourceVersion == version || !identity.Text(observed.ResourceVersion, 128) || !bytes.Equal(observed.Data[clusterCredentialSecretKey], body) {
		return "", value.ErrClusterCredentialDenied
	}
	return observed.ResourceVersion, nil
}
