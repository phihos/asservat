package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

// UIDReader reads metadata.uid of named objects with the caller's own token
// (Helm-native installation: UIDs that SQL keys on are read by name at
// startup, never pinned or compared).
type UIDReader struct{ api rest.Interface }

func NewUIDReader(config *rest.Config) (*UIDReader, error) {
	api, err := newBoundedAPI(config)
	if err != nil {
		return nil, err
	}
	return &UIDReader{api}, nil
}

// Namespace returns the UID of a namespace.
func (r *UIDReader) Namespace(ctx context.Context, name string) (string, error) {
	if len(validation.IsDNS1123Label(name)) != 0 {
		return "", value.ErrInvalid
	}
	return r.uid(ctx, "/api/v1/namespaces/"+name)
}

// Object returns the UID of a namespaced core or apps object; kind is the
// plural resource path segment ("configmaps", "serviceaccounts") and group
// is "" for core or "apps".
func (r *UIDReader) Object(ctx context.Context, group, resource, namespace, name string) (string, error) {
	if len(validation.IsDNS1123Label(namespace)) != 0 || len(validation.IsDNS1123Subdomain(name)) != 0 || len(validation.IsDNS1123Label(resource)) != 0 {
		return "", value.ErrInvalid
	}
	base := "/api/v1"
	if group != "" {
		base = "/apis/" + group + "/v1"
	}
	return r.uid(ctx, base+"/namespaces/"+namespace+"/"+resource+"/"+name)
}

func (r *UIDReader) uid(ctx context.Context, path string) (string, error) {
	if r == nil || ctx == nil {
		return "", value.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	raw, err := r.api.Get().AbsPath(path).MaxRetries(0).DoRaw(call)
	defer clear(raw)
	if err != nil {
		return "", errors.Join(value.ErrUnavailable, err)
	}
	var object struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if len(raw) > 4<<20 || json.Unmarshal(raw, &object) != nil || !authorization.UUID(object.Metadata.UID) {
		return "", value.ErrChanged
	}
	return object.Metadata.UID, nil
}
