package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

// ReadSetupFleetSource reads the release namespace and the fleet ConfigMap by
// name with two plain GETs and decodes the fleet settings with the runtime's
// own decoder. The namespace and ConfigMap UIDs are taken from the reads.
func ReadSetupFleetSource(ctx context.Context, config *rest.Config, clusterID, namespace, configMap, installation, issuerEpoch string) (fleet.Administration, value.NamespaceRef, error) {
	var zero fleet.Administration
	if ctx == nil || config == nil || !authorization.UUID(clusterID) || len(validation.IsDNS1123Label(namespace)) != 0 || len(validation.IsDNS1123Subdomain(configMap)) != 0 || !authorization.UUID(installation) {
		return zero, value.NamespaceRef{}, value.ErrInvalid
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		return zero, value.NamespaceRef{}, err
	}
	uid := func(path string) (string, error) {
		raw, err := api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
		if err != nil {
			return "", permissionError(ctx, err)
		}
		o, err := objectEnvelope(raw)
		if err != nil {
			return "", err
		}
		m, err := decodeMetadata(o.Metadata, true)
		if err != nil {
			return "", err
		}
		return m.UID, nil
	}
	nsUID, err := uid("/api/v1/namespaces/" + namespace)
	if err != nil {
		return zero, value.NamespaceRef{}, err
	}
	control := value.NamespaceRef{Name: namespace, UID: nsUID}
	client, err := NewPermissionClient(config, clusterID, control, time.Now)
	if err != nil {
		return zero, control, err
	}
	sourceUID, err := uid("/api/v1/namespaces/" + namespace + "/configmaps/" + configMap)
	if err != nil {
		return zero, control, err
	}
	settings, err := NewFleetSettingsClient(client, configMap, sourceUID, installation, issuerEpoch)
	if err != nil {
		return zero, control, err
	}
	a, err := settings.FleetAdministration(ctx)
	return a, control, err
}
