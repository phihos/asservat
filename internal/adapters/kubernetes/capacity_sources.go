package kubernetes

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// CapacitySourceNames are the fixed names derived from the installation.
func CapacitySourceNames(installation string) (guard, namespaceGuard, probeNamespace, processingSource, processingGuard string) {
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	return prefix + "-capacity-guard", prefix + "-capacity-ns-guard", prefix + "-capacity-probe", prefix + "-processing-source", prefix + "-processing-guard"
}

// ReadStoragePoolUID reads the operator-created EvidenceStoragePool's UID,
// which the capacity qualification binds as the system pool.
func ReadStoragePoolUID(ctx context.Context, config *rest.Config, namespace, name string) (string, error) {
	api, err := installerAPI(config)
	if err != nil || ctx == nil {
		return "", cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	raw, err := api.CoreV1().RESTClient().Get().AbsPath("/apis/asservat.io/v1alpha1/namespaces/" + namespace + "/evidencestoragepools/" + name).DoRaw(call)
	if err != nil {
		return "", cfg.ErrUnavailable
	}
	var pool struct {
		Metadata struct {
			Name, Namespace, UID string
			DeletionTimestamp    *meta.Time `json:"deletionTimestamp"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &pool) != nil || pool.Metadata.Name != name || pool.Metadata.Namespace != namespace || !authorization.UUID(pool.Metadata.UID) || pool.Metadata.DeletionTimestamp != nil {
		return "", cfg.ErrChanged
	}
	return pool.Metadata.UID, nil
}
