package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ConnectorWorkload is the connector's own Helm-rendered workload: the names
// from its configuration and the UIDs read by name once at process start.
// Helm keeps the objects across upgrades; a recreated object fails the
// process's checks until it restarts. Digest is the deterministic workload
// protection digest the hub pins (ConnectorWorkloadDigest).
type ConnectorWorkload struct {
	Namespace, NamespaceUID   string
	Account, AccountUID       string
	Deployment, DeploymentUID string
	Digest                    artifact.Digest
}

// ReadConnectorWorkload resolves the UIDs under the connector's own RBAC
// (get on its namespace, account and Deployment).
func ReadConnectorWorkload(ctx context.Context, config *rest.Config, clusterID, namespace, account, deployment string) (ConnectorWorkload, error) {
	var zero ConnectorWorkload
	if ctx == nil || config == nil || !authorization.UUID(clusterID) || len(validation.IsDNS1123Label(namespace)) != 0 || len(validation.IsDNS1123Subdomain(account)) != 0 || len(validation.IsDNS1123Subdomain(deployment)) != 0 {
		return zero, cfg.ErrInvalid
	}
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		return zero, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	ns, err := api.CoreV1().Namespaces().Get(call, namespace, meta.GetOptions{})
	if err != nil || ns.DeletionTimestamp != nil {
		return zero, cfg.ErrUnavailable
	}
	sa, err := api.CoreV1().ServiceAccounts(namespace).Get(call, account, meta.GetOptions{})
	if err != nil || sa.DeletionTimestamp != nil {
		return zero, cfg.ErrUnavailable
	}
	d, err := api.AppsV1().Deployments(namespace).Get(call, deployment, meta.GetOptions{})
	if err != nil || d.DeletionTimestamp != nil {
		return zero, cfg.ErrUnavailable
	}
	out := ConnectorWorkload{Namespace: namespace, NamespaceUID: string(ns.UID), Account: account, AccountUID: string(sa.UID), Deployment: deployment, DeploymentUID: string(d.UID), Digest: ConnectorWorkloadDigest(clusterID, namespace, deployment)}
	for _, id := range []string{out.NamespaceUID, out.AccountUID, out.DeploymentUID} {
		if !authorization.UUID(id) {
			return zero, cfg.ErrUnavailable
		}
	}
	return out, nil
}

// matches checks that the workload names the client's namespace and the
// profile's Deployment and account.
func (w ConnectorWorkload) matches(c *PermissionClient, namespace, account, deployment string) bool {
	return c != nil && c.control.Name == w.Namespace && c.control.UID == w.NamespaceUID && namespace == w.Namespace && account == w.Account && deployment == w.Deployment && w.Digest == ConnectorWorkloadDigest(c.clusterID, w.Namespace, w.Deployment)
}

// ReadCollectorNamespace resolves the collector namespace's UID by name for
// the node attester's client (get on that one namespace).
func ReadCollectorNamespace(ctx context.Context, config *rest.Config, namespace string) (cfg.NamespaceRef, error) {
	if ctx == nil || config == nil || len(validation.IsDNS1123Label(namespace)) != 0 {
		return cfg.NamespaceRef{}, cfg.ErrInvalid
	}
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		return cfg.NamespaceRef{}, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	ns, err := api.CoreV1().Namespaces().Get(call, namespace, meta.GetOptions{})
	if err != nil || ns.DeletionTimestamp != nil || !authorization.UUID(string(ns.UID)) {
		return cfg.NamespaceRef{}, cfg.ErrUnavailable
	}
	return cfg.NamespaceRef{Name: namespace, UID: string(ns.UID)}, nil
}
