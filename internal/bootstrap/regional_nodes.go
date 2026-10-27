package bootstrap

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// regionalNodes is the connector's optional ADR-246 node listener. Its
// Kubernetes reads (TokenReview, collector Pods/DaemonSet, Nodes) use the
// observer account; the installer grants exactly those reads.
type regionalNodes struct {
	server   *NodeChannelServer
	listener net.Listener
}

func validRegionalCollector(c contracts.RegionalDeployment) bool {
	n := c.Collector
	return n == nil || (identity.Text(n.Namespace.Name, 63) && authorization.UUID(n.Namespace.UID) && identity.Text(n.DaemonSet, 253) && identity.Text(n.ServiceAccount, 253))
}

func newRegionalNodes(ctx context.Context, c contracts.RegionalDeployment, in *providerInputs) (*regionalNodes, error) {
	certPEM, err := in.read(ctx, contracts.RegionalNodeServerFile, 64<<10)
	if err != nil {
		return nil, err
	}
	keyPEM, err := in.read(ctx, contracts.RegionalNodeServerKeyFile, 16<<10)
	defer clear(keyPEM)
	if err != nil {
		return nil, err
	}
	server, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	client, err := kube.NewPermissionClient(in.kubernetes("kube-observer.token"), c.ClusterID, cfg.NamespaceRef{Name: c.Collector.Namespace.Name, UID: c.Collector.Namespace.UID}, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	attester, err := kube.NewNodeAttester(client, c.InstallationID, c.Collector.DaemonSet, c.Collector.ServiceAccount)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	s, err := NewNodeChannelServer(c.ClusterID, attester, server, os.Stderr, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	l, err := net.Listen("tcp", contracts.RegionalNodeListenAddress)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	return &regionalNodes{server: s, listener: l}, nil
}

func (n *regionalNodes) serve(ctx context.Context) error { return n.server.Serve(ctx, n.listener) }
func (n *regionalNodes) close()                          { _ = n.listener.Close() }
