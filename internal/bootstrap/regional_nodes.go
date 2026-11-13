package bootstrap

import (
	"context"
	"net"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// regionalNodes is the connector's optional ADR-246 node listener. Its
// Kubernetes reads (TokenReview, collector Pods/DaemonSet, Nodes) and the
// listener objects' get/update use the connector account; the chart grants
// exactly those.
type regionalNodes struct {
	server   *NodeChannelServer
	listener net.Listener
}

func newRegionalNodes(ctx context.Context, c regionalConfig, in *providerInputs) (*regionalNodes, error) {
	n := c.Collector
	config := in.kubernetes(contracts.ConnectorKubeTokenFile)
	server, err := kube.NodeListener{Namespace: c.Namespace, Secret: n.ListenerSecret, RootNamespace: n.Namespace, RootConfig: n.RootConfigMap, ServerName: n.ServerName}.Ensure(ctx, config)
	if err != nil {
		return nil, &fixedStepError{"node-listener", err}
	}
	workload, err := kube.ReadCollectorNamespace(ctx, config, n.Namespace)
	if err != nil {
		return nil, &fixedStepError{"node-namespace", err}
	}
	client, err := kube.NewPermissionClient(config, c.ClusterID, workload, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	attester, err := kube.NewNodeAttester(client, n.DaemonSet, n.ServiceAccount)
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
