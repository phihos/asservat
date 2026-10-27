package bootstrap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/transport/node"
	"golang.org/x/net/netutil"
)

// NodeChannelServer is the connector's node listener (ADR-246, I-02): TLS
// 1.3 with the installation-provided server certificate, node client
// certificates from a per-process in-memory issuer, and the in-memory node
// registry. Each node holds at most one long poll and one status request.
type NodeChannelServer struct {
	Channel *delivery.NodeChannel
	issuer  *mtls.NodeIssuer
	handler http.Handler
	server  tls.Certificate
}

// nodeChannelConnections bounds open connections: two per node plus slack.
const nodeChannelConnections = 2*delivery.MaxNodes + 16

func NewNodeChannelServer(clusterID string, attester delivery.NodeAttester, server tls.Certificate, out io.Writer, now func() time.Time) (*NodeChannelServer, error) {
	if attester == nil || len(server.Certificate) == 0 || out == nil || now == nil {
		return nil, delivery.ErrNodeInvalid
	}
	issuer, err := mtls.NewNodeIssuer(clusterID, now)
	if err != nil {
		return nil, err
	}
	ch, err := delivery.NewNodeChannel(attester, issuer, now, func(v delivery.NodeView) { fmt.Fprintln(out, describeNodeView(v)) })
	if err != nil {
		return nil, err
	}
	h, err := node.NewHandler(ch)
	if err != nil {
		return nil, err
	}
	return &NodeChannelServer{Channel: ch, issuer: issuer, handler: h, server: server}, nil
}

// describeNodeView is the connector's operator line for one node change:
// identities, closed facts and reasons only.
func describeNodeView(v delivery.NodeView) string {
	id := v.Identity
	line := fmt.Sprintf("connector node %s (uid %s) pod %s epoch %s runtime %q", id.NodeName, id.NodeUID, id.PodName, id.Epoch, id.Runtime)
	if v.Report == nil {
		return line + ": enrolled, no report yet"
	}
	parts := []string{}
	for _, m := range v.Report.Mechanisms {
		reasons := make([]string, len(m.Reasons))
		for i, r := range m.Reasons {
			reasons[i] = string(r)
		}
		parts = append(parts, fmt.Sprintf("%s %s [%s]", m.Mechanism, m.Adapter, strings.Join(reasons, ",")))
	}
	f := v.Report.Facts
	return fmt.Sprintf("%s: report %d kernel %s btf %s tcx %s cgroup2 %s; %s", line, v.Report.Sequence, f.KernelRelease, f.BTF, f.TCX, f.CgroupV2, strings.Join(parts, "; "))
}

// Serve runs the listener until ctx ends, then shuts down within five seconds.
func (s *NodeChannelServer) Serve(ctx context.Context, l net.Listener) error {
	if s == nil || ctx == nil || l == nil {
		return delivery.ErrNodeInvalid
	}
	srv := &http.Server{Handler: s.handler, TLSConfig: s.issuer.ServerConfig(s.server),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: collector.PollHold + 10*time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }}
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		close(stopped)
	}()
	err := srv.ServeTLS(netutil.LimitListener(l, nodeChannelConnections), "", "")
	if errors.Is(err, http.ErrServerClosed) {
		<-stopped
		return nil
	}
	return err
}
