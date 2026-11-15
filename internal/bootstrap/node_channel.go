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

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/transport/node"
	"golang.org/x/net/netutil"
)

// NodeChannelServer is the connector's node listener (ADR-246, I-02):
// HTTP/2 over TLS 1.3 with the installation-provided server certificate and
// the in-memory node registry. Each node holds one stream plus its uploads on
// one connection.
type NodeChannelServer struct {
	Channel *delivery.NodeChannel
	handler http.Handler
	server  tls.Certificate
}

// nodeChannelConnections bounds open connections: one per node plus slack
// for replacements.
const nodeChannelConnections = 2 * delivery.MaxNodes

func NewNodeChannelServer(attester delivery.NodeAttester, server tls.Certificate, out io.Writer, now func() time.Time) (*NodeChannelServer, error) {
	if attester == nil || len(server.Certificate) == 0 || out == nil || now == nil {
		return nil, delivery.ErrNodeInvalid
	}
	ch, err := delivery.NewNodeChannel(now, func(v delivery.NodeView) { fmt.Fprintln(out, describeNodeView(v)) })
	if err != nil {
		return nil, err
	}
	h, err := node.NewHandler(ch, attester)
	if err != nil {
		return nil, err
	}
	return &NodeChannelServer{Channel: ch, handler: h, server: server}, nil
}

// describeNodeView is the connector's operator line for one node change:
// identities, closed facts and reasons only.
func describeNodeView(v delivery.NodeView) string {
	id := v.Identity
	line := fmt.Sprintf("connector node %s (uid %s) pod %s runtime %q", id.NodeName, id.NodeUID, id.PodName, id.Runtime)
	if v.Report == nil {
		return line + ": connected, no report yet"
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
	return fmt.Sprintf("%s: report %d kernel %s btf %s tcx %s cgroup2 %s; %s", line, v.Reports, f.KernelRelease, f.BTF, f.TCX, f.CgroupV2, strings.Join(parts, "; "))
}

// Serve runs the listener until ctx ends, then shuts down within five seconds.
func (s *NodeChannelServer) Serve(ctx context.Context, l net.Listener) error {
	if s == nil || ctx == nil || l == nil {
		return delivery.ErrNodeInvalid
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	// Streams are long-lived, so there is no server-wide read or write
	// timeout: uploads set their own per-request deadline, HTTP/2 PING ends a
	// connection whose peer stopped answering and IdleTimeout closes idle ones.
	srv := &http.Server{Handler: s.handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{s.server}, MinVersion: tls.VersionTLS13},
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10, Protocols: protocols, HTTP2: &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: 15 * time.Second},
		ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }, ConnContext: node.ConnContext}
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
