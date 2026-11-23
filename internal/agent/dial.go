package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// A packet capture of a pod through which the agent's own connection to
// the hub passes (the hub's pod, or a pod on the host's network) would
// record its own upload, which makes more packets to upload. So the agent
// dials the hub from a few fixed source ports, and every capture leaves
// those out.
//
// The ports lie above Linux's default range for outgoing connections
// (32768 to 60999), so no other program's connection uses them unless the
// node is configured otherwise. An agent holds its stream and the uploads
// of the recordings that run at once; 64 ports are far more than that, and
// beyond them it dials like any program.
const hubPortFirst, hubPortLast = 61000, 61063

// ownTraffic is the tcpdump expression for the agent's connections to the hub.
var ownTraffic = fmt.Sprintf("tcp portrange %d-%d", hubPortFirst, hubPortLast)

// withoutOwnTraffic returns a capture filter that also leaves out the
// agent's own connections to the hub.
func withoutOwnTraffic(filter string) string {
	if filter == "" {
		return "not (" + ownTraffic + ")"
	}
	return "(" + filter + ") and not (" + ownTraffic + ")"
}

var nextHubPort atomic.Uint32

// DialHub connects to the hub from one of the agent's source ports. It is
// the DialContext of the agent's HTTP transport.
func DialHub(ctx context.Context, network, address string) (net.Conn, error) {
	return dialHub(ctx, network, address, hubDialWait)
}

// hubDialWait is how long a connection to the hub may take to come about.
// The kernel tries for two minutes to reach an address that does not
// answer, as the hub's does while its pod is replaced, and the node is not
// reachable for captures all that time; the agent tries anew by itself
// after a second or more.
const hubDialWait = 10 * time.Second

func dialHub(ctx context.Context, network, address string, wait time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	const ports = hubPortLast - hubPortFirst + 1
	for range ports {
		port := hubPortFirst + int(nextHubPort.Add(1)%ports)
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{Port: port}, Control: func(_, _ string, c syscall.RawConn) error {
			// A port whose last connection just closed can be bound again.
			var failed error
			err := c.Control(func(fd uintptr) { failed = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1) })
			return errors.Join(err, failed)
		}}
		conn, err := dialer.DialContext(ctx, network, address)
		// The port is taken, or its last connection to this address still lingers: the next one.
		if errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EADDRNOTAVAIL) {
			continue
		}
		return conn, err
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}
