//go:build !gadget || !linux

package gadget

import (
	"context"
	"net"
	"net/netip"
)

func DialProfile(context.Context, string, netip.Addr, uint16) (net.Conn, error) {
	return nil, ErrEngineUnavailable
}

func ProfileDialAvailable() bool { return false }
