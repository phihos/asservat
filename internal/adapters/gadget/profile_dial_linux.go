//go:build gadget && linux

package gadget

import (
	"asservat.local/asservat/internal/domain/authorization"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	networkns "github.com/vishvananda/netns"
)

// DialProfile opens exactly one TCP connection in the target Pod's current
// network namespace. It reads no credentials, performs no DNS lookup and never
// tries another Pod or address. The caller supplies an independently resolved
// endpoint and retains admission, deadline and response ownership.
func DialProfile(ctx context.Context, podUID string, address netip.Addr, port uint16) (net.Conn, error) {
	if ctx == nil || ctx.Err() != nil || !authorization.UUID(podUID) || !address.IsValid() || address.Zone() != "" || address.Is4In6() || port == 0 {
		return nil, ErrTargetNotFound
	}
	pid, err := podProcess("/proc", podUID)
	if err != nil {
		return nil, err
	}
	target, err := networkns.GetFromPid(pid)
	if err != nil {
		return nil, ErrTargetNotFound
	}
	defer target.Close()
	// Opening the namespace pins it even if the process exits. Recheck the
	// process's cgroup after opening so PID reuse cannot select another Pod.
	group, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil || !(bytes.Contains(group, []byte("pod"+podUID)) || bytes.Contains(group, []byte("pod"+strings.ReplaceAll(podUID, "-", "_")))) {
		return nil, ErrTargetNotFound
	}
	host, err := networkns.GetFromPid(1)
	if err != nil {
		return nil, ErrEngineUnavailable
	}
	defer host.Close()
	if target.Equal(host) {
		return nil, ErrTargetHostNetwork
	}
	type answer struct {
		connection net.Conn
		err        error
	}
	result := make(chan answer, 1)
	go func() {
		runtime.LockOSThread()
		original, err := networkns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			result <- answer{err: ErrEngineUnavailable}
			return
		}
		defer original.Close()
		if err = networkns.Set(target); err != nil {
			runtime.UnlockOSThread()
			result <- answer{err: ErrEngineUnavailable}
			return
		}
		var connection net.Conn
		if !address.IsLoopback() {
			addrs, e := net.InterfaceAddrs()
			found := false
			for _, a := range addrs {
				if p, e := netip.ParsePrefix(a.String()); e == nil && p.Addr() == address {
					found = true
				}
			}
			if e != nil || !found {
				err = ErrTargetNotFound
			}
		}
		if err == nil {
			network := "tcp4"
			if address.Is6() {
				network = "tcp6"
			}
			dialer := net.Dialer{}
			connection, err = dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), strconv.Itoa(int(port))))
		}
		if restore := networkns.Set(original); restore != nil {
			if connection != nil {
				_ = connection.Close()
				connection = nil
			}
			err = ErrEngineUnavailable
			// Returning with the thread locked retires that thread; never put a
			// thread still in the target namespace back in Go's scheduler pool.
		} else {
			runtime.UnlockOSThread()
		}
		if err != nil {
			err = fmt.Errorf("%w: profile connection", ErrEngineUnavailable)
		}
		result <- answer{connection, err}
	}()
	// Join even on cancellation: DialContext owns its cancellation and the
	// namespace handles cannot close while the thread still uses them.
	out := <-result
	if ctx.Err() != nil {
		if out.connection != nil {
			_ = out.connection.Close()
		}
		return nil, ctx.Err()
	}
	return out.connection, out.err
}

func ProfileDialAvailable() bool { return true }
