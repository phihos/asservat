package integration

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// Only an owned fixture tunnel: Chromium keeps the actual installed HTTPS
// origin while reaching its host-forwarded address, as the Go native clients
// already do. No response data, authority or credentials are manufactured.
func installedHistoryBrowserTunnel(t *testing.T, parent context.Context, origin, address string) string {
	t.Helper()
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		t.Fatal("invalid installed browser origin")
	}
	authority := u.Host
	if u.Port() == "" {
		authority = net.JoinHostPort(u.Hostname(), "443")
	}
	ctx, cancel := context.WithCancel(parent)
	var joined sync.WaitGroup
	slots := make(chan struct{}, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != authority {
			http.Error(w, "fixture destination refused", http.StatusForbidden)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "fixture capacity", http.StatusServiceUnavailable)
			return
		}
		joined.Add(1)
		defer joined.Done()
		remote, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
		if err != nil {
			http.Error(w, "fixture endpoint unavailable", http.StatusBadGateway)
			return
		}
		defer remote.Close()
		local, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer local.Close()
		until := time.Now().Add(5 * time.Minute)
		if end, ok := ctx.Deadline(); ok && end.Before(until) {
			until = end
		}
		_ = local.SetDeadline(until)
		_ = remote.SetDeadline(until)
		closed := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { defer close(closed); _ = local.Close(); _ = remote.Close() })
		defer func() {
			if !stop() {
				<-closed
			}
		}()
		if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(remote, buffered); _ = remote.Close(); close(done) }()
		_, _ = io.Copy(local, remote)
		_ = local.Close()
		_ = remote.Close()
		<-done
	}))
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.MaxHeaderBytes = 8 << 10
	server.Start()
	t.Cleanup(func() { cancel(); server.Close(); joined.Wait() })
	return server.URL
}
