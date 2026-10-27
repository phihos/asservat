package integration

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
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

func TestInstalledHistoryBrowserTunnelPinsDestinationAndJoinsCancellation(t *testing.T) {
	var seen atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		_, _ = io.WriteString(w, "actual owned TLS response")
	}))
	defer target.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	proxy := installedHistoryBrowserTunnel(t, ctx, "https://browser.synthetic.invalid", target.Listener.Addr().String())
	u, err := url.Parse(proxy)
	if err != nil {
		t.Fatal(err)
	}
	// The trust decision here is explicitly synthetic; the installed driver
	// separately uses the exact real session and fixed forwarded endpoint.
	transport := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("https://browser.synthetic.invalid/probe")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "actual owned TLS response" || seen.Load() != 1 {
		t.Fatal("proxy did not preserve actual server reply", err)
	}
	if response, err = client.Get("https://foreign.synthetic.invalid/probe"); err == nil {
		_ = response.Body.Close()
		t.Fatal("foreign destination accepted")
	}
	transport.CloseIdleConnections()
	cancel()
	if response, err = client.Get("https://browser.synthetic.invalid/probe"); err == nil {
		_ = response.Body.Close()
		t.Fatal("cancelled tunnel accepted another destination")
	}
}

type installedHistoryBrowserResult struct {
	Kind, GrantID, CaptureID, PreviewID, Digest, SettingsDigest string
	SourceExpiresAt                                             time.Time
}

// The only injected browser credential is the real HttpOnly Asservat session
// already issued by the installed Keycloak login. It crosses a private stdin
// pipe, never a command argument, report, page script or fixture authority row.
func installedRecorderHistoryBrowser(t *testing.T, ctx context.Context, browser *installedBrowser, address string, target map[string]string, source string, approve func(string)) installedHistoryBrowserResult {
	t.Helper()
	origin, err := url.Parse(browser.base)
	if err != nil || browser.client.Jar == nil {
		t.Fatal("installed history browser session missing")
	}
	type cookie struct {
		Name     string `json:"name"`
		Value    string `json:"value"`
		URL      string `json:"url"`
		HTTPOnly bool   `json:"httpOnly"`
		Secure   bool   `json:"secure"`
		SameSite string `json:"sameSite"`
	}
	var cookies []cookie
	for _, c := range browser.client.Jar.Cookies(origin) {
		cookies = append(cookies, cookie{c.Name, c.Value, browser.base, true, true, "Lax"})
	}
	if len(cookies) == 0 {
		t.Fatal("installed history browser has no original session")
	}
	proxy := installedHistoryBrowserTunnel(t, ctx, browser.base, address)
	config, err := json.Marshal(map[string]any{"origin": browser.base, "proxy": proxy, "cookies": cookies, "target": target, "sourceCaptureID": source})
	if err != nil || len(config) > 16<<10 {
		clear(config)
		t.Fatal("installed browser input bound", err)
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Minute)
	command := exec.CommandContext(call, "node", filepath.Join("..", "..", "web", "scripts", "installed-history-browser.mjs"))
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = 5 * time.Second
	in, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var diagnostic consoleBoundedOutput
	command.Stderr = &diagnostic
	if err = command.Start(); err != nil {
		cancel()
		clear(config)
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = in.Close()
		if command.ProcessState == nil {
			_ = command.Wait()
		}
	}()
	if _, err = in.Write(append(config, '\n')); err != nil {
		clear(config)
		t.Fatal("browser input", err)
	}
	clear(config)
	var result installedHistoryBrowserResult
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 1024), 8<<10)
	for scanner.Scan() {
		var event installedHistoryBrowserResult
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			t.Fatal("invalid browser fixture event")
		}
		switch event.Kind {
		case "review":
			if len(event.GrantID) != 36 || len(event.PreviewID) != 36 || len(event.Digest) != 64 {
				t.Fatal("browser review identity missing")
			}
			approve(event.GrantID)
			if _, err = io.WriteString(in, "approved\n"); err != nil {
				t.Fatal("browser continuation pipe", err)
			}
		case "captured":
			result = event
		default:
			t.Fatal("unexpected browser fixture event")
		}
	}
	if err = scanner.Err(); err != nil {
		t.Fatal("bounded browser result", err)
	}
	if err = command.Wait(); err != nil {
		t.Fatalf("installed React history workflow: %v\n%s", err, diagnostic.String())
	}
	if len(result.CaptureID) != 36 || result.CaptureID == source || len(result.GrantID) != 36 || result.SourceExpiresAt.IsZero() {
		t.Fatal("installed history browser did not complete")
	}
	return result
}
