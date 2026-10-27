package integration

import (
	"asservat.local/asservat/internal/domain/artifact"
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

// Called from the already collector-qualified approved recording focus after
// its first real PCAPNG. The approval callback is the existing independently
// authenticated reviewer, never a fixture INSERT or a copied original grant.
func qualifyInstalledRecorderHistory(t *testing.T, ctx context.Context, browser *installedBrowser, address string, target map[string]string, sourceCapture, sourceGrant string, invoke func(string, any) (installedJourneyEnvelope, string), diagnose func(string), approve func(context.Context, string)) {
	t.Helper()
	type settings struct {
		CaptureID       string    `json:"capture_id"`
		Digest          string    `json:"settings_digest"`
		ExecutionDigest string    `json:"original_execution_digest"`
		ExpiresAt       time.Time `json:"expires_at"`
		Settings        struct {
			Composition struct {
				Authored struct {
					Components []struct {
						ProfileRef json.RawMessage `json:"profileRef"`
						Overrides  []struct {
							Field string          `json:"field"`
							Value json.RawMessage `json:"value"`
						} `json:"overrides"`
					} `json:"components"`
				} `json:"authored"`
				ResolvedProfiles json.RawMessage `json:"resolvedProfiles"`
			} `json:"profile_composition"`
		} `json:"settings"`
	}
	read := func(name string, args, out any) {
		t.Helper()
		var reply installedJourneyEnvelope
		status, code, err := installedJourneyRetryUnavailable(ctx, func() (string, string, error) {
			var code string
			reply, code = invoke(name, args)
			return reply.Status, code, nil
		})
		if err != nil || status != "ok" || code != "" || json.Unmarshal(reply.Data, out) != nil {
			if selected, ok := args.(map[string]string); ok {
				diagnose(selected["capture_id"])
			}
			t.Fatal("installed history MCP read", name, status, code, err)
		}
	}
	var source settings
	read("get_capture_settings", map[string]string{"capture_id": sourceCapture}, &source)
	if source.CaptureID != sourceCapture || source.Digest == "" || len(source.Settings.Composition.Authored.Components) != 1 || !time.Now().Before(source.ExpiresAt) {
		t.Fatal("original encrypted recording settings unavailable")
	}
	var requestedGrant string
	result := installedRecorderHistoryBrowser(t, ctx, browser, address, target, sourceCapture, func(approvalCtx context.Context, grant string) {
		if grant == sourceGrant || requestedGrant != "" {
			t.Fatal("repeat reused original approval or created multiple new reviews")
		}
		requestedGrant = grant
		approve(approvalCtx, grant)
	})
	if requestedGrant != result.GrantID || result.SettingsDigest != source.Digest || !result.SourceExpiresAt.Equal(source.ExpiresAt) || result.Digest == source.ExecutionDigest {
		t.Fatal("browser/MCP source or new review binding differs")
	}
	var progress struct {
		Phase        string `json:"phase"`
		CaseID       string `json:"case_id"`
		RepeatedFrom string `json:"repeated_from_capture_id"`
		HistoryState string `json:"history_state"`
	}
	read("get_capture", map[string]string{"capture_id": result.CaptureID}, &progress)
	if progress.Phase != "Succeeded" || progress.CaseID == "" || progress.RepeatedFrom != sourceCapture || progress.HistoryState != "available" {
		t.Fatal("repeat lineage/availability lost", progress)
	}
	var repeated settings
	read("get_capture_settings", map[string]string{"capture_id": result.CaptureID}, &repeated)
	if repeated.Digest == source.Digest || repeated.ExecutionDigest != result.Digest || repeated.ExpiresAt.After(source.ExpiresAt) || !time.Now().Before(repeated.ExpiresAt) || len(repeated.Settings.Composition.Authored.Components) != 1 {
		t.Fatal("edited settings lost identity/source cutoff")
	}
	old, next := source.Settings.Composition, repeated.Settings.Composition
	if string(old.Authored.Components[0].ProfileRef) != string(next.Authored.Components[0].ProfileRef) || string(old.ResolvedProfiles) != string(next.ResolvedProfiles) {
		t.Fatal("repeat silently upgraded a profile version/definition")
	}
	filter, window := false, false
	for _, edit := range next.Authored.Components[0].Overrides {
		filter = filter || edit.Field == "packetFilter" && string(edit.Value) == `"tcp dst port 8080"`
		window = window || edit.Field == "packetAfter" && string(edit.Value) == `"3s"`
	}
	if !filter || !window {
		t.Fatal("edited filter/window not preserved in encrypted second snapshot")
	}
	var evidence struct {
		Artifacts []struct {
			ID        string    `json:"artifact_id"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"artifacts"`
	}
	browser.read(ctx, "get_case", map[string]string{"case_id": progress.CaseID}, &evidence)
	if len(evidence.Artifacts) != 1 {
		t.Fatal("repeated recording has no exact native result")
	}
	native := installedHistoryBrowserNative(t, ctx, browser, evidence.Artifacts[0].ID, evidence.Artifacts[0].ExpiresAt)
	path := filepath.Join(t.TempDir(), "history-repeat.pcapng")
	if err := os.WriteFile(path, native, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(ctx, "tshark", "-r", path, "-T", "fields", "-e", "frame.time_epoch", "-e", "tcp.dstport").Output()
	if err != nil {
		t.Fatal("repeated native PCAPNG unreadable", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var first, last float64
	for i, line := range lines {
		columns := strings.Split(line, "\t")
		if len(columns) != 2 || columns[1] != "8080" {
			t.Fatal("packet violated restored edited destination filter")
		}
		stamp, e := strconv.ParseFloat(columns[0], 64)
		if e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			first = stamp
		}
		last = stamp
	}
	span := last - first
	// Continuous owned HTTP traffic distinguishes the edited 3s window from
	// the source's 2s window. This is fixture sampling tolerance, not a new
	// product timing guarantee; record the actual native span below.
	if span < 2.1 || span > 3.5 {
		t.Fatal("native packet span did not reproduce edited 3s window", span)
	}
	t.Logf("actual React history/settings/filter+window edit/new independent grant/resume succeeded: source=%s repeated=%s newGrant=%s packets=%d nativeBytes=%d nativeSpanSeconds=%.6f sourceExpiry=%s", sourceCapture, result.CaptureID, result.GrantID, len(lines), len(native), span, source.ExpiresAt.Format(time.RFC3339Nano))
}

func installedHistoryBrowserNative(t *testing.T, ctx context.Context, browser *installedBrowser, artifactID string, expires time.Time) []byte {
	t.Helper()
	// One original bound covers the initial preparation and every later read.
	ctx, stop := context.WithDeadline(ctx, installedJourneyEarlier(expires, time.Now().Add(3*time.Minute)))
	defer stop()
	prepare := map[string]string{"artifact_id": artifactID, "idempotency_key": "installed-history-repeat-download-" + artifactID}
	prepareOnce := func() installedJourneyDownload {
		t.Helper()
		reply, status, err := browser.operation(ctx, "prepare_artifact_download", prepare, prepare["idempotency_key"])
		var d installedJourneyDownload
		if err != nil || status != http.StatusOK || reply.Status != "ok" || json.Unmarshal(reply.Data, &d) != nil {
			t.Fatal("repeat native preparation", status, reply.Status, err)
		}
		return d
	}
	download := prepareOnce()
	original, until := download.DownloadID, download.ExpiresAt
	if original == "" || until.IsZero() || until.After(expires) {
		t.Fatal("repeat native original deadline")
	}
	limit, cancel := context.WithDeadline(ctx, installedJourneyEarlier(until, time.Now().Add(3*time.Minute)))
	defer cancel()
	for download.State == "Preparing" {
		if installedJourneyPause(limit, 2*time.Second) != nil {
			t.Fatal("repeat native stayed Preparing")
		}
		if download.ContinuePreparation {
			download = prepareOnce()
		} else {
			browser.read(limit, "get_artifact_download", map[string]string{"download_id": original}, &download)
		}
		if download.DownloadID != original || !download.ExpiresAt.Equal(until) {
			t.Fatal("repeat native identity/deadline changed")
		}
	}
	if download.State != "Ready" || download.ContentPath != "/api/v1/downloads/"+original+"/content" || download.SizeBytes == nil || *download.SizeBytes < 1 || *download.SizeBytes > artifact.RecordingNativeLimit {
		t.Fatal("repeat native not ready", download.State)
	}
	request, err := http.NewRequestWithContext(limit, http.MethodGet, browser.base+download.ContentPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Dest", "document")
	response, err := browser.client.Do(request)
	if err != nil {
		t.Fatal("repeat browser native transfer", err)
	}
	defer response.Body.Close()
	_, disposition, err := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	if err != nil || disposition["filename"] != "artifact-"+artifactID+".pcapng" {
		t.Fatal("repeat native filename", err)
	}
	native, err := io.ReadAll(io.LimitReader(response.Body, artifact.RecordingNativeLimit+1))
	digest := sha256.Sum256(native)
	if err != nil || response.StatusCode != http.StatusOK || int64(len(native)) != *download.SizeBytes || hex.EncodeToString(digest[:]) != download.SHA256 {
		t.Fatal("repeat native differs from authenticated metadata", response.StatusCode, err)
	}
	return native
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
func installedRecorderHistoryBrowser(t *testing.T, ctx context.Context, browser *installedBrowser, address string, target map[string]string, source string, approve func(context.Context, string)) installedHistoryBrowserResult {
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
			approve(call, event.GrantID)
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
		message := diagnostic.String()
		for _, c := range cookies {
			message = strings.ReplaceAll(message, c.Value, "[session]")
		}
		t.Fatalf("installed React history workflow: %v\n%s", err, message)
	}
	if len(result.CaptureID) != 36 || result.CaptureID == source || len(result.GrantID) != 36 || result.SourceExpiresAt.IsZero() {
		t.Fatal("installed history browser did not complete")
	}
	return result
}
