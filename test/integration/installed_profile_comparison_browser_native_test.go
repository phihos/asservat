package integration

// Dependencies are existing installed-native helpers, not a synthetic server.
import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// installedProfileComparisonBrowser preserves qualifyInstalledProfileComparison's
// existing call/poll loop. Go still schedules the original paid polls and runs
// all canonical reply, native aggregation, association and SQL/key/worker checks.
// observed receives an early reply BEFORE semantic validation; the owner should
// register its proof closure before the first call and retain the pending handle
// and operation ID here, so a browser/render failure cannot bypass known cleanup.
func installedProfileComparisonBrowser(t *testing.T, ctx context.Context, browser *installedBrowser, address string, source installedProfileComparisonSource, observed func(installedComparisonReply)) (func(string, any) installedComparisonReply, func()) {
	call, _, close := installedProfileBrowser(t, ctx, browser, address, source, "comparison", observed)
	return call, close
}

// Heap mode uses the same installed React/session transport and one existing
// query. Native bytes stay in a Go-owned private directory, never stdout.
func installedProfileBrowser(t *testing.T, ctx context.Context, browser *installedBrowser, address string, source installedProfileComparisonSource, mode string, observed func(installedComparisonReply)) (func(string, any) installedComparisonReply, func() ([]byte, installedJourneyDownload), func()) {
	t.Helper()
	origin, err := url.Parse(browser.base)
	if err != nil || browser.client.Jar == nil || observed == nil {
		t.Fatal("installed comparison browser session missing")
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
		t.Fatal("installed comparison original cookie missing")
	}
	if mode != "comparison" && mode != "heap" {
		t.Fatal("invalid profile browser mode")
	}
	nativeDirectory := t.TempDir()
	nativePath := filepath.Join(nativeDirectory, "heap-native.pb.gz")
	proxy := installedHistoryBrowserTunnel(t, ctx, browser.base, address)
	config, err := json.Marshal(map[string]any{"origin": browser.base, "proxy": proxy, "cookies": cookies, "caseID": source.CaseID, "artifactID": source.ArtifactID, "mode": mode, "nativeDestination": nativePath})
	if err != nil || len(config) > 16<<10 {
		clear(config)
		t.Fatal("installed comparison private input bound")
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Minute) // Existing history driver ceiling; original parent still wins.
	command := exec.CommandContext(call, "node", filepath.Join("..", "..", "web", "scripts", "installed-profile-comparison-browser.mjs"))
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
		clear(config)
		t.Fatal(err)
	}
	out, err := command.StdoutPipe()
	if err != nil {
		cancel()
		clear(config)
		t.Fatal(err)
	}
	var diagnostic consoleBoundedOutput
	command.Stderr = &diagnostic
	if err = command.Start(); err != nil {
		cancel()
		clear(config)
		t.Fatal(err)
	}
	waited, closed := false, false
	t.Cleanup(func() {
		cancel()
		_ = in.Close()
		if !waited {
			_ = command.Wait()
			waited = true
		}
	})
	fail := func(stage string) {
		t.Helper()
		message := diagnostic.String()
		for _, c := range cookies {
			message = strings.ReplaceAll(message, c.Value, "[session]")
		}
		t.Fatalf("installed React comparison %s\n%s", stage, message)
	}
	if _, err = in.Write(append(config, '\n')); err != nil {
		clear(config)
		fail("input unavailable")
	}
	clear(config)
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 1024), 64<<10)
	type event struct {
		Kind      string          `json:"kind"`
		Name      string          `json:"name"`
		File      string          `json:"file"`
		Filename  string          `json:"filename"`
		Input     json.RawMessage `json:"input"`
		Reply     json.RawMessage `json:"reply"`
		Transport struct {
			Post, SameOrigin, CSRF, NoBearer bool
		} `json:"transport"`
	}
	read := func() event {
		t.Helper()
		if !scanner.Scan() {
			// Join first so the bounded diagnostic includes Chromium's terminal
			// failure timeline rather than racing its stderr write.
			cancel()
			_ = command.Wait()
			waited = true
			fail("event unavailable")
		}
		var e event
		if json.Unmarshal(scanner.Bytes(), &e) != nil {
			fail("invalid bounded event")
		}
		return e
	}
	if read().Kind != "ready" {
		fail("page not ready")
	}
	invoke := func(name string, args any) installedComparisonReply {
		t.Helper()
		if closed || name != "get_query_result" && (mode == "comparison" && name != "compare_profiles" || mode == "heap" && name != "get_profile_summary") {
			fail("unexpected operation")
		}
		encoded, err := json.Marshal(map[string]any{"kind": "call", "name": name, "input": args})
		if err != nil || len(encoded) > 16<<10 {
			fail("operation input bound")
		}
		if _, err = in.Write(append(encoded, '\n')); err != nil {
			fail("operation input unavailable")
		}
		e := read()
		var reply installedComparisonReply
		if e.Kind != "operation" || e.Name != name || json.Unmarshal(e.Reply, &reply) != nil {
			fail("operation association")
		}
		observed(reply)
		if !e.Transport.Post || !e.Transport.SameOrigin || !e.Transport.CSRF || !e.Transport.NoBearer {
			fail("original cookie browser transport")
		}
		var actual, wanted any
		input, encodeErr := json.Marshal(args)
		if encodeErr != nil || json.Unmarshal(input, &wanted) != nil || json.Unmarshal(e.Input, &actual) != nil || !reflect.DeepEqual(actual, wanted) || browser.wire.ValidateOutput(name, e.Reply) != nil {
			fail("canonical request or reply")
		}
		return reply
	}
	download := func() ([]byte, installedJourneyDownload) {
		t.Helper()
		if closed || mode != "heap" {
			fail("unexpected native download")
		}
		if _, err := in.Write([]byte("{\"kind\":\"download\"}\n")); err != nil {
			fail("native command unavailable")
		}
		var original, key string
		var deadline time.Time
		var ready installedJourneyDownload
		for {
			e := read()
			if e.Kind == "native" {
				if ready.State != "Ready" || e.File != "heap-native.pb.gz" || e.Filename != "artifact-"+source.ArtifactID+".pb.gz" {
					fail("native attachment association")
				}
				info, err := os.Lstat(nativePath)
				if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > artifact.MaxPprofBytes {
					fail("private native file bound")
				}
				f, err := os.Open(nativePath)
				if err != nil {
					fail("private native file unavailable")
				}
				native, readErr := io.ReadAll(io.LimitReader(f, artifact.MaxPprofBytes+1))
				_ = f.Close()
				digest := sha256.Sum256(native)
				if readErr != nil || ready.SizeBytes == nil || int64(len(native)) != *ready.SizeBytes || hex.EncodeToString(digest[:]) != ready.SHA256 {
					fail("native metadata/bytes mismatch")
				}
				return native, ready
			}
			if e.Kind != "operation" || e.Name != "prepare_artifact_download" && e.Name != "get_artifact_download" || !e.Transport.Post || !e.Transport.SameOrigin || !e.Transport.CSRF || !e.Transport.NoBearer || browser.wire.ValidateOutput(e.Name, e.Reply) != nil {
				fail("native operation contract")
			}
			var reply installedComparisonReply
			var args map[string]string
			var current installedJourneyDownload
			if json.Unmarshal(e.Reply, &reply) != nil || reply.Status != "ok" || json.Unmarshal(reply.Data, &current) != nil || json.Unmarshal(e.Input, &args) != nil || current.ArtifactID != source.ArtifactID {
				fail("native operation association")
			}
			if e.Name == "prepare_artifact_download" {
				if args["artifact_id"] != source.ArtifactID || args["idempotency_key"] == "" || key != "" && (key != args["idempotency_key"] || !ready.ContinuePreparation) {
					fail("native preparation key changed")
				}
				key = args["idempotency_key"]
			} else if original == "" || args["download_id"] != original {
				fail("native status identity changed")
			}
			if original == "" {
				original, deadline = current.DownloadID, current.ExpiresAt
			}
			if original == "" || current.DownloadID != original || deadline.IsZero() || !current.ExpiresAt.Equal(deadline) || deadline.After(source.Expires) || current.State != "Preparing" && current.State != "Ready" {
				fail("native original identity/deadline/state")
			}
			if current.State == "Ready" && (current.ContentPath != "/api/v1/downloads/"+original+"/content" || current.SizeBytes == nil || *current.SizeBytes < 1 || *current.SizeBytes > artifact.MaxPprofBytes) {
				fail("native ready metadata")
			}
			ready = current
		}
	}
	finish := func() {
		t.Helper()
		if closed {
			return
		}
		// Defer this function immediately after construction. On assertion
		// failure, join Chromium before the owner's deferred SQL terminal reads.
		if t.Failed() {
			cancel()
			_ = in.Close()
			if !waited {
				_ = command.Wait()
				waited = true
			}
			closed = true
			return
		}
		if _, err := in.Write([]byte("{\"kind\":\"close\"}\n")); err != nil {
			fail("close unavailable")
		}
		if read().Kind != "closed" {
			fail("render or joined browser close")
		}
		_ = in.Close()
		err := command.Wait()
		waited, closed = true, true
		if err != nil {
			fail("terminal process")
		}
		t.Logf("installed React comparison joined after rendered-row checks:\n%s", diagnostic.String())
		cancel()
	}
	return invoke, download, finish
}

// The original independent review selects one client, never both; no second
// raw approval or enlarged parent disclosure pool is introduced for heap UI.
func installedProfileResultClient() string {
	if installedProfileFocus() && installedHeapProfileVariant() {
		return "console"
	}
	return "mcp"
}
