package integration

// Dependencies are existing installed-native helpers, not a synthetic server.
import (
	"bufio"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// installedProfileComparisonBrowser preserves qualifyInstalledProfileComparison's
// existing call/poll loop. Go still schedules the original paid polls and runs
// all canonical reply, native aggregation, association and SQL/key/worker checks.
// observed receives an early reply BEFORE semantic validation; the owner should
// register its proof closure before the first call and retain the pending handle
// and operation ID here, so a browser/render failure cannot bypass known cleanup.
func installedProfileComparisonBrowser(t *testing.T, ctx context.Context, browser *installedBrowser, address string, source installedProfileComparisonSource, observed func(installedComparisonReply)) (func(string, any) installedComparisonReply, func()) {
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
	proxy := installedHistoryBrowserTunnel(t, ctx, browser.base, address)
	config, err := json.Marshal(map[string]any{"origin": browser.base, "proxy": proxy, "cookies": cookies, "caseID": source.CaseID, "artifactID": source.ArtifactID})
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
		if closed || name != "compare_profiles" && name != "get_query_result" {
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
	return invoke, finish
}
