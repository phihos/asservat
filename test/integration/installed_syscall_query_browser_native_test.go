package integration

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

type installedSyscallQueryBrowserSource struct {
	CaseID, ArtifactID, Version, PodUID, GrantID string
	Expires                                      time.Time
}

// Reuses the installed HttpOnly cookie tunnel and bounded line protocol. The
// caller owns scheduled polls and independent SQL/native checks; this helper
// owns Chromium through its final rendered-result/close acknowledgement only.
func installedSyscallQueryBrowser(t *testing.T, ctx context.Context, browser *installedBrowser, address string, source installedSyscallQueryBrowserSource, selection map[string]any, observed func(installedComparisonReply)) (func(string, any) installedComparisonReply, func()) {
	t.Helper()
	origin, err := url.Parse(browser.base)
	if err != nil || browser.client.Jar == nil || observed == nil {
		t.Fatal("syscall browser original session missing")
	}
	var cookies []map[string]any
	for _, c := range browser.client.Jar.Cookies(origin) {
		cookies = append(cookies, map[string]any{"name": c.Name, "value": c.Value, "url": browser.base, "httpOnly": true, "secure": true, "sameSite": "Lax"})
	}
	if len(cookies) == 0 {
		t.Fatal("syscall browser original cookie missing")
	}
	config, err := json.Marshal(map[string]any{"mode": "syscall-query", "origin": browser.base, "proxy": installedHistoryBrowserTunnel(t, ctx, browser.base, address), "cookies": cookies, "caseID": source.CaseID, "artifactID": source.ArtifactID, "version": source.Version, "podUID": source.PodUID, "grantID": source.GrantID, "query_request": selection})
	if err != nil || len(config) > 16<<10 {
		clear(config)
		t.Fatal("syscall browser private input bound")
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Minute)
	cmd := exec.CommandContext(call, "node", filepath.Join("..", "..", "web", "scripts", "installed-syscall-query-browser.mjs"))
	// Chromium children keep stdout open after node is killed; bound Wait.
	cmd.WaitDelay = 5 * time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	in, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var diagnostic consoleBoundedOutput
	cmd.Stderr = &diagnostic
	if err = cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	waited, closed := false, false
	t.Cleanup(func() {
		cancel()
		_ = in.Close()
		if !waited {
			_ = cmd.Wait()
			waited = true
		}
	})
	fail := func(stage string) {
		t.Helper()
		closed = true
		message := diagnostic.String()
		for _, c := range cookies {
			message = strings.ReplaceAll(message, c["value"].(string), "[session]")
		}
		t.Fatalf("installed React syscall %s\n%s", stage, message)
	}
	if _, err = in.Write(append(config, '\n')); err != nil {
		clear(config)
		fail("input unavailable")
	}
	clear(config)
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 1024), 64<<10)
	type event struct {
		Kind, Name   string
		Input, Reply json.RawMessage
		Transport    struct{ Post, SameOrigin, CSRF, NoBearer bool }
	}
	read := func() event {
		t.Helper()
		if !scanner.Scan() {
			cancel()
			_ = cmd.Wait()
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
		if closed || name != "syscall_query" && name != "get_query_result" {
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
			fail("original cookie transport")
		}
		var actual, wanted any
		input, err := json.Marshal(args)
		if err != nil || json.Unmarshal(input, &wanted) != nil || json.Unmarshal(e.Input, &actual) != nil {
			fail("canonical input unavailable")
		}
		if name == "syscall_query" {
			a, aok := actual.(map[string]any)
			w, wok := wanted.(map[string]any)
			key, kok := a["idempotency_key"].(string)
			if !aok || !wok || !kok || len(key) < 1 || len(key) > 128 {
				fail("original UI key missing")
			}
			w["idempotency_key"] = key
			if original, ok := args.(map[string]any); ok {
				original["idempotency_key"] = key
			}
		}
		if !reflect.DeepEqual(actual, wanted) || browser.wire.ValidateOutput(name, e.Reply) != nil {
			fail("canonical request or reply")
		}
		return reply
	}
	finish := func() {
		t.Helper()
		if closed {
			return
		}
		closed = true
		if _, err := in.Write([]byte("{\"kind\":\"close\"}\n")); err != nil {
			fail("close command")
		}
		if read().Kind != "closed" {
			fail("close acknowledgement")
		}
		_ = in.Close()
		if err := cmd.Wait(); err != nil {
			waited = true
			fail("terminal failure")
		}
		waited = true
		cancel()
		t.Log("installed React syscall rendered recorded values and joined before caller terminal proof")
	}
	return invoke, finish
}
