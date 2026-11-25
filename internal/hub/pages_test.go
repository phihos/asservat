package hub_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/hub"
)

// The pages show what workloads and agents hand the hub. Should a value
// ever reach a page as markup, the browser still runs none of it: the
// pages tell it to run scripts from the hub's own files only (a content
// security policy, as OWASP's cheat sheet on cross-site scripting advises
// as the second line of defence), and so carry no script of their own in
// their markup.
func TestPagesRunOnlyTheHubsOwnScripts(t *testing.T) {
	h, err := hub.New(hub.Config{MasterKey: bytes.Repeat([]byte{1}, 32), Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h.Handler())
	defer server.Close()
	inline := regexp.MustCompile(`<script(?:\s+type="module")?\s*>|\son[a-z]+\s*=\s*["']|javascript:`)
	for _, page := range []string{"/", "/view"} {
		res, err := http.Get(server.URL + page)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		policy := res.Header.Get("Content-Security-Policy")
		for _, part := range []string{"script-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'self'"} {
			if !strings.Contains(policy, part) {
				t.Errorf("%s: the policy %q lacks %s", page, policy, part)
			}
		}
		if strings.Contains(policy, "unsafe-inline'; script") || regexp.MustCompile(`script-src[^;]*unsafe`).MatchString(policy) {
			t.Errorf("%s: the policy lets markup run script: %s", page, policy)
		}
		if found := inline.Find(body); found != nil {
			t.Errorf("%s carries script in its markup, which the policy forbids: %s", page, found)
		}
	}
	// The scripts themselves are the hub's files.
	for _, script := range []string{"/console.js", "/view/view.js"} {
		res, err := http.Get(server.URL + script)
		if err != nil || res.StatusCode != 200 || !strings.Contains(res.Header.Get("Content-Type"), "javascript") {
			t.Errorf("%s: %v %v", script, res.StatusCode, err)
		}
		res.Body.Close()
	}
}
