package hub

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// A Go execution trace is shown by Go's own trace tool ("go tool trace"):
// the hub runs it for the view on a loopback port and passes its pages on.
// The tool writes its links from the root of its own server, so the hub
// rewrites them to the view's pages.

// traceListening is what the tool logs once it serves.
var traceListening = regexp.MustCompile(`listening on (http://127\.0\.0\.1:\d+)`)

// rootLink matches a quoted address that starts at the server's root, as
// the tool's pages write their links and requests: "/goroutines", '/jsontrace?…'.
var rootLink = regexp.MustCompile(`(["'])/([a-z])`)

// tracePages starts Go's trace tool for an execution trace and returns a
// handler for its pages, which are reached under prefix. The tool runs
// until ctx ends. It reads the whole trace into memory first; the hub
// decrypts the trace into its work directory for that and removes it once
// the tool serves.
func (h *Hub) tracePages(ctx context.Context, a storedArtifact, prefix string) (http.Handler, error) {
	file, err := os.CreateTemp(h.WorkDir, "view-*.trace")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	err = h.plain(ctx, a, file)
	if e := file.Close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, fmt.Errorf("open artifact: %w", err)
	}
	cmd := exec.CommandContext(ctx, h.GoTrace, "-http=127.0.0.1:0", file.Name())
	// The tool keeps a cache and looks for a browser to open; it has a home for neither.
	cmd.Env = append(os.Environ(), "HOME="+h.WorkDir, "BROWSER=true")
	// The hub owns the pipe of what the tool logs, so that the tool's end
	// does not close it before its last words are read.
	said, says := io.Pipe()
	cmd.Stderr = says
	if err := cmd.Start(); err != nil {
		return nil, errStatus{http.StatusNotImplemented, "this hub cannot show Go execution traces: " + err.Error()}
	}
	go func() {
		cmd.Wait() // ends with ctx; reaps the process
		says.Close()
	}()
	// The tool logs its progress and, at last, where it listens. If it ends
	// before that, its last words say why.
	var target *url.URL
	var last string
	lines := bufio.NewScanner(said)
	for lines.Scan() {
		last = lines.Text()
		if m := traceListening.FindStringSubmatch(last); m != nil {
			target, _ = url.Parse(m[1])
			break
		}
	}
	if target == nil {
		return nil, errStatus{http.StatusUnprocessableEntity, "Go's trace tool cannot read this trace: " + last}
	}
	go io.Copy(io.Discard, said) // the tool keeps logging

	proxy := httputil.NewSingleHostReverseProxy(target)
	direct := proxy.Director
	proxy.Director = func(r *http.Request) {
		direct(r)
		r.Host = target.Host
		r.Header.Del("Accept-Encoding") // the pages are rewritten as text
		r.Header.Del("Cookie")
		r.Header.Del("Authorization")
	}
	proxy.ModifyResponse = func(res *http.Response) error {
		kind := res.Header.Get("Content-Type")
		// The viewer's own files under /static/ are large and link nowhere.
		if strings.HasPrefix(res.Request.URL.Path, "/static/") || !(strings.HasPrefix(kind, "text/html") || strings.Contains(kind, "javascript")) {
			return nil
		}
		page, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return err
		}
		page = rootLink.ReplaceAll(page, []byte("${1}"+prefix+"/${2}"))
		res.Body = io.NopCloser(bytes.NewReader(page))
		res.ContentLength = int64(len(page))
		res.Header.Set("Content-Length", strconv.Itoa(len(page)))
		return nil
	}
	return proxy, nil
}
