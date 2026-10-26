package console

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

const testOrigin = "https://console.example.test"
const testJS = "/assets/index-01234567.js"
const testCSS = "/assets/index-89ABCDEF.css"
const testHTML = `<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Asservat</title><script type="module" crossorigin src="` + testJS + `"></script><link rel="stylesheet" crossorigin href="` + testCSS + `"></head><body><div id="root"></div><noscript>JavaScript is required.</noscript></body></html>`

// These are the exact reviewed touch-action bytes, not an allowance for a
// library-selected arbitrary style or untrusted HTML attribute.
const reviewedPressStyle = `@layer {
  [data-react-aria-pressable] {
    touch-action: pan-x pan-y pinch-zoom;
  }
}`

func TestReviewedPressStyleHash(t *testing.T) {
	sum := sha256.Sum256([]byte(reviewedPressStyle))
	if "sha256-"+base64.StdEncoding.EncodeToString(sum[:]) != pressStyleHash || !strings.Contains(contentSecurityPolicy, "style-src 'self' '"+pressStyleHash+"'") {
		t.Fatal("style allowance does not match exact reviewed CSS")
	}
}

// The installed pinned source is additionally compared when the web workspace
// is present. The real browser gate also rejects any changed injected rule via
// its CSP-error check. No dependency source parsing occurs in product code.
func TestPinnedReactAriaPressStyle(t *testing.T) {
	source, err := os.ReadFile("../../web/node_modules/react-aria/dist/private/interactions/usePress.mjs")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("install locked web dependencies for source compatibility qualification")
	} else if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "PRESSABLE_ATTRIBUTE = 'data-react-aria-pressable'") {
		t.Fatal("reviewed React Aria press attribute changed")
	}
	match := regexp.MustCompile("(?s)style\\.textContent = `([^`]+)`\\.trim\\(\\)").FindSubmatch(source)
	if len(match) != 2 {
		t.Fatal("reviewed React Aria style form changed")
	}
	css := regexp.MustCompile(`\$\{[^}]+\$var\$PRESSABLE_ATTRIBUTE\}`).ReplaceAllString(strings.TrimSpace(string(match[1])), "data-react-aria-pressable")
	if css != reviewedPressStyle {
		t.Fatal("pinned React Aria source requires a new explicit CSS review")
	}
}

func packageFiles() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                     &fstest.MapFile{Data: []byte(testHTML)},
		strings.TrimPrefix(testJS, "/"):  &fstest.MapFile{Data: []byte("document.title = 'Asservat';")},
		strings.TrimPrefix(testCSS, "/"): &fstest.MapFile{Data: []byte("body { color: #123; }")},
	}
}

func request(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "console.example.test"
	r.TLS = &tls.ConnectionState{}
	return r
}

func TestStaticSnapshotAndCacheBoundaries(t *testing.T) {
	files := packageFiles()
	h, err := New(testOrigin, files)
	if err != nil {
		t.Fatal(err)
	}
	files["index.html"].Data = []byte("replaced")
	files[strings.TrimPrefix(testJS, "/")].Data[0] = 'x'
	files["assets/new-01234567.js"] = &fstest.MapFile{Data: []byte("new")}

	for _, target := range []string{"/", "/captures/new", "/policies", "/captures/00000000-0000-4000-8000-000000000008", "/cases/00000000-0000-4000-8000-000000000007", testJS, testCSS} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request("GET", target))
		if w.Code != 200 {
			t.Fatalf("GET %s = %d", target, w.Code)
		}
		if consoleRoute(target) {
			if w.Body.String() != testHTML || w.Header().Get("ETag") != "" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
				t.Fatal("shell content or cache changed")
			}
		} else {
			if !strings.Contains(w.Header().Get("Cache-Control"), "immutable") || len(w.Header().Get("ETag")) != 66 || strings.HasPrefix(w.Body.String(), "x") {
				t.Fatal("asset did not remain an immutable snapshot")
			}
			cached := request("GET", target)
			cached.Header.Set("If-None-Match", w.Header().Get("ETag"))
			cw := httptest.NewRecorder()
			h.ServeHTTP(cw, cached)
			if cw.Code != 304 || cw.Body.Len() != 0 || !strings.Contains(cw.Header().Get("Cache-Control"), "immutable") {
				t.Fatal("conditional asset request did not remain cacheable and body-free")
			}
		}
		if w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("X-Content-Type-Options") != "nosniff" || strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-") || w.Header().Get("Content-Security-Policy") != contentSecurityPolicy {
			t.Fatal("missing restrictive response headers")
		}
		head := httptest.NewRecorder()
		h.ServeHTTP(head, request("HEAD", target))
		if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != strconv.Itoa(w.Body.Len()) {
			t.Fatal("HEAD mismatch")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request("GET", "/assets/new-01234567.js"))
	if w.Code != 404 {
		t.Fatal("late filesystem change became visible")
	}
	r := request("GET", testJS)
	r.Header.Set("Range", "bytes=999999-")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 416 || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("range error may be cached")
	}
}

func TestNoFallbackOrRequestAuthority(t *testing.T) {
	h, err := New(testOrigin, packageFiles())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/api/v1/session", "/auth/start", "/content/secret", "/captures/one", "/index.html", "/assets", "/assets/", "/assets/missing-01234567.js", "/assets/../index.html", "/assets//index-01234567.js", "/%61ssets/index-01234567.js", "/assets/index-01234567.js?x=1", "/?", "/?secret=anything", "/assets/index-01234567.js.map", "/\\assets/index-01234567.js"} {
		t.Run(target, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request("GET", target))
			if w.Code != 404 || w.Body.String() != "Not found\n" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") || w.Header().Get("Location") != "" {
				t.Fatalf("unrecognized path: status %d, body %q", w.Code, w.Body.String())
			}
		})
	}
	for _, target := range []string{"/cases", "/cases/", "/cases/not-a-uuid", "/cases/00000000-0000-4000-8000-000000000007/raw", "/cases/00000000-0000-4000-8000-000000000007?token=secret", "/cases/%30%30%30%30%30%30%30%30-0000-4000-8000-000000000007", "/captures", "/captures/", "/captures/new/", "/captures/new?preview_id=secret", "/captures/00000000-0000-4000-8000-000000000008/raw", "/captures/%30%30%30%30%30%30%30%30-0000-4000-8000-000000000008", "/policies/", "/policies?name=secret"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request("GET", target))
		if w.Code != http.StatusNotFound || w.Body.String() != "Not found\n" {
			t.Fatalf("unsupported capture route %q exposed a shell", target)
		}
	}
	attacks := map[string]func(*http.Request){
		"plaintext forwarded TLS": func(r *http.Request) { r.TLS = nil; r.Header.Set("X-Forwarded-Proto", "https") },
		"forwarded host": func(r *http.Request) {
			r.Host = "other.example.test"
			r.Header.Set("Forwarded", "proto=https;host=console.example.test")
			r.Header.Set("X-Forwarded-Host", "console.example.test")
		},
		"absolute URL":           func(r *http.Request) { r.URL.Scheme = "https"; r.URL.Host = r.Host },
		"authorization":          func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret") },
		"empty authorization":    func(r *http.Request) { r.Header["Authorization"] = []string{""} },
		"wrong origin":           func(r *http.Request) { r.Header.Set("Origin", "https://other.example.test") },
		"duplicate origin":       func(r *http.Request) { r.Header.Add("Origin", testOrigin); r.Header.Add("Origin", testOrigin) },
		"cross-site subresource": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"same-site subresource":  func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") },
		"duplicate fetch site": func(r *http.Request) {
			r.Header.Add("Sec-Fetch-Site", "same-origin")
			r.Header.Add("Sec-Fetch-Site", "same-origin")
		},
		"unknown fetch site":    func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "anything") },
		"escaped request URI":   func(r *http.Request) { r.RequestURI = "/%2f" },
		"oversized request URI": func(r *http.Request) { r.RequestURI = "/" + strings.Repeat("a", 2048) },
	}
	for name, change := range attacks {
		t.Run(name, func(t *testing.T) {
			r := request("GET", "/")
			change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 404 || w.Body.String() != "Not found\n" {
				t.Fatalf("request admitted: %d", w.Code)
			}
		})
	}
	for _, target := range []string{"/", testJS} {
		for _, method := range []string{"POST", "PUT", "DELETE", "OPTIONS", "TRACE"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(method, target))
			if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
				t.Fatalf("%s %s admitted", method, target)
			}
		}
	}
	for _, site := range []string{"same-origin", "none", "same-site", "cross-site"} {
		r := request("GET", "/")
		r.Header.Set("Sec-Fetch-Site", site)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("normal landing navigation rejected: %s", site)
		}
		r = request("GET", testJS)
		r.Header.Set("Sec-Fetch-Site", site)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if (site == "cross-site" || site == "same-site") && w.Code != 404 {
			t.Fatal("cross-origin asset navigation admitted")
		}
	}
}

func TestRejectInvalidPackageAndOrigin(t *testing.T) {
	for _, origin := range []string{"", "http://console.example.test", "https://Console.example.test", testOrigin + "/", testOrigin + ":443", testOrigin + ":00080", testOrigin + ":65536", testOrigin + ":", testOrigin + "?", testOrigin + "#x", "https://user@console.example.test", "https://console.example.test..", "https://-console.example.test", "https://☃.example.test"} {
		if _, err := New(origin, packageFiles()); !errors.Is(err, ErrInvalidOrigin) {
			t.Errorf("origin %q accepted: %v", origin, err)
		}
	}
	for _, origin := range []string{testOrigin, testOrigin + ":8443", "https://127.0.0.1:8443", "https://[::1]:8443"} {
		if _, err := New(origin, packageFiles()); err != nil {
			t.Errorf("origin %q rejected: %v", origin, err)
		}
	}
	badPackages := map[string]func(fstest.MapFS){
		"missing index":           func(f fstest.MapFS) { delete(f, "index.html") },
		"missing referenced file": func(f fstest.MapFS) { delete(f, strings.TrimPrefix(testJS, "/")) },
		"symlink":                 func(f fstest.MapFS) { f[strings.TrimPrefix(testJS, "/")].Mode = fs.ModeSymlink },
		"source map":              func(f fstest.MapFS) { f["assets/index-01234567.js.map"] = &fstest.MapFile{Data: []byte("{}")} },
		"unhashed file":           func(f fstest.MapFS) { f["assets/index.js"] = &fstest.MapFile{Data: []byte("script")} },
		"nested directory":        func(f fstest.MapFS) { f["assets/nested/index-01234567.js"] = &fstest.MapFile{Data: []byte("script")} },
		"secret file":             func(f fstest.MapFS) { f["secret.txt"] = &fstest.MapFile{Data: []byte("not a console asset")} },
		"empty":                   func(f fstest.MapFS) { f["index.html"].Data = nil },
		"oversized html":          func(f fstest.MapFS) { f["index.html"].Data = bytes.Repeat([]byte(" "), maxShellBytes+1) },
		"oversized asset": func(f fstest.MapFS) {
			f[strings.TrimPrefix(testJS, "/")].Data = bytes.Repeat([]byte(" "), maxAssetBytes+1)
		},
		"too many assets": func(f fstest.MapFS) {
			for n := range maxFiles {
				f["assets/extra"+strconv.Itoa(n)+"-01234567.js"] = &fstest.MapFile{Data: []byte("x")}
			}
		},
	}
	for name, mutate := range badPackages {
		t.Run(name, func(t *testing.T) {
			files := packageFiles()
			mutate(files)
			if _, err := New(testOrigin, files); !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("invalid package admitted: %v", err)
			}
		})
	}
	for _, change := range []struct{ old, replacement string }{
		{testJS, "https://cdn.example.test/index-01234567.js"},
		{testCSS, "//cdn.example.test/index-89ABCDEF.css"},
		{testJS, testJS + "?v=1"},
		{testJS, "/assets/../assets/index-01234567.js"},
		// HTML keeps the first duplicate attribute; the browser and tokenizer
		// must not be tricked into treating the later valid value as authority.
		{`type="module"`, `type="text/javascript" type="module"`},
		{`</script>`, `alert(1)</script>`},
		{`<head>`, `<head><base href="https://elsewhere.example.test">`},
		{`<head>`, `<head><meta http-equiv="refresh" content="0;url=https://elsewhere.example.test">`},
		{`<head>`, `<head><style>body{color:red}</style>`},
		{`<div id="root">`, `<div id="root" onclick="alert(1)">`},
		{`<div id="root">`, `<div id="root" style="color:red">`},
		{`<body>`, `<body><iframe src="/auth/start"></iframe>`},
		{`crossorigin`, `crossorigin="use-credentials"`},
	} {
		files := packageFiles()
		files["index.html"].Data = []byte(strings.Replace(testHTML, change.old, change.replacement, 1))
		if _, err := New(testOrigin, files); !errors.Is(err, ErrInvalidPackage) {
			t.Errorf("invalid HTML admitted (%s): %v", change.replacement, err)
		}
	}
}

// The product workspace build is optional for ordinary Go-only development.
// The console release gate must build web/dist first and run this test without
// skipping it; this checks real bundler output against the Go delivery contract.
func TestBuiltConsolePackage(t *testing.T) {
	const directory = "../../web/dist"
	if _, err := os.Stat(directory); errors.Is(err, fs.ErrNotExist) {
		t.Skip("web/dist not built; build the production console for this qualification")
	} else if err != nil {
		t.Fatal(err)
	}
	h, err := New(testOrigin, os.DirFS(directory))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request("GET", "/"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `id="root"`) {
		t.Fatal("built shell not served")
	}
}
