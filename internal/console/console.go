// Package console serves a packaged browser application. It supplies no session,
// API, collection or evidence authority; bootstrap composes those separately.
package console

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html"
)

const (
	maxFiles      = 256
	maxAssetBytes = 16 << 20
	maxShellBytes = 256 << 10
	maxTotalBytes = 64 << 20
	// react-aria 3.53.1 (react-aria-components 1.22.1) injects one fixed usePress
	// touch-action rule. Approve only those exact reviewed bytes. New component
	// styles require separate qualification; this is no general inline allowance.
	pressStyleHash = "sha256-38RhXrc7EdReTKsOm23ZPOCUgniTUUcjky8QOOrQx6o="
	// API connections stay on the same origin; the shell has no evidence of its
	// own and no inline script, evaluation or remote dependency is permitted.
	contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self' '" + pressStyleHash + "'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
)

var (
	ErrInvalidOrigin  = errors.New("console: invalid HTTPS origin")
	ErrInvalidPackage = errors.New("console: invalid static package")
	assetName         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*-[A-Za-z0-9_-]{8,64}\.(js|css|svg|png|jpg|jpeg|webp|ico|woff2)$`)
	caseRoute         = regexp.MustCompile(`^/cases/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	captureRoute      = regexp.MustCompile(`^/captures/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type asset struct {
	data      []byte
	mediaType string
	etag      string
}

type handler struct {
	origin, host string
	shell        []byte
	assets       map[string]asset
}

// New copies a complete, bounded release package from files. The caller must
// supply a trusted package filesystem, typically an embedded or image-owned
// directory. No filesystem reads occur after construction. The exact HTTPS
// origin is installation configuration, never derived from request headers.
//
// Only the landing, new-capture and exact UUID progress/case paths are console
// routes. API, auth and content are composed separately; no general fallback.
func New(origin string, files fs.FS) (http.Handler, error) {
	u, err := canonicalOrigin(origin)
	if err != nil {
		return nil, err
	}
	if files == nil {
		return nil, ErrInvalidPackage
	}
	h := &handler{origin: origin, host: u.Host, assets: make(map[string]asset)}
	names, err := inventory(files)
	if err != nil {
		return nil, err
	}
	total := 0
	for _, name := range names {
		limit := maxAssetBytes
		if name == "index.html" {
			limit = maxShellBytes
		} else if path.Dir(name) != "assets" || len(path.Base(name)) > 160 || !assetName.MatchString(path.Base(name)) {
			return nil, ErrInvalidPackage
		}
		f, e := files.Open(name)
		if e != nil {
			return nil, ErrInvalidPackage
		}
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > int64(limit) {
			_ = f.Close()
			return nil, ErrInvalidPackage
		}
		data, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
		closeErr := f.Close()
		if e != nil || closeErr != nil || len(data) == 0 || len(data) > limit || int64(len(data)) != info.Size() || total > maxTotalBytes-len(data) {
			return nil, ErrInvalidPackage
		}
		total += len(data)
		if name == "index.html" {
			h.shell = data
		} else {
			sum := sha256.Sum256(data)
			h.assets["/"+name] = asset{data, assetType(path.Ext(name)), `"` + hex.EncodeToString(sum[:]) + `"`}
		}
	}
	if len(h.shell) == 0 || !validShell(h.shell, h.assets) {
		return nil, ErrInvalidPackage
	}
	return h, nil
}

// Read directory entries in bounded batches, rather than letting WalkDir read
// an arbitrarily large release directory before applying the inventory limit.
func directory(files fs.FS, name string, limit int) ([]fs.DirEntry, error) {
	f, err := files.Open(name)
	if err != nil {
		return nil, ErrInvalidPackage
	}
	defer f.Close()
	info, err := f.Stat()
	r, ok := f.(fs.ReadDirFile)
	if err != nil || !info.IsDir() || !ok {
		return nil, ErrInvalidPackage
	}
	var entries []fs.DirEntry
	for {
		batch, err := r.ReadDir(limit + 1 - len(entries))
		entries = append(entries, batch...)
		if len(entries) > limit || (err != nil && !errors.Is(err, io.EOF)) {
			return nil, ErrInvalidPackage
		}
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		if len(batch) == 0 {
			return nil, ErrInvalidPackage
		}
	}
}

func inventory(files fs.FS) ([]string, error) {
	root, err := directory(files, ".", 2)
	if err != nil || len(root) != 2 {
		return nil, ErrInvalidPackage
	}
	for _, entry := range root {
		if entry == nil || (entry.Name() == "index.html" && !entry.Type().IsRegular()) || (entry.Name() == "assets" && entry.Type() != fs.ModeDir) || (entry.Name() != "index.html" && entry.Name() != "assets") {
			return nil, ErrInvalidPackage
		}
	}
	entries, err := directory(files, "assets", maxFiles-1)
	if err != nil {
		return nil, ErrInvalidPackage
	}
	names := []string{"index.html"}
	for _, entry := range entries {
		if entry == nil || !entry.Type().IsRegular() || len(entry.Name()) > 160 || !assetName.MatchString(entry.Name()) {
			return nil, ErrInvalidPackage
		}
		names = append(names, "assets/"+entry.Name())
	}
	return names, nil
}

func canonicalOrigin(origin string) (*url.URL, error) {
	u, err := url.Parse(origin)
	if err != nil || len(origin) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != origin || u.Host != strings.ToLower(u.Host) {
		return nil, ErrInvalidOrigin
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return nil, ErrInvalidOrigin
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, ErrInvalidOrigin
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil {
		if len(host) > 253 {
			return nil, ErrInvalidOrigin
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, ErrInvalidOrigin
			}
			for _, c := range label {
				if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
					return nil, ErrInvalidOrigin
				}
			}
		}
	}
	return u, nil
}

func assetType(extension string) string {
	switch extension {
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".ico":
		return "image/x-icon"
	case ".woff2":
		return "font/woff2"
	}
	return ""
}

// validShell validates the deliberately small release entry point, not arbitrary
// HTML or the semantics of trusted JavaScript/CSS. CSP also restricts resources
// requested by those assets. Package provenance and dependency review belong to
// the release pipeline rather than being inferred from this parser.
func validShell(data []byte, assets map[string]asset) bool {
	if !utf8.Valid(data) {
		return false
	}
	z := html.NewTokenizer(bytes.NewReader(data))
	module, inScript := false, false
	for {
		switch z.Next() {
		case html.ErrorToken:
			return errors.Is(z.Err(), io.EOF) && module && !inScript
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if inScript {
				return false
			}
			attributes := map[string]string{}
			for _, a := range t.Attr {
				if _, duplicate := attributes[a.Key]; duplicate || a.Namespace != "" {
					return false
				}
				attributes[a.Key] = a.Val
			}
			allowed := ""
			switch t.Data {
			case "html":
				allowed = " lang dir "
			case "head", "body", "title", "noscript", "p":
			case "div":
				allowed = " id "
			case "meta":
				allowed = " charset name content "
				if name := attributes["name"]; name != "" && name != "viewport" && name != "description" && name != "theme-color" && name != "referrer" {
					return false
				}
				if attributes["name"] == "referrer" && attributes["content"] != "no-referrer" {
					return false
				}
			case "script":
				allowed = " type src crossorigin "
				if attributes["type"] != "module" || !shellAsset(attributes["src"], ".js", assets) {
					return false
				}
				module, inScript = true, true
			case "link":
				allowed = " rel href crossorigin type "
				ext := ""
				switch attributes["rel"] {
				case "stylesheet":
					ext = ".css"
				case "modulepreload":
					ext = ".js"
				case "icon":
					if !strings.HasPrefix(assets[attributes["href"]].mediaType, "image/") {
						return false
					}
				default:
					return false
				}
				if !shellAsset(attributes["href"], ext, assets) {
					return false
				}
			default:
				return false
			}
			for key, value := range attributes {
				if !strings.Contains(allowed, " "+key+" ") || (key == "crossorigin" && value != "" && value != "anonymous") {
					return false
				}
			}
		case html.EndTagToken:
			if inScript {
				if z.Token().Data != "script" {
					return false
				}
				inScript = false
			}
		case html.TextToken:
			if inScript && strings.TrimSpace(string(z.Text())) != "" {
				return false
			}
		}
	}
}

func shellAsset(name, extension string, assets map[string]asset) bool {
	_, ok := assets[name]
	return ok && (extension == "" || path.Ext(name) == extension)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	// Forwarded headers deliberately have no authority. TLS and Host must be
	// correct at this handler; trusted ingress adaptation is a separate boundary.
	if r.TLS == nil || r.Host != h.host || r.URL == nil || r.URL.IsAbs() || r.URL.Opaque != "" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || len(r.RequestURI) > 2048 || r.RequestURI != r.URL.Path || len(r.Header.Values("Authorization")) != 0 || !h.sameOrigin(r) {
		notFound(w, r)
		return
	}
	a, isAsset := h.assets[r.URL.Path]
	if !consoleRoute(r.URL.Path) && !isAsset {
		notFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if isAsset {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Content-Type", a.mediaType)
		w.Header().Set("ETag", a.etag)
		http.ServeContent(assetResponseWriter{w}, r, path.Base(r.URL.Path), time.Time{}, bytes.NewReader(a.data))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(h.shell)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(h.shell)
	}
}

func consoleRoute(path string) bool {
	return path == "/" || path == "/captures/new" || path == "/policies" || captureRoute.MatchString(path) || caseRoute.MatchString(path)
}

// ServeContent removes cache headers on conditional/range errors. Preserve the
// console's explicit error no-store rule instead of relying on cache defaults.
type assetResponseWriter struct{ http.ResponseWriter }

func (w assetResponseWriter) WriteHeader(status int) {
	if status >= 400 {
		w.Header().Set("Cache-Control", "no-store, private")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (h *handler) sameOrigin(r *http.Request) bool {
	if origins := r.Header.Values("Origin"); len(origins) != 0 && (len(origins) != 1 || origins[0] != h.origin) {
		return false
	}
	sites := r.Header.Values("Sec-Fetch-Site")
	if len(sites) > 1 {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	case "same-site", "cross-site":
		// Following an authenticated console navigation link must work. Cross-origin
		// embedding and subresource loads do not need access to the console.
		return r.Method == http.MethodGet && consoleRoute(r.URL.Path) && r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document"
	default:
		return false
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, "Not found\n")
	}
}
