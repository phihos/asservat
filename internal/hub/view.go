package hub

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"

	"asservat.local/asservat/internal/api"
)

// A file is looked at in the browser without leaving the hub: the hub opens
// it with the program that people use for such files and answers the
// viewer's questions about it. An open file is a view. It lives as long as
// the browser keeps the stream that opened it, so nothing has to guess when
// somebody stopped looking.

// view is one file that a user has open.
type view struct {
	user    string
	capture string
	// end closes the view; its stream ends with it.
	end context.CancelFunc
	// ask sends one question to the program that holds the file, for a
	// viewer that asks: the packet viewer.
	ask func(method string, params json.RawMessage) (json.RawMessage, error)
	// pages are the pages of a tool's own web interface, by path, for a
	// viewer that shows it: pprof's.
	pages map[string]http.Handler
	// tool serves every page of a tool that runs beside the hub: Go's
	// trace tool.
	tool http.Handler
}

type views struct {
	mu   sync.Mutex
	open map[string]*view
}

func (v *views) add(id string, opened *view) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.open[id] = opened
}

func (v *views) remove(id string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.open, id)
}

// endOf closes the views of a capture's files, when the capture is deleted.
func (v *views) endOf(capture string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, opened := range v.open {
		if opened.capture == capture {
			opened.end()
		}
	}
}

func (v *views) get(id string) *view {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.open[id]
}

// openView opens an artifact for its viewer and tells the browser the view's
// ID. The response is an event stream that stays open; closing it ends the
// view.
func (h *Hub) openView(w http.ResponseWriter, r *http.Request, u User) error {
	c, err := h.visible(r.Context(), u, r.PathValue("id"))
	if err != nil {
		return err
	}
	a, err := h.Store.Artifact(r.Context(), c.ID, r.PathValue("name"))
	if err != nil {
		return err
	}
	viewer := api.ViewerOf(a.Name)
	if viewer != "pcap" && viewer != "pprof" && viewer != "gotrace" && viewer != "heap" {
		return errStatus{http.StatusBadRequest, "this file is not opened in the hub; its viewer reads it in the browser, or it only downloads"}
	}
	if err := h.Store.Audit(r.Context(), u.Name, "artifact.view", c.ID, map[string]string{"name": a.Name}); err != nil {
		return err
	}
	// The view ends with the stream, whichever way the stream ends.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	opened := &view{user: u.Name, capture: c.ID, end: cancel}
	id := uuid.NewString()
	switch viewer {
	case "pcap":
		opened.ask, err = h.dissect(ctx, a)
	case "gotrace":
		opened.tool, err = h.tracePages(ctx, a, "/api/views/"+id+"/pages")
	case "heap":
		opened.pages, err = h.heapPages(ctx, a)
	default:
		// "base" names another profile, as "<capture>/<file>": pprof then
		// shows this profile minus that one.
		var base *storedArtifact
		if named := r.URL.Query().Get("base"); named != "" {
			id, name, _ := strings.Cut(named, "/")
			from, err := h.visible(ctx, u, id)
			if err != nil {
				return err
			}
			b, err := h.Store.Artifact(ctx, from.ID, name)
			if err != nil {
				return err
			}
			if api.ViewerOf(b.Name) != "pprof" {
				return errStatus{http.StatusBadRequest, "the base is not a profile"}
			}
			base = &b
		}
		opened.pages, err = h.profilePages(ctx, a, base)
	}
	if err != nil {
		return err
	}
	h.views.add(id, opened)
	defer h.views.remove(id)

	h.stream(ctx, w, "data: "+id, nil)
	return nil
}

// sharkdMethods are the questions a viewer may ask Wireshark's sharkd. All
// of them read the loaded capture; none opens files or changes settings.
var sharkdMethods = map[string]bool{
	"status":    true, // number of packets, duration
	"frames":    true, // rows of the packet list
	"frame":     true, // one packet's tree and bytes
	"intervals": true, // how many packets a filter shows
	"check":     true, // whether a display filter is valid
	"complete":  true, // field names for the filter input
	"follow":    true, // the payload of a stream
	"tap":       true, // statistics; see allowedTaps
}

// tapName matches the statistics that a viewer may ask sharkd for:
// conversations and endpoints of a protocol, expert information and the
// protocol hierarchy. sharkd has other taps; these only count packets.
var tapName = regexp.MustCompile(`^(?:(?:conv|endpt):[A-Za-z0-9]+|expert|phs)$`)

// allowedTaps reports whether a "tap" question names only such statistics,
// with or without a display filter.
func allowedTaps(params json.RawMessage) bool {
	var asked map[string]json.RawMessage
	if json.Unmarshal(params, &asked) != nil {
		return false
	}
	for key, value := range asked {
		var text string
		if json.Unmarshal(value, &text) != nil {
			return false
		}
		if key != "filter" && !(strings.HasPrefix(key, "tap") && tapName.MatchString(text)) {
			return false
		}
	}
	return true
}

// askView passes a viewer's question to its view.
func (h *Hub) askView(w http.ResponseWriter, r *http.Request, u User) error {
	v := h.views.get(r.PathValue("view"))
	if v == nil || v.user != u.Name || v.ask == nil {
		return ErrNotFound
	}
	method := r.PathValue("method")
	if !sharkdMethods[method] {
		return errStatus{http.StatusBadRequest, "unknown question"}
	}
	params, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	if !json.Valid(params) {
		return errStatus{http.StatusBadRequest, "the question is not JSON"}
	}
	if method == "tap" && !allowedTaps(params) {
		return errStatus{http.StatusBadRequest, "unknown statistics"}
	}
	result, err := v.ask(method, params)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(result)
	return err
}

// viewPage serves a page of the tool's web interface that a view holds.
func (h *Hub) viewPage(w http.ResponseWriter, r *http.Request, u User) error {
	v := h.views.get(r.PathValue("view"))
	if v == nil || v.user != u.Name {
		return ErrNotFound
	}
	page := v.pages["/"+r.PathValue("page")]
	if page == nil && v.tool != nil {
		// The tool sees the page's address as its own.
		r.URL.Path = "/" + r.PathValue("page")
		page = v.tool
	}
	if page == nil {
		return ErrNotFound
	}
	// The trace viewer under /trace is an application of its own, with its own look.
	if r.URL.Path == "/trace" {
		page.ServeHTTP(w, r)
		return nil
	}
	framed := &framedPage{ResponseWriter: w}
	page.ServeHTTP(framed, r)
	framed.end()
	return nil
}

// framedLook is added to the pages that a tool draws itself, so that they
// are set in Asservat's type inside the viewer's frame.
const framedLook = `<link rel="stylesheet" href="/assets/identity.css"><link rel="stylesheet" href="/view/framed.css">`

// framedPage passes a tool's response on and adds framedLook to an HTML
// page, before its body and so after the page's own styles. It holds such
// a page until the tool has written all of it; anything else is passed on
// as it comes.
type framedPage struct {
	http.ResponseWriter
	decided, html bool
	page          bytes.Buffer
}

func (f *framedPage) Unwrap() http.ResponseWriter { return f.ResponseWriter }

// decide tells from the response's type, or else from its first bytes,
// whether it is an HTML page.
func (f *framedPage) decide(first []byte) {
	if f.decided {
		return
	}
	f.decided = true
	kind := f.Header().Get("Content-Type")
	if kind == "" && first != nil {
		kind = http.DetectContentType(first)
	}
	if f.html = strings.HasPrefix(kind, "text/html"); f.html {
		f.Header().Del("Content-Length")
	}
}

func (f *framedPage) WriteHeader(status int) {
	f.decide(nil)
	f.ResponseWriter.WriteHeader(status)
}

func (f *framedPage) Write(p []byte) (int, error) {
	f.decide(p)
	if f.html {
		return f.page.Write(p)
	}
	return f.ResponseWriter.Write(p)
}

func (f *framedPage) end() {
	if f.html {
		f.ResponseWriter.Write(bytes.Replace(f.page.Bytes(), []byte("<body"), []byte(framedLook+"<body"), 1))
	}
}

// plain writes an artifact, decrypted, to w.
func (h *Hub) plain(ctx context.Context, a storedArtifact, w io.Writer) error {
	key, err := unwrapKey(h.MasterKey, a.Key)
	if err != nil {
		return err
	}
	blob, err := h.Blobs.Get(ctx, a.Blob)
	if err != nil {
		return err
	}
	defer blob.Close()
	return decrypt(w, blob, key)
}

// dissect loads a packet capture into Wireshark's sharkd, which runs until
// ctx ends, and returns how to ask it. sharkd needs the capture as a file:
// the hub decrypts it into its work directory and removes the name as soon
// as sharkd holds the file open.
func (h *Hub) dissect(ctx context.Context, a storedArtifact) (func(string, json.RawMessage) (json.RawMessage, error), error) {
	file, err := os.CreateTemp(h.WorkDir, "view-*"+path.Ext(a.Name))
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

	cmd := exec.CommandContext(ctx, h.Sharkd, "-")
	// sharkd reads its settings from the home directory; it has none here.
	cmd.Env = append(os.Environ(), "HOME="+h.WorkDir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, errStatus{http.StatusNotImplemented, "this hub cannot show packet captures: " + err.Error()}
	}
	go cmd.Wait() // ends with ctx; reaps the process

	// sharkd answers one question at a time, each with one line.
	var mu sync.Mutex
	answers := bufio.NewReader(stdout)
	next := 0
	ask := func(method string, params json.RawMessage) (json.RawMessage, error) {
		mu.Lock()
		defer mu.Unlock()
		next++
		question, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": next, "method": method, "params": params})
		if err != nil {
			return nil, err
		}
		if _, err := stdin.Write(append(question, '\n')); err != nil {
			return nil, errViewEnded
		}
		for {
			line, err := answers.ReadBytes('\n')
			if err != nil {
				return nil, errViewEnded
			}
			var answer struct {
				ID     int             `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			// sharkd also prints notices that answer nothing.
			if json.Unmarshal(line, &answer) != nil || answer.ID != next {
				continue
			}
			if answer.Error != nil {
				return nil, errStatus{http.StatusBadRequest, answer.Error.Message}
			}
			return answer.Result, nil
		}
	}
	load, _ := json.Marshal(map[string]string{"file": file.Name()})
	if _, err := ask("load", load); err != nil {
		return nil, fmt.Errorf("load packet capture: %w", err)
	}
	return ask, nil
}

var errViewEnded = errStatus{http.StatusGone, "this view has ended; open the file again"}

// packetText returns a packet capture as text, for readers that cannot open
// the viewer. Without a filter it is the statistics of Wireshark's menu:
// the protocols, the conversations and the expert information. With a
// display filter, as Wireshark takes them, it is the packets that match, as
// the rows of the packet list. Both list 60 entries: a page for a reader,
// of whom most are language models with a limited context.
func (h *Hub) packetText(ctx context.Context, a storedArtifact, filter string) (string, error) {
	const entries = 60
	ctx, done := context.WithCancel(ctx)
	defer done() // ends sharkd
	ask, err := h.dissect(ctx, a)
	if err != nil {
		return "", err
	}
	asked := func(method string, params any, into any) error {
		question, err := json.Marshal(params)
		if err != nil {
			return err
		}
		answer, err := ask(method, question)
		if err != nil {
			return err
		}
		return json.Unmarshal(answer, into)
	}
	var status struct {
		Frames   int
		Duration float64
	}
	if err := asked("status", struct{}{}, &status); err != nil {
		return "", err
	}
	var text strings.Builder
	fmt.Fprintf(&text, "%d packets over %s s.\n", status.Frames, strconv.FormatFloat(status.Duration, 'f', -1, 64))
	if filter != "" {
		if _, err := ask("check", json.RawMessage(`{"filter":`+strconv.Quote(filter)+`}`)); err != nil {
			return "", errStatus{http.StatusBadRequest, "the display filter is not valid: " + err.Error()}
		}
		var frames []struct {
			C []string
		}
		if err := asked("frames", map[string]any{"filter": filter, "limit": entries}, &frames); err != nil {
			return "", err
		}
		fmt.Fprintf(&text, "\nThe first %d packets that match %q (number, seconds, source, destination, protocol, length, info):\n", len(frames), filter)
		for _, f := range frames {
			text.WriteString(strings.Join(f.C, "  ") + "\n")
		}
		return text.String(), nil
	}
	var stats struct {
		Taps []struct {
			Tap    string
			Protos []packetProtocol
			Convs  []struct {
				Saddr, Sport, Daddr, Dport string
				Txf, Txb, Rxf, Rxb         int64
				Start, Stop                float64
			}
			Details []struct{ S, G, M, P string }
		}
	}
	if err := asked("tap", map[string]string{"tap0": "phs", "tap1": "conv:TCP", "tap2": "conv:UDP", "tap3": "expert"}, &stats); err != nil {
		return "", err
	}
	// sharkd answers in its own order: the parts are put into that of the request.
	wanted := []string{"phs", "conv:TCP", "conv:UDP", "expert"}
	sort.SliceStable(stats.Taps, func(i, j int) bool {
		return slices.Index(wanted, stats.Taps[i].Tap) < slices.Index(wanted, stats.Taps[j].Tap)
	})
	for _, tap := range stats.Taps {
		switch {
		case tap.Tap == "phs":
			text.WriteString("\nProtocols, each within the one above it (packets, bytes):\n")
			var walk func([]packetProtocol, int)
			walk = func(list []packetProtocol, depth int) {
				for _, p := range list {
					fmt.Fprintf(&text, "%s%s  %d packets, %d bytes\n", strings.Repeat("  ", depth), p.Proto, p.Frames, p.Bytes)
					walk(p.Protos, depth+1)
				}
			}
			walk(tap.Protos, 1)
		case strings.HasPrefix(tap.Tap, "conv:") && len(tap.Convs) > 0:
			sort.Slice(tap.Convs, func(i, j int) bool { return tap.Convs[i].Txb+tap.Convs[i].Rxb > tap.Convs[j].Txb+tap.Convs[j].Rxb })
			fmt.Fprintf(&text, "\n%d %s conversations, the largest first (A <-> B: packets and bytes from A, from B, seconds from start to end):\n", len(tap.Convs), strings.TrimPrefix(tap.Tap, "conv:"))
			for _, c := range tap.Convs[:min(len(tap.Convs), entries)] {
				fmt.Fprintf(&text, "  %s:%s <-> %s:%s: %d packets %d bytes, %d packets %d bytes, %.3f to %.3f\n", c.Saddr, c.Sport, c.Daddr, c.Dport, c.Txf, c.Txb, c.Rxf, c.Rxb, c.Start, c.Stop)
			}
		case tap.Tap == "expert" && len(tap.Details) > 0:
			// The same remark on many packets is told once, with its number.
			counts, order := map[string]int{}, []string{}
			for _, d := range tap.Details {
				remark := fmt.Sprintf("%s (%s, %s): %s", d.S, d.G, d.P, d.M)
				if counts[remark] == 0 {
					order = append(order, remark)
				}
				counts[remark]++
			}
			sort.SliceStable(order, func(i, j int) bool { return counts[order[i]] > counts[order[j]] })
			text.WriteString("\nWireshark's expert information, the most frequent first:\n")
			for _, remark := range order[:min(len(order), entries)] {
				fmt.Fprintf(&text, "  %d × %s\n", counts[remark], remark)
			}
		}
	}
	text.WriteString("\nTo list packets, read the file again with \"filter\": a Wireshark display filter such as \"tcp.analysis.retransmission\", \"http.response.code >= 500\" or \"ip.addr == 10.0.0.1 and tcp.port == 8080\".\n")
	return text.String(), nil
}

// packetProtocol is a protocol of the hierarchy that sharkd reports.
type packetProtocol struct {
	Proto         string
	Frames, Bytes int64
	Protos        []packetProtocol
}
