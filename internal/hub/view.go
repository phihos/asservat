package hub

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
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
	if viewer != "pcap" && viewer != "pprof" {
		return errStatus{http.StatusBadRequest, "this file is not opened in the hub; its viewer reads it in the browser, or it only downloads"}
	}
	if err := h.Store.Audit(r.Context(), u.Name, "artifact.view", c.ID, map[string]string{"name": a.Name}); err != nil {
		return err
	}
	// The view ends with the stream, whichever way the stream ends.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	opened := &view{user: u.Name, capture: c.ID, end: cancel}
	if viewer == "pcap" {
		opened.ask, err = h.dissect(ctx, a)
	} else {
		opened.pages, err = h.profilePages(ctx, a)
	}
	if err != nil {
		return err
	}
	id := uuid.NewString()
	h.views.add(id, opened)
	defer h.views.remove(id)

	w.Header().Set("Content-Type", "text/event-stream")
	fmt.Fprintf(w, "data: %s\n\n", id)
	http.NewResponseController(w).Flush()
	<-ctx.Done()
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
	if page == nil {
		return ErrNotFound
	}
	page.ServeHTTP(w, r)
	return nil
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
