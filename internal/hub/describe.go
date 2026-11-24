package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"asservat.local/asservat/internal/api"

	"asservat.local/asservat/internal/coredesc"
)

// A core's description is begun by the agent that recorded it, with gdb
// and Delve. The stacks of Python and .NET programs are read by tools that
// the agent's image leaves out, to stay small on every node: the hub adds
// them when the core and the program's files have arrived (completed). A
// later Asservat may also describe the same core better: when a core is
// opened whose description is from an older describer, the hub describes
// it again from the stored core and files. Either way it stores the new
// description in place of the old.

// describe is asked by the core viewer before it shows a core. It answers
// whether the description was made anew.
func (h *Hub) describe(w http.ResponseWriter, r *http.Request, u User) error {
	var in struct{ Name string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return errStatus{http.StatusBadRequest, "invalid JSON"}
	}
	c, err := h.visible(r.Context(), u, r.PathValue("id"))
	if err != nil {
		return err
	}
	if api.ViewerOf(in.Name) != "core" || strings.HasSuffix(in.Name, coredesc.Suffix) {
		return errStatus{http.StatusBadRequest, "the file is no core"}
	}
	// The work goes on when the viewer that asked is closed: the next one
	// finds it done. It takes seconds, or minutes with debug information
	// to download; a gdb that hangs gives the core's turn back after 15.
	done := h.renew(r.Context(), u, c.ID, in.Name)
	// A description can take longer than a proxy waits for an answer: the
	// answer begins with spaces, one for every beat of the hub's streams,
	// which JSON allows before a value.
	beat := time.NewTicker(h.StreamBeat)
	defer beat.Stop()
	begun := false
	for {
		select {
		case <-r.Context().Done():
			return nil
		case result := <-done:
			if result.err != nil && !begun {
				return result.err
			}
			if result.err != nil {
				slog.Error("core not described again", "capture", c.ID, "name", in.Name, "error", result.err)
				result.described, result.reason = false, "the hub could not describe the core again now"
			}
			return reply(w, map[string]any{"described": result.described, "reason": result.reason})
		case <-beat.C:
			if !begun {
				w.Header().Set("Content-Type", "application/json")
				begun = true
			}
			io.WriteString(w, " ")
			http.NewResponseController(w).Flush()
		}
	}
}

// renewed is what became of describing a core again: whether it was, or
// why not.
type renewed struct {
	described bool
	reason    string
	err       error
}

// renew describes a core again where its description is older than this
// hub makes them or awaits a runtime's stacks, for the user who opens it
// (none where the hub completes what an agent sent), and tells on the
// channel what became of it. The work goes on when the one who asked has gone: the next
// finds it done. It takes seconds, or minutes with debug information to
// download; a gdb that hangs gives the core's turn back after 15.
func (h *Hub) renew(ctx context.Context, u User, capture, name string) <-chan renewed {
	done := make(chan renewed, 1)
	go func() {
		work, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
		defer cancel()
		described, reason, err := h.describeAgain(work, capture, name)
		var cannot undescribable
		switch {
		case errors.As(err, &cannot):
			// The description as it is still shows. What the core or its
			// files make fail fails again: it is not tried for this core
			// until the hub starts anew. Other failures, as of the store,
			// pass.
			slog.Warn("core not described again", "capture", capture, "name", name, "error", err)
			h.mu.Lock()
			h.undescribed[capture+"/"+name] = true
			h.mu.Unlock()
			described, reason, err = false, "this Asservat could not describe the core again", nil
		case err == nil && described:
			// The description is stored: that is the answer, whatever
			// becomes of its audit entry. Completing what the agent sent
			// is part of the recording, no one's act.
			if u.Name != "" {
				if err := h.Store.Audit(work, u.Name, "artifact.describe", capture, map[string]string{"name": name}); err != nil {
					slog.Error("audit", "action", "artifact.describe", "capture", capture, "error", err)
				}
			}
			h.notify(capture)
		}
		done <- renewed{described, reason, err}
	}()
	return done
}

// undescribable is the failure to describe a core that lies in the core or
// its files, not in what the hub needs around them.
type undescribable struct{ error }

// describeAgain describes the core of the name anew if its description is
// older than this hub makes them, or adds the stacks of the runtimes that
// it awaits, if the capture holds the program's files. Otherwise it says
// in reason why not.
func (h *Hub) describeAgain(ctx context.Context, capture, name string) (described bool, reason string, err error) {
	core, err := h.Store.Artifact(ctx, capture, name)
	if err != nil {
		return false, "", err
	}
	// One at a time for a core: who asks meanwhile waits and finds it done.
	key := capture + "/" + name
	for {
		h.mu.Lock()
		if h.undescribed[key] {
			h.mu.Unlock()
			return false, "this Asservat could not describe the core again", nil
		}
		running := h.describing[key]
		if running == nil {
			if h.describing == nil {
				h.describing = map[string]chan struct{}{}
			}
			running = make(chan struct{})
			h.describing[key] = running
			h.mu.Unlock()
			defer func() {
				h.mu.Lock()
				delete(h.describing, key)
				h.mu.Unlock()
				close(running)
			}()
			break
		}
		h.mu.Unlock()
		select {
		case <-running:
		case <-ctx.Done():
			return false, "", ctx.Err()
		}
	}
	// The numbers of the threads inside their container, which only the
	// agent could tell, are kept from the description that is replaced.
	describer := coredesc.Describer{Scratch: h.WorkDir, DebuginfodURLs: h.DebuginfodURLs, PystackPython: h.pystack} // what gdb downloads stays for the next core
	var begun []byte
	if old, err := h.Store.Artifact(ctx, capture, name+coredesc.Suffix); err == nil {
		var report bytes.Buffer
		if err := h.plain(ctx, old, &report); err != nil {
			return false, "", err
		}
		switch {
		case coredesc.DescribedBy(report.Bytes()) < coredesc.Version:
			describer.ThreadIDs = coredesc.ThreadIDs(report.Bytes())
		case describer.Completes(report.Bytes()):
			begun = report.Bytes()
		default:
			return false, "", nil
		}
	} else if err != ErrNotFound {
		return false, "", err
	}
	files, err := h.Store.Artifact(ctx, capture, name+coredesc.FilesSuffix)
	if err == ErrNotFound {
		return false, "the capture was made before Asservat kept the program's files with a core", nil
	}
	if err != nil {
		return false, "", err
	}

	dir, err := os.MkdirTemp(h.WorkDir, "describe-*")
	if err != nil {
		return false, "", err
	}
	defer os.RemoveAll(dir)
	file, err := os.Create(filepath.Join(dir, "core"))
	if err != nil {
		return false, "", err
	}
	err = h.plain(ctx, core, file)
	if e := file.Close(); err == nil {
		err = e
	}
	if err != nil {
		return false, "", err
	}
	root := filepath.Join(dir, "root")
	archive, unpacked := io.Pipe()
	read := make(chan error, 1)
	go func() {
		err := h.plain(ctx, files, unpacked)
		unpacked.CloseWithError(err)
		read <- err
	}()
	err = coredesc.ExtractFiles(archive, root, files.Size)
	archive.CloseWithError(err)
	// An archive that the store could not hand over is not a bad archive.
	// The store's reader is told why unpacking ended: that is not its failure.
	if stored := <-read; stored != nil && !errors.Is(stored, io.ErrClosedPipe) && (err == nil || !errors.Is(stored, err)) {
		return false, "", stored
	}
	if err != nil {
		return false, "", undescribable{err}
	}
	var report []byte
	if begun != nil {
		report = describer.Complete(ctx, begun, file.Name(), root)
	} else {
		report, err = describer.Describe(ctx, file.Name(), root)
	}
	if ctx.Err() != nil {
		return false, "", ctx.Err() // the hub is stopping or the time is up: no fault of the core, and nothing to store
	}
	if err != nil {
		return false, "", undescribable{err}
	}
	a, err := h.keep(ctx, name+coredesc.Suffix, bytes.NewReader(report))
	if err != nil {
		return false, "", err
	}
	old, replaced, err := h.Store.ReplaceArtifact(ctx, capture, a)
	if err != nil || !replaced {
		h.Blobs.Delete(context.WithoutCancel(ctx), a.Blob)
		return false, "", err
	}
	if old != "" {
		h.Blobs.Delete(context.WithoutCancel(ctx), old)
	}
	return true, "", nil
}
