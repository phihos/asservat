package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"asservat.local/asservat/internal/coredesc"
)

// A core's description is made once, by the agent that recorded it. A
// later Asservat may describe the same core better. The capture keeps the
// program's files next to the core for that: when a core is opened whose
// description is from an older describer, the hub describes it again from
// the stored core and files, and stores the new description in place of
// the old.

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
	described, reason, err := h.describeAgain(r.Context(), c.ID, in.Name)
	if err != nil {
		return err
	}
	if described {
		if err := h.Store.Audit(r.Context(), u.Name, "artifact.describe", c.ID, map[string]string{"name": in.Name}); err != nil {
			return err
		}
		h.notify(c.ID)
	}
	return reply(w, map[string]any{"described": described, "reason": reason})
}

// describeAgain describes the core of the name anew if its description is
// older than this hub makes them and the capture holds the program's
// files. Otherwise it says in reason why not.
func (h *Hub) describeAgain(ctx context.Context, capture, name string) (described bool, reason string, err error) {
	core, err := h.Store.Artifact(ctx, capture, name)
	if err != nil {
		return false, "", err
	}
	// One at a time for a core: who asks meanwhile waits and finds it done.
	key := capture + "/" + name
	for {
		h.mu.Lock()
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
	if old, err := h.Store.Artifact(ctx, capture, name+coredesc.Suffix); err == nil {
		var report bytes.Buffer
		if err := h.plain(ctx, old, &report); err != nil {
			return false, "", err
		}
		if coredesc.DescribedBy(report.Bytes()) >= coredesc.Version {
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
	go func() { unpacked.CloseWithError(h.plain(ctx, files, unpacked)) }()
	err = coredesc.ExtractFiles(archive, root)
	archive.CloseWithError(err)
	if err != nil {
		return false, "", err
	}
	report, err := coredesc.Describer{Scratch: h.WorkDir, DebuginfodURLs: h.DebuginfodURLs}.Describe(ctx, file.Name(), root) // what gdb downloads stays for the next core
	if err != nil {
		return false, "", err
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
