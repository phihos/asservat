package hub

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"asservat.local/asservat/internal/api"
)

// A line of strace (-f -tt -T): the process, the time and the rest.
var straceLine = regexp.MustCompile(`^(?:\[pid\s+)?(\d+)?\]?\s*\d\d:\d\d:\d\d(?:\.\d+)? (.*)$`)

// The end of a call: its result and how long it took.
var (
	straceName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	straceResumed = regexp.MustCompile(`^<\.\.\. (\S+) resumed>`)
	straceTook    = regexp.MustCompile(` <(\d+\.\d+)>$`)
	straceFailed  = regexp.MustCompile(`\)\s+= -1\b[^)]*(?:\([^)]*\))?$`)
)

// straceCall is a system call's row of a trace's summary.
type straceCall struct {
	Name    string  `json:"name"`
	Calls   int     `json:"calls"`
	Errors  int     `json:"errors"`
	Seconds float64 `json:"seconds"`
}

// straceCalls reads a trace of system calls and returns what "strace -c"
// would print of it, as the viewer's summary does: for each call how often
// it was called, how often it failed and the time spent in it, the longest
// first, and their total. A call that another process interrupted, which
// strace prints in two lines, is one call. The trace is read as a stream, a
// line at a time: of a line longer than the buffer, as a write of a large
// buffer, only its beginning and end are kept.
func straceCalls(trace io.Reader) (rows []straceCall, all straceCall, err error) {
	type sum = straceCall
	per := map[string]*sum{}
	of := func(name string) *sum {
		if per[name] == nil {
			per[name] = &sum{Name: name}
		}
		return per[name]
	}
	// end takes a call's result and duration from the end of its line.
	end := func(s *sum, tail string) {
		if took := straceTook.FindStringSubmatchIndex(tail); took != nil {
			seconds, _ := strconv.ParseFloat(tail[took[2]:took[3]], 64)
			s.Seconds += seconds
			tail = tail[:took[0]]
		}
		if straceFailed.MatchString(tail) {
			s.Errors++
		}
	}
	open := map[string]string{} // the call that a process is in, by process
	lines := bufio.NewReaderSize(trace, 64<<10)
	for {
		head, long, err := lines.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, all, err
		}
		line, tail := string(head), ""
		for long {
			var rest []byte
			if rest, long, err = lines.ReadLine(); err != nil {
				break
			}
			tail = string(rest)
		}
		m := straceLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pid, rest := m[1], m[2]
		// The end of a long line is where its result stands.
		ending := rest
		if tail != "" {
			ending = tail
		}
		if straceResumed.MatchString(rest) {
			if name, was := open[pid]; was {
				delete(open, pid)
				end(of(name), ending)
			}
			continue
		}
		paren := strings.IndexByte(rest, '(')
		// A call has the name of a function: anything else before a bracket is no call, and would be a row of its own.
		if strings.HasPrefix(rest, "---") || strings.HasPrefix(rest, "+++") || paren < 0 || !straceName.MatchString(rest[:paren]) {
			continue
		}
		s := of(rest[:paren])
		s.Calls++
		if strings.HasSuffix(ending, " <unfinished ...>") {
			open[pid] = s.Name
		} else {
			end(s, ending)
		}
	}
	all.Name = "total"
	for _, s := range per {
		rows = append(rows, *s)
		all.Calls, all.Errors, all.Seconds = all.Calls+s.Calls, all.Errors+s.Errors, all.Seconds+s.Seconds
	}
	slices.SortFunc(rows, func(a, b straceCall) int {
		return cmp.Or(cmp.Compare(b.Seconds, a.Seconds), cmp.Compare(b.Calls, a.Calls), cmp.Compare(a.Name, b.Name))
	})
	return rows, all, nil
}

// straceText is a trace's summary as text, in the columns of "strace -c".
// The time is the time spent in a call, so calls that wait, as futex or
// epoll_pwait, lead it.
func straceText(rows []straceCall, all straceCall) string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "%d calls of %d system calls, %.6f s in them (the time a call took, so calls that wait lead). With offset instead of summary the trace is read as text.\n\n", all.Calls, len(rows), all.Seconds)
	fmt.Fprintf(&out, "%6s %12s %11s %9s %9s %s\n", "% time", "seconds", "usecs/call", "calls", "errors", "syscall")
	for _, s := range append(slices.Clone(rows), all) {
		share, each, errors := 0.0, 0.0, ""
		if all.Seconds > 0 {
			share = s.Seconds * 100 / all.Seconds
		}
		if s.Calls > 0 {
			each = s.Seconds * 1e6 / float64(s.Calls)
		}
		if s.Errors > 0 {
			errors = strconv.Itoa(s.Errors)
		}
		fmt.Fprintf(&out, "%6.2f %12.6f %11.0f %9d %9s %s\n", share, s.Seconds, each, s.Calls, errors, s.Name)
	}
	return out.String()
}

// traceSummary is the summary of a stored trace, read as it is unpacked.
func (h *Hub) traceSummary(ctx context.Context, a storedArtifact) ([]straceCall, straceCall, error) {
	key, err := unwrapKey(h.MasterKey, a.Key)
	if err != nil {
		return nil, straceCall{}, err
	}
	blob, err := h.Blobs.Get(ctx, a.Blob)
	if err != nil {
		return nil, straceCall{}, err
	}
	defer blob.Close()
	trace, unpacking := io.Pipe()
	go func() { unpacking.CloseWithError(unpacked(unpacking, blob, key, a.Packed)) }()
	rows, all, err := straceCalls(trace)
	trace.CloseWithError(err)
	if err != nil {
		return nil, all, fmt.Errorf("read %s: %w", a.Name, err)
	}
	return rows, all, nil
}

// errNoTrace refuses the summary of a file that is no trace of system calls.
var errNoTrace = errStatus{http.StatusBadRequest, "summary is for system call traces (*.strace)"}

// summary serves a trace's summary to the viewer, which loads only the
// beginning of a large trace and could not sum up the rest.
func (h *Hub) summary(w http.ResponseWriter, r *http.Request, u User) error {
	c, err := h.visible(r.Context(), u, r.PathValue("id"))
	if err != nil {
		return err
	}
	a, err := h.Store.Artifact(r.Context(), c.ID, r.PathValue("name"))
	if err != nil {
		return err
	}
	if api.ViewerOf(a.Name) != "strace" {
		return errNoTrace
	}
	if err := h.Store.Audit(r.Context(), u.Name, "artifact.view", c.ID, map[string]any{"name": a.Name, "summary": true}); err != nil {
		return err
	}
	rows, all, err := h.traceSummary(r.Context(), a)
	if err != nil {
		return err
	}
	return reply(w, map[string]any{"calls": rows, "total": all})
}
