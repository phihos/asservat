package hub

import (
	"bufio"
	"bytes"
	"cmp"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
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

// straceSummary reads a trace of system calls and returns what "strace -c"
// would print of it, as the viewer's summary does: for each call its share
// of the time, the seconds, the microseconds per call, how often it was
// called and how often it failed. The time is the time spent in the call,
// so calls that wait, as futex or epoll_pwait, lead it. A call that another
// process interrupted, which strace prints in two lines, is one call. The
// trace is read as a stream, a line at a time: of a line longer than the
// buffer, as a write of a large buffer, only its beginning and end are kept.
func straceSummary(trace io.Reader) (string, error) {
	type sum struct {
		name          string
		calls, errors int
		seconds       float64
	}
	per := map[string]*sum{}
	of := func(name string) *sum {
		if per[name] == nil {
			per[name] = &sum{name: name}
		}
		return per[name]
	}
	// end takes a call's result and duration from the end of its line.
	end := func(s *sum, tail string) {
		if took := straceTook.FindStringSubmatchIndex(tail); took != nil {
			seconds, _ := strconv.ParseFloat(tail[took[2]:took[3]], 64)
			s.seconds += seconds
			tail = tail[:took[0]]
		}
		if straceFailed.MatchString(tail) {
			s.errors++
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
			return "", err
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
		s.calls++
		if strings.HasSuffix(ending, " <unfinished ...>") {
			open[pid] = s.name
		} else {
			end(s, ending)
		}
	}
	rows := make([]*sum, 0, len(per))
	all := sum{name: "total"}
	for _, s := range per {
		rows = append(rows, s)
		all.calls, all.errors, all.seconds = all.calls+s.calls, all.errors+s.errors, all.seconds+s.seconds
	}
	slices.SortFunc(rows, func(a, b *sum) int {
		return cmp.Or(cmp.Compare(b.seconds, a.seconds), cmp.Compare(b.calls, a.calls), cmp.Compare(a.name, b.name))
	})
	var out bytes.Buffer
	fmt.Fprintf(&out, "%d calls of %d system calls, %.6f s in them (the time a call took, so calls that wait lead). With offset instead of summary the trace is read as text.\n\n", all.calls, len(rows), all.seconds)
	fmt.Fprintf(&out, "%6s %12s %11s %9s %9s %s\n", "% time", "seconds", "usecs/call", "calls", "errors", "syscall")
	row := func(s *sum) {
		share, each, errors := 0.0, 0.0, ""
		if all.seconds > 0 {
			share = s.seconds * 100 / all.seconds
		}
		if s.calls > 0 {
			each = s.seconds * 1e6 / float64(s.calls)
		}
		if s.errors > 0 {
			errors = strconv.Itoa(s.errors)
		}
		fmt.Fprintf(&out, "%6.2f %12.6f %11.0f %9d %9s %s\n", share, s.seconds, each, s.calls, errors, s.name)
	}
	for _, s := range rows {
		row(s)
	}
	row(&all)
	return out.String(), nil
}
