package kubernetes

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/targets"
)

// logReaders bounds concurrent pods/log reads of one observation (ADR-241);
// the client's own 20 requests/s limiter still applies.
const logReaders = 8

// logProgram mirrors the compiler's bound on a log regexp's compiled size.
const logProgram = 4096

// logMatcher is a compiled ADR-241 record predicate. It runs only the
// linear-time RE2 engine or a substring search; nothing in a record is
// executed or followed.
type logMatcher struct {
	literal []byte
	re      *regexp.Regexp
	path    []string
}

func newLogMatcher(m value.LogMatch) (logMatcher, error) {
	if !m.Valid() {
		return logMatcher{}, value.ErrInvalid
	}
	out := logMatcher{literal: []byte(m.Pattern)}
	if m.JSONField != "" {
		out.path = strings.Split(m.JSONField, ".")
	}
	if m.Regexp {
		parsed, err := syntax.Parse(m.Pattern, syntax.Perl)
		if err != nil {
			return logMatcher{}, value.ErrInvalid
		}
		prog, err := syntax.Compile(parsed.Simplify())
		if err != nil || len(prog.Inst) > logProgram {
			return logMatcher{}, value.ErrInvalid
		}
		if out.re, err = regexp.Compile(m.Pattern); err != nil {
			return logMatcher{}, value.ErrInvalid
		}
	}
	return out, nil
}

func (m logMatcher) match(record []byte) bool {
	if len(m.path) > 0 {
		v, ok := logJSONField(record, m.path)
		if !ok {
			return false
		}
		record = v
	}
	if m.re != nil {
		return m.re.Match(record)
	}
	return bytes.Contains(record, m.literal)
}

// logJSONField returns the text of the JSON value at path in a record that
// is a JSON object: a string's decoded text, or a number's or boolean's
// literal. Objects, arrays, null, a missing key or invalid JSON never match.
func logJSONField(record []byte, path []string) ([]byte, bool) {
	raw := json.RawMessage(record)
	for _, key := range path {
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil {
			return nil, false
		}
		next, ok := object[key]
		if !ok {
			return nil, false
		}
		raw = next
	}
	raw = bytes.TrimSpace(raw)
	switch {
	case len(raw) == 0:
		return nil, false
	case raw[0] == '"':
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, false
		}
		return []byte(s), true
	case raw[0] == 't' || raw[0] == 'f' || raw[0] == '-' || raw[0] >= '0' && raw[0] <= '9':
		return raw, true
	}
	return nil, false
}

// logStream is one container log of one observed Pod.
type logStream struct {
	pod       int
	container string
	limit     int64
}

// logResult is one stream's outcome: matching records in the window, the
// newest match second, whether a record was dropped as overlong, and whether
// the read failed or was truncated (so an absent match proves nothing).
type logResult struct {
	matches, newest   int64
	overlong, unknown bool
}

// logContainers names the containers of a Pod whose current or last
// instance may have written a record within the window: running, or
// terminated (now or as the last state of a waiting container) after the
// window started. A container that never ran has no log.
func logContainers(item restartPodItem, windowStart time.Time) []string {
	var out []string
	for _, s := range append(append([]restartContainerStatus{}, item.Status.InitContainerStatuses...), item.Status.ContainerStatuses...) {
		if s.Name == "" {
			continue
		}
		recent := func(t *struct {
			Reason     string
			ExitCode   int32
			FinishedAt string
		}) bool {
			if t == nil {
				return false
			}
			at, err := time.Parse(time.RFC3339, t.FinishedAt)
			return err != nil || at.After(windowStart)
		}
		switch {
		case s.State.Running != nil:
		case s.State.Terminated != nil:
			if !recent(s.State.Terminated) {
				continue
			}
		case !recent(s.LastState.Terminated):
			continue
		}
		out = append(out, s.Name)
	}
	return out
}

// logMatches adds the ADR-241 log level to the observed Pods. For every
// container of every observed Pod it reads one bounded pods/log GET
// (sinceSeconds = eventWindow, timestamps, limitBytes) and counts the
// records within the window that match. Only per-Pod counts, the newest
// match second and an overlong flag leave the region; no record text is
// returned, logged or kept. A Pod whose read failed or was truncated without
// a match is Unknown. Lines of a container instance that restarted inside
// the window are not read (the current instance only). More than
// MaxLogStreams containers fail the poll (ErrLimit, Unknown); a denied read
// fails it (ErrDenied).
func (c *PodTargets) logMatches(ctx context.Context, namespace string, m value.LogMatch, now time.Time, pods []value.PodRestarts, items []restartPodItem) error {
	matcher, err := newLogMatcher(m)
	if err != nil {
		return err
	}
	windowStart := now.Add(-time.Duration(m.WindowSeconds) * time.Second)
	var streams []logStream
	perPod := make([]int, len(pods))
	for i, item := range items {
		for _, name := range logContainers(item, windowStart) {
			streams = append(streams, logStream{pod: i, container: name})
			perPod[i]++
		}
	}
	if len(streams) > value.MaxLogStreams {
		return value.ErrLimit
	}
	for i := range streams {
		streams[i].limit = int64(min(value.MaxLogPodBytes/perPod[streams[i].pod], value.MaxLogBytes/len(streams)))
	}
	results := make([]logResult, len(streams))
	var (
		wg     sync.WaitGroup
		denied atomic.Bool
	)
	slots := make(chan struct{}, logReaders)
	for i, s := range streams {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			r, err := c.readLog(ctx, namespace, pods[s.pod].Name, s, m, matcher, windowStart, now)
			if err != nil {
				denied.Store(true)
			}
			results[i] = r
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if denied.Load() {
		return value.ErrDenied
	}
	unknown := make([]bool, len(pods))
	for i, s := range streams {
		r, p := results[i], &pods[s.pod]
		p.ProbeFailures = min(p.ProbeFailures+r.matches, 1<<31)
		p.ProbeLast = max(p.ProbeLast, r.newest)
		p.Overlong = p.Overlong || r.overlong
		unknown[s.pod] = unknown[s.pod] || r.unknown
	}
	for i := range pods {
		// A match proves the level even if another container's read failed.
		pods[i].Unknown = unknown[i] && pods[i].ProbeFailures == 0
	}
	return nil
}

// countingReader counts the bytes read, so a body that reached limitBytes is
// known to be truncated.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// readLog reads one container's log window. A denied read is an error (the
// connector lacks pods/log); any other failure, a truncated body or a
// malformed timestamp makes the stream Unknown.
func (c *PodTargets) readLog(ctx context.Context, namespace, pod string, s logStream, m value.LogMatch, matcher logMatcher, windowStart, now time.Time) (logResult, error) {
	var out logResult
	body, err := c.client.api.Get().AbsPath("/api/v1/namespaces/"+namespace+"/pods/"+pod+"/log").
		Param("container", s.container).Param("sinceSeconds", strconv.FormatInt(m.WindowSeconds, 10)).
		Param("timestamps", "true").Param("limitBytes", strconv.FormatInt(s.limit, 10)).MaxRetries(0).Stream(ctx)
	if err != nil {
		if permissionError(ctx, err) == cfg.ErrDenied {
			return out, value.ErrDenied
		}
		out.unknown = true
		return out, nil
	}
	defer body.Close()
	counted := &countingReader{r: io.LimitReader(body, s.limit+1)}
	lines := bufio.NewReaderSize(counted, m.MaxRecordBytes+64)
	for {
		line, err := lines.ReadSlice('\n')
		state := recordWhole
		if errors.Is(err, bufio.ErrBufferFull) {
			// Longer than the record bound: keep the prefix, skip the rest.
			line, state = append([]byte(nil), line...), recordOverlong
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = lines.ReadSlice('\n')
			}
		}
		if err != nil && !errors.Is(err, io.EOF) {
			out.unknown = true
			return out, nil
		}
		truncated := counted.n > s.limit-1
		if errors.Is(err, io.EOF) && truncated && state == recordWhole {
			// The last line of a body cut at limitBytes is incomplete.
			state = recordCut
		}
		if len(line) > 0 && !logRecord(&out, line, state, m, matcher, windowStart, now) {
			out.unknown = true
			return out, nil
		}
		if err != nil {
			out.unknown = out.unknown || truncated
			return out, nil
		}
	}
}

// Record states: within the bounds, longer than maxRecordBytes, or cut off
// at the end of a body truncated by limitBytes.
const (
	recordWhole = iota
	recordOverlong
	recordCut
)

// logRecord evaluates one "<RFC 3339 timestamp> <record>" line. An overlong
// record is dropped (and flagged), or with matchPrefix its prefix is
// matched; a cut-off record is evaluated only with matchPrefix. It returns
// false for a malformed timestamp.
func logRecord(out *logResult, line []byte, state int, m value.LogMatch, matcher logMatcher, windowStart, now time.Time) bool {
	stamp, record, found := bytes.Cut(line, []byte(" "))
	if !found && state != recordWhole {
		return true // a cut-off timestamp
	}
	at, err := time.Parse(time.RFC3339Nano, string(bytes.TrimRight(stamp, "\r\n")))
	if err != nil {
		return false
	}
	if !at.After(windowStart) {
		return true
	}
	// Record times come from the node's runtime clock: a future time would
	// raise the watermark past later real records, so it counts as now.
	if at.After(now) {
		at = now
	}
	record = bytes.TrimSuffix(bytes.TrimSuffix(record, []byte("\n")), []byte("\r"))
	if state == recordWhole && len(record) > m.MaxRecordBytes {
		state = recordOverlong
	}
	if state != recordWhole {
		if state == recordOverlong {
			out.overlong = true
		}
		if !m.MatchPrefix {
			return true
		}
		record = record[:min(len(record), m.MaxRecordBytes)]
	}

	if !matcher.match(record) {
		return true
	}
	if at.Unix() < value.MinProbeLast || at.Unix() >= 1<<31 {
		return false
	}
	out.matches = min(out.matches+1, 1<<31)
	out.newest = max(out.newest, at.Unix())
	return true
}
