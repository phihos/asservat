package logs

import (
	"bytes"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// StreamCheck validates the complete native stream against independently
// accepted source/window facts and the manifest's actual acquisition interval.
// It retains one bounded JSONL record, not a goroutine or a whole artifact.
// Write/Close are serialized by the owning native pipeline.
type StreamCheck struct {
	state                        state
	pod                          string
	start, end, from, until      time.Time
	writeUntil, maxFetchFinished time.Time
	acquiring                    bool
	limit, total                 int64
	line                         []byte
	err                          error
	closed                       bool
}

func NewCheck(e artifact.ContextExpectation, from, until time.Time) (*StreamCheck, error) {
	if until.IsZero() || until.Before(from) {
		return nil, artifact.ErrInvalid
	}
	return newCheck(e, from, until, false)
}

// NewAcquiringCheck has no invented acquisition end. Its owner must call
// CloseAt only after source EOF and the original-source post-check have joined.
// It is not a substitute for those producer checks or source authentication.
func NewAcquiringCheck(e artifact.ContextExpectation, from time.Time) (*StreamCheck, error) {
	if e.Registration.WriteUntil.IsZero() || !from.Before(e.Registration.WriteUntil) || from.Before(e.Registration.AnchorAt) {
		return nil, artifact.ErrInvalid
	}
	return newCheck(e, from, time.Time{}, true)
}
func newCheck(e artifact.ContextExpectation, from, until time.Time, acquiring bool) (*StreamCheck, error) {
	if e.NativeType != artifact.LogsArtifact || e.DataClass != "raw" || !e.Logs.Valid() || e.PodUID == "" || e.ActionID != e.Logs.ActionID || e.Registration.NativeLimit != e.Logs.MaxNativeBytes || from.IsZero() {
		return nil, artifact.ErrInvalid
	}
	start, end, err := e.Logs.Window(e.TriggeredAt)
	if err != nil {
		return nil, err
	}
	return &StreamCheck{pod: e.PodUID, start: start, end: end, from: from, until: until, writeUntil: e.Registration.WriteUntil, acquiring: acquiring, limit: e.Logs.MaxNativeBytes}, nil
}

func (c *StreamCheck) fail(err error) error {
	if c.err == nil {
		c.err = err
	}
	clear(c.line)
	c.line = nil
	return c.err
}
func (c *StreamCheck) Write(p []byte) error {
	if c == nil {
		return artifact.ErrInvalid
	}
	if c.err != nil {
		return c.err
	}
	if c.closed {
		return c.fail(artifact.ErrInvalid)
	}
	if int64(len(p)) > c.limit-c.total {
		return c.fail(artifact.ErrLimit)
	}
	c.total += int64(len(p))
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		take := p
		if i >= 0 {
			take = p[:i]
		}
		if len(c.line)+len(take) >= artifact.LogMaxLine {
			return c.fail(artifact.ErrLimit)
		}
		c.line = append(c.line, take...)
		if i < 0 {
			return nil
		}
		record, err := parseRecord(c.line)
		if err != nil {
			return c.fail(err)
		}
		switch r := record.(type) {
		case artifact.LogHeader:
			if r.PodUID != c.pod || !r.WindowStart.Equal(c.start) || !r.WindowEnd.Equal(c.end) {
				return c.fail(artifact.ErrIntegrity)
			}
		case artifact.LogCoverage:
			// Native/manifest acquisition instants retain their exact precision. The
			// unrelated display-only microsecond normalization must not rewrite them.
			if r.FetchStartedAt != nil && (r.FetchStartedAt.Before(c.from) || r.FetchFinishedAt == nil || !c.acquiring && r.FetchFinishedAt.After(c.until)) {
				return c.fail(artifact.ErrIntegrity)
			}
		}
		if err = c.state.consume(record); err != nil {
			return c.fail(err)
		}
		if r, ok := record.(artifact.LogCoverage); ok && r.FetchFinishedAt != nil && r.FetchFinishedAt.After(c.maxFetchFinished) {
			c.maxFetchFinished = *r.FetchFinishedAt
		}
		clear(c.line)
		c.line = c.line[:0]
		p = p[i+1:]
	}
	return nil
}
func (c *StreamCheck) Close() error {
	if c == nil {
		return artifact.ErrInvalid
	}
	if c.err != nil {
		return c.err
	}
	if c.closed {
		return nil
	}
	if c.acquiring {
		return c.fail(artifact.ErrIntegrity)
	}
	c.closed = true
	if len(c.line) != 0 || !c.state.footer {
		return c.fail(artifact.ErrIntegrity)
	}
	clear(c.line)
	c.line = nil
	return nil
}

// CloseAt supplies the actual completed interval once. It does not obtain time
// from a deadline, refresh a source, or extend the original write authority.
func (c *StreamCheck) CloseAt(actualUntil time.Time) error {
	if c == nil {
		return artifact.ErrInvalid
	}
	if c.err != nil {
		return c.err
	}
	if c.closed {
		if c.acquiring && c.until.Equal(actualUntil) {
			return nil
		}
		return c.fail(artifact.ErrInvalid)
	}
	if !c.acquiring {
		return c.fail(artifact.ErrInvalid)
	}
	if actualUntil.IsZero() || actualUntil.Before(c.from) || actualUntil.Before(c.maxFetchFinished) || !actualUntil.Before(c.writeUntil) {
		return c.fail(artifact.ErrIntegrity)
	}
	if len(c.line) != 0 || !c.state.footer {
		return c.fail(artifact.ErrIntegrity)
	}
	c.until = actualUntil
	c.closed = true
	clear(c.line)
	c.line = nil
	return nil
}
