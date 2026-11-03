package diagnostics

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/google/pprof/profile"
	"golang.org/x/exp/trace"
)

// Publisher verification bounds for Go endpoint profiles (ADR-284). They
// bound what the key-holding publisher parses; a profile over a bound is
// refused, never truncated.
const (
	// MaxPprofMappings bounds the mapping table; a Go process has a few
	// dozen, a profile of many shared objects a few hundred.
	MaxPprofMappings    = 4096
	maxPprofSampleTypes = 16 // profile.schema.json sampleTypes.maxItems
	maxPprofName        = 64 // profile.schema.json type/unit maxLength
	maxPprofDuration    = 86_400_000_000_000
	// MaxGoTraceEvents bounds the events read from one execution trace.
	MaxGoTraceEvents = 1 << 25
)

// ErrNotProfile is a native stream that is not a bounded, valid profile of
// its registered type.
var ErrNotProfile = errors.New("native bytes are not a valid bounded profile")

// CheckPprof is the publisher's check of a stored pprof artifact: exactly
// one gzip member (CRC and length verified) of at most
// artifact.MaxPprofDecompressedBytes, parsed by github.com/google/pprof/profile
// and structurally valid (CheckValid: consistent sample values, table IDs
// and references). Sample types and their units must be named, duration and
// period non-negative and bounded, the period type named when present, and
// the mapping table bounded with each mapping's range ordered.
func CheckPprof(r io.Reader) error {
	return checkPprof(r, artifact.MaxPprofDecompressedBytes)
}

func checkPprof(r io.Reader, limit int64) (err error) {
	defer recoverParser(&err)
	_, err = parsePprof(r, limit)
	return err
}

// parsePprof shares publication semantics with the bounded summary analyzer.
// Callers contain parser panics and retain their own cancellation/authority.
func parsePprof(r io.Reader, limit int64) (*profile.Profile, error) {
	br := bufio.NewReader(r)
	gz, err := gzip.NewReader(br)
	if err != nil {
		return nil, ErrNotProfile
	}
	gz.Multistream(false)
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	n, err := plain.ReadFrom(io.LimitReader(gz, limit+1))
	if err != nil {
		return nil, ErrNotProfile
	}
	if n > limit {
		return nil, artifact.ErrLimit
	}
	if _, err = br.ReadByte(); err != io.EOF { // nothing after the member
		return nil, ErrNotProfile
	}
	if err := preflightPprof(plain.Bytes()); err != nil {
		return nil, err
	}
	p, err := profile.ParseUncompressed(plain.Bytes())
	if err != nil || p.CheckValid() != nil {
		return nil, ErrNotProfile
	}
	if len(p.SampleType) < 1 || len(p.SampleType) > maxPprofSampleTypes || len(p.Mapping) > MaxPprofMappings {
		return nil, ErrNotProfile
	}
	for _, t := range p.SampleType {
		if !pprofName(t.Type) || !pprofName(t.Unit) {
			return nil, ErrNotProfile
		}
	}
	if p.DurationNanos < 0 || p.DurationNanos > maxPprofDuration || p.TimeNanos < 0 || p.Period < 0 ||
		p.PeriodType != nil && (!pprofName(p.PeriodType.Type) || !pprofName(p.PeriodType.Unit)) {
		return nil, ErrNotProfile
	}
	for _, m := range p.Mapping {
		if m.Limit < m.Start {
			return nil, ErrNotProfile
		}
	}
	return p, nil
}

func pprofName(s string) bool { return len(s) >= 1 && len(s) <= maxPprofName }

// CheckGoTrace is the publisher's check of a stored Go execution trace: a
// version 2 trace (Go 1.22 and later; older formats are refused rather than
// converted) that golang.org/x/exp/trace reads to its end without error,
// with at most MaxGoTraceEvents events.
func CheckGoTrace(r io.Reader) error {
	return checkGoTrace(r, MaxGoTraceEvents)
}

func checkGoTrace(r io.Reader, limit int) (err error) {
	defer recoverParser(&err)
	br := bufio.NewReader(r)
	head, err := br.Peek(artifact.GoTraceHeaderBytes)
	if err != nil || !artifact.GoTraceHeader(head) {
		return ErrNotProfile
	}
	tr, err := trace.NewReader(br)
	if err != nil {
		return ErrNotProfile
	}
	// The reader frames every trace with Sync events; a trace without any
	// other event (a bare header) records nothing and is refused.
	recorded := false
	for events := 0; ; events++ {
		ev, err := tr.ReadEvent()
		if err == io.EOF {
			if !recorded {
				return ErrNotProfile
			}
			return nil
		}
		if err != nil {
			return ErrNotProfile
		}
		if events >= limit {
			return artifact.ErrLimit
		}
		recorded = recorded || ev.Kind() != trace.EventSync
	}
}

// recoverParser turns a panic of a third-party parser on hostile input into
// a refusal, so one artifact cannot stop the publisher.
func recoverParser(err *error) {
	if v := recover(); v != nil {
		*err = fmt.Errorf("%w: parser panic", ErrNotProfile)
	}
}

// ProfileCheck is the streaming form of a profile check for a verifier that
// sees the authenticated native stream in chunks. Close returns the verdict;
// the check goroutine always ends by Close.
type ProfileCheck struct {
	w    *io.PipeWriter
	done chan error
}

// NewPprofCheck starts CheckPprof on a stream.
func NewPprofCheck() *ProfileCheck { return newProfileCheck(CheckPprof) }

// NewGoTraceCheck starts CheckGoTrace on a stream.
func NewGoTraceCheck() *ProfileCheck { return newProfileCheck(CheckGoTrace) }

func newProfileCheck(check func(io.Reader) error) *ProfileCheck {
	r, w := io.Pipe()
	c := &ProfileCheck{w: w, done: make(chan error, 1)}
	go func() {
		err := check(r)
		// Drain so writers never block on an early verdict.
		_, _ = io.Copy(io.Discard, r)
		c.done <- err
	}()
	return c
}

func (c *ProfileCheck) Write(p []byte) error {
	_, err := c.w.Write(p)
	return err
}

// Close ends the stream and returns the verdict.
func (c *ProfileCheck) Close() error {
	_ = c.w.Close()
	return <-c.done
}
