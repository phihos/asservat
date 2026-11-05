package logs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"

	"asservat.local/asservat/internal/domain/artifact"
)

// Each remaining origin reserves bounded worst-case provenance AND coverage.
// This includes HTML-escaped 256-byte runtime IDs, all seven gaps and times.
const originReserve int64 = 4096
const tailReserve int64 = 1536
const footerReserve int64 = 512

type Encoder struct {
	ctx                              context.Context
	writer                           io.Writer
	limit, written                   int64
	fragmentAllowance, originEncoded int64
	state                            state
	err                              error
	full                             bool
}

func NewEncoder(ctx context.Context, w io.Writer, h artifact.LogHeader, maxBytes int64) (*Encoder, error) {
	if ctx == nil || w == nil || !h.WellFormed() || maxBytes < 1 || maxBytes > artifact.LogNativeLimit {
		return nil, artifact.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return nil, artifact.ErrInvalid
	}
	if int64(len(raw)+1)+int64(h.Origins)*originReserve+footerReserve > maxBytes {
		return nil, artifact.ErrLimit
	}
	e := &Encoder{ctx: ctx, writer: w, limit: maxBytes, fragmentAllowance: (maxBytes - int64(len(raw)+1) - int64(h.Origins)*originReserve - footerReserve) / int64(h.Origins)}
	if err = e.emit(h); err != nil {
		return nil, err
	}
	return e, nil
}
func (e *Encoder) emit(v any) error {
	if e == nil {
		return artifact.ErrInvalid
	}
	if e.err != nil {
		return e.err
	}
	if err := e.ctx.Err(); err != nil {
		e.err = err
		return err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return artifact.ErrInvalid
	}
	defer clear(raw)
	if len(raw)+1 > artifact.LogMaxLine {
		return artifact.ErrLimit
	}
	if e.written+int64(len(raw)+1) > e.limit {
		return artifact.ErrLimit
	}
	if err = e.state.consume(v); err != nil {
		return err
	}
	raw = append(raw, '\n')
	n, err := e.writer.Write(raw)
	e.written += int64(n)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = e.ctx.Err()
	}
	if err != nil {
		e.err = err
	}
	return err
}
func (e *Encoder) BeginOrigin(o artifact.LogOrigin) error {
	if e == nil {
		return artifact.ErrInvalid
	}
	e.full = false
	e.originEncoded = 0
	return e.emit(o)
}

// WriteLineFragment preserves original bytes including prefixes and line ends.
// The caller parses a source time before this call; nil stays explicitly unknown.
// A fragment cannot contain an interior newline. All fragments of a logical
// line must carry the same source time. A size refusal writes none of the fragment.
func (e *Encoder) WriteLineFragment(p []byte, sourceTime *string) (int, error) {
	if e == nil || e.state.origin == nil || len(p) < 1 || len(p) > artifact.LogMaxFragmentBytes {
		return 0, artifact.ErrInvalid
	}
	f := artifact.LogFragment{Record: "fragment", OriginID: e.state.origin.OriginID, Line: e.state.line, Offset: e.state.sourceBytes, LineOffset: e.state.lineOffset, Continuation: e.state.lineOffset > 0, EndLine: p[len(p)-1] == '\n', SourceTime: sourceTime, Data: base64.StdEncoding.EncodeToString(p)}
	raw, err := f.Bytes()
	clear(raw)
	if err != nil {
		return 0, err
	}
	b, err := json.Marshal(f)
	if err != nil {
		return 0, artifact.ErrInvalid
	}
	reserve := int64(e.state.header.Origins-e.state.finished-1)*originReserve + tailReserve
	encoded := int64(len(b) + 1)
	fits := e.written+encoded+reserve <= e.limit && e.originEncoded+encoded <= e.fragmentAllowance
	clear(b)
	if !fits {
		e.full = true
		return 0, artifact.ErrLimit
	}
	if err = e.emit(f); err != nil {
		return 0, err
	}
	e.originEncoded += encoded
	return len(p), nil
}

// Write is the source-time-unknown convenience writer. Acquisition that parses
// timestamp prefixes uses WriteLineFragment instead, retaining the prefixes.
func (e *Encoder) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		take := len(p)
		if take > artifact.LogMaxFragmentBytes {
			take = artifact.LogMaxFragmentBytes
		}
		if i := bytes.IndexByte(p[:take], '\n'); i >= 0 {
			take = i + 1
		}
		written, err := e.WriteLineFragment(p[:take], nil)
		n += written
		if err != nil {
			return n, err
		}
		p = p[take:]
	}
	return n, nil
}

// EndOrigin fills exact retained counters. Gaps and fetch intervals describe
// acquisition, not complete historical coverage. Unknown times are explicit.
func (e *Encoder) EndOrigin(c artifact.LogCoverage) error {
	if e == nil || e.state.origin == nil {
		return artifact.ErrInvalid
	}
	c.Record = "coverage"
	c.OriginID = e.state.origin.OriginID
	c.SourceBytes = e.state.sourceBytes
	c.Fragments = e.state.sourceFragments
	c.Lines = e.state.sourceLines
	c.Gaps = append([]string{}, c.Gaps...)
	if e.state.unknownTime && !hasGap(c, "timestampUnknown") {
		c.Gaps = append(c.Gaps, "timestampUnknown")
	}
	if e.full {
		if !hasGap(c, "outputFull") {
			c.Gaps = append(c.Gaps, "outputFull")
		}
		c.FetchOutcome = "partial"
	}
	return e.emit(c)
}
func (e *Encoder) Close() error {
	if e == nil {
		return artifact.ErrInvalid
	}
	return e.emit(artifact.LogFooter{Record: "footer", Origins: e.state.finished, SourceBytes: e.state.bytes, Fragments: e.state.fragments, Lines: e.state.lines})
}
