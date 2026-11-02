package httpheaders

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// ErrNotProjection is a stored document that is not exactly a projection
// this package could have produced under the accepted limits (ADR-282).
var ErrNotProjection = errors.New("document is not an approved HTTP header projection")

// EncodeWithin is Encode bounded by limit bytes (at most the native limit):
// when the document does not fit, the latest records are dropped and
// counted as RecordsDropped, so the result is still a consistent
// projection. It fails only when not even the envelope fits.
func (pr Projection) EncodeWithin(limit int64) ([]byte, error) {
	limit = min(limit, artifact.HTTPHeadersNativeLimit)
	for {
		b, err := json.Marshal(pr)
		if err != nil {
			return nil, err
		}
		if int64(len(b)) <= limit {
			return b, nil
		}
		if len(pr.Records) == 0 {
			return nil, artifact.ErrLimit
		}
		// Drop the latest records whose encodings cover the excess; a
		// changed counter width is caught by the next round.
		excess, drop := int64(len(b))-limit, 0
		for drop < len(pr.Records) && excess > 0 {
			r, err := json.Marshal(pr.Records[len(pr.Records)-1-drop])
			if err != nil {
				return nil, err
			}
			excess -= int64(len(r)) + 1
			drop++
		}
		kept := pr.Records[:len(pr.Records)-drop]
		for _, r := range pr.Records[len(kept):] {
			pr.Counters.Records--
			pr.Counters.RecordsDropped++
			if r.Partial {
				pr.Counters.PartialRecords--
			}
		}
		pr.Records = kept
	}
}

// CheckProjection is the publisher's independent recheck of a stored
// `http-response-headers/v1` document (ADR-282). The document must be at
// most limit bytes, decode strictly into Projection (no unknown field) and
// re-encode to exactly the stored bytes, so no duplicate key, whitespace or
// escape can carry bytes the checks below do not see. It must state the
// format, protocol and the accepted limits; every record must lie within
// the document's own window in time order, carry a projected method, a
// status (or be partial) and only content-type then content-length, each
// value unchanged by the projector's own value check. Record counters must
// match the records. It returns the record count.
func CheckProjection(r io.Reader, limits Limits, limit int64) (int, error) {
	if limits.Validate() != nil || limit < 1 {
		return 0, ErrInvalid
	}
	limit = min(limit, artifact.HTTPHeadersNativeLimit)
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return 0, err
	}
	if int64(len(b)) > limit {
		return 0, artifact.ErrLimit
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var pr Projection
	if dec.Decode(&pr) != nil || dec.More() {
		return 0, ErrNotProjection
	}
	canonical, err := pr.Encode()
	if err != nil || !bytes.Equal(canonical, b) {
		return 0, ErrNotProjection
	}
	l := limits
	want := LimitsRecord{MaxFlows: l.MaxFlows, MaxHeaderBytes: l.MaxHeaderBytes, MaxFlowBytes: l.MaxFlowBytes, MaxTotalBytes: l.MaxTotalBytes, IdleTimeoutSeconds: int64(l.IdleTimeout / time.Second), Snaplen: Snaplen}
	if pr.Format != artifact.HTTPHeadersFormat || pr.Protocol != "http1" || pr.Limits != want ||
		!validTime(pr.StartedAt) || !validTime(pr.EndedAt) || pr.EndedAt.Before(pr.StartedAt) ||
		len(pr.Records) > maxRecords || pr.Counters.Records != uint64(len(pr.Records)) {
		return 0, ErrNotProjection
	}
	var partial uint64
	prev := pr.StartedAt
	for _, rec := range pr.Records {
		if !checkRecord(rec, prev, pr.EndedAt) {
			return 0, ErrNotProjection
		}
		prev = rec.Timestamp
		if rec.Partial {
			partial++
		}
	}
	if partial != pr.Counters.PartialRecords {
		return 0, ErrNotProjection
	}
	return len(pr.Records), nil
}

func checkRecord(r Record, from, until time.Time) bool {
	if r.Timestamp.Before(from) || r.Timestamp.After(until) || projectMethod(r.Method) != r.Method ||
		r.Status == 0 && !r.Partial || r.Status != 0 && (r.Status < 100 || r.Status > 599) || len(r.Headers) > 2 {
		return false
	}
	next := 0 // content-type, then content-length, each at most once
	for _, h := range r.Headers {
		switch {
		case h.Name == "content-type" && next == 0:
			v, ok := projectContentType(h.Value)
			if !ok || v != h.Value {
				return false
			}
			next = 1
		case h.Name == "content-length" && next <= 1:
			if !contentLength.MatchString(h.Value) {
				return false
			}
			next = 2
		default:
			return false
		}
	}
	return true
}

// ProjectionCheck is the streaming form of CheckProjection for a verifier
// that sees the authenticated native stream in chunks. It buffers at most
// the bound and checks on Close.
type ProjectionCheck struct {
	limits Limits
	limit  int64
	buf    bytes.Buffer
	err    error
}

// NewProjectionCheck starts a check of a document of at most limit bytes
// produced under limits.
func NewProjectionCheck(limits Limits, limit int64) *ProjectionCheck {
	c := &ProjectionCheck{limits: limits, limit: min(limit, artifact.HTTPHeadersNativeLimit)}
	if limits.Validate() != nil || limit < 1 {
		c.err = ErrInvalid
	}
	return c
}

func (c *ProjectionCheck) Write(p []byte) error {
	if c.err != nil {
		return c.err
	}
	if int64(len(p)) > c.limit-int64(c.buf.Len()) {
		c.err = artifact.ErrLimit
		return c.err
	}
	c.buf.Write(p)
	return nil
}

// Close returns the verdict and clears the buffered document.
func (c *ProjectionCheck) Close() error {
	b := c.buf.Bytes()
	defer clear(b)
	if c.err != nil {
		return c.err
	}
	_, err := CheckProjection(bytes.NewReader(b), c.limits, c.limit)
	return err
}
