package httpheaders

import (
	"crypto/sha256"
	"fmt"
	"slices"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// ReadPage returns one get_http_headers page of the stored projection native
// (ADR-282 slice 4). The whole document first passes the publisher's
// recheck under the accepted limits and output cap (strict decode,
// byte-identical canonical form, projected values, record counters), so a
// tampered or foreign document yields no record. The cursor must have been
// issued for this exact document (its SHA-256) and lie inside it.
func ReadPage(native []byte, limits Limits, limit int64, s analysis.HTTPHeaderSelection) (analysis.HTTPHeaderPage, error) {
	if !s.Valid() || limits.Validate() != nil || limit < 1 {
		return analysis.HTTPHeaderPage{}, ErrInvalid
	}
	if int64(len(native)) > min(limit, artifact.HTTPHeadersNativeLimit) {
		return analysis.HTTPHeaderPage{}, artifact.ErrLimit
	}
	pr, err := checkedProjection(native, limits)
	if err != nil {
		return analysis.HTTPHeaderPage{}, err
	}
	digest := artifact.Digest(sha256.Sum256(native))
	if !s.Matches(digest) || s.Start > 0 && s.Start >= len(pr.Records) {
		return analysis.HTTPHeaderPage{}, analysis.ErrInvalidCursor
	}
	dropped, incomplete, gaps := coverage(pr.Counters)
	page := analysis.HTTPHeaderPage{ProjectionDigest: digest, Start: s.Start, Total: len(pr.Records),
		DroppedFlows: dropped, IncompleteFlows: incomplete, CoverageGaps: gaps}
	end := min(len(pr.Records), s.Start+s.Limit)
	page.Records = make([]analysis.HTTPHeaderRecord, 0, end-s.Start)
	for _, r := range pr.Records[s.Start:end] {
		out := analysis.HTTPHeaderRecord{Timestamp: r.Timestamp.UTC(), Method: r.Method, Status: r.Status, Partial: r.Partial,
			Headers: make([]analysis.HTTPHeaderField, 0, len(r.Headers))}
		for _, h := range r.Headers {
			out.Headers = append(out.Headers, analysis.HTTPHeaderField{Name: h.Name, Value: h.Value})
		}
		page.Records = append(page.Records, out)
	}
	if !page.Valid(s) {
		return analysis.HTTPHeaderPage{}, ErrNotProjection
	}
	return page, nil
}

// coverage reports the document's gaps. Stop counters count flow
// directions, so both totals are upper bounds on affected flows:
// dropped_flows are directions never parsed as HTTP/1 (no SYN seen, TLS,
// HTTP/2); incomplete_flows are directions that stopped after parsing
// began. Frame-level losses and output bounds appear only as gap text.
func coverage(c Counters) (dropped, incomplete uint64, gaps []string) {
	dropped = c.StoppedMidstream + c.StoppedTLS + c.StoppedHTTP2
	incomplete = c.StoppedIncomplete + c.StoppedGap + c.StoppedBufferLimit + c.StoppedUpgrade + c.StoppedConnect +
		c.StoppedMalformed + c.StoppedHeaderLimit + c.StoppedBudget + c.StoppedPipeline + c.StoppedUnpaired
	gaps = []string{}
	for _, g := range []struct {
		n    uint64
		text string
	}{
		{c.EngineLostFrames, "%d frames lost by the capture engine."},
		{c.InvalidFrames, "%d frames could not be decoded."},
		{c.FragmentFrames, "%d IP fragments not reassembled."},
		{c.TruncatedFrames, "%d frames truncated at the snapshot length."},
		{c.MidstreamFrames, "%d frames of flows that started before the capture."},
		{c.FlowLimitFrames, "%d frames of flows beyond the flow limit."},
		{c.OpenAtCloseFlows, "%d flows still open when the capture ended."},
		{c.RecordsDropped, "%d records dropped at the output limit."},
		{c.DroppedValues, "%d header values failed their check and were omitted."},
		{c.StoppedMidstream, "%d flow directions omitted: started before the capture."},
		{c.StoppedTLS, "%d flow directions omitted: TLS; no decryption or raw fallback."},
		{c.StoppedHTTP2, "%d flow directions omitted: HTTP/2."},
		{c.StoppedIncomplete, "%d flow directions ended inside a message."},
		{c.StoppedGap, "%d flow directions stopped at missing or truncated bytes."},
		{c.StoppedBufferLimit, "%d flow directions stopped at the reassembly buffer limit."},
		{c.StoppedUpgrade, "%d flow directions stopped at a protocol upgrade."},
		{c.StoppedConnect, "%d flow directions stopped at a CONNECT tunnel."},
		{c.StoppedMalformed, "%d flow directions stopped at malformed HTTP/1."},
		{c.StoppedHeaderLimit, "%d flow directions stopped at the header block limit."},
		{c.StoppedBudget, "%d flow directions stopped at the parser memory budget."},
		{c.StoppedPipeline, "%d flow directions stopped at the pipelining limit."},
		{c.StoppedUnpaired, "%d flow directions stopped at a response without a request."},
	} {
		if g.n > 0 {
			gaps = append(gaps, fmt.Sprintf(g.text, g.n))
		}
	}
	return dropped, incomplete, slices.Clip(gaps)
}
