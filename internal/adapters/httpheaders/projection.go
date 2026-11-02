package httpheaders

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// Projection is the native `http-response-headers/v1` document. A record
// has the shape of a get_http_headers record: the request time, the
// projected method, the final status and the approved response headers
// (Content-Type, Content-Length). No URL, query, Host, connection tuple,
// body, trailer or credential header is kept.
type Projection struct {
	Format    string       `json:"format"`
	Protocol  string       `json:"protocol"`
	StartedAt time.Time    `json:"started_at"`
	EndedAt   time.Time    `json:"ended_at"`
	Limits    LimitsRecord `json:"limits"`
	Records   []Record     `json:"records"`
	Counters  Counters     `json:"counters"`
}

// LimitsRecord states the bounds the projection was produced under.
type LimitsRecord struct {
	MaxFlows           int   `json:"max_flows"`
	MaxHeaderBytes     int   `json:"max_header_bytes"`
	MaxFlowBytes       int   `json:"max_reassembly_bytes_per_flow"`
	MaxTotalBytes      int   `json:"max_reassembly_bytes"`
	IdleTimeoutSeconds int64 `json:"idle_timeout_seconds"`
	Snaplen            int   `json:"snaplen"`
}

type Record struct {
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method,omitempty"`
	Status    int       `json:"status,omitempty"`
	Headers   []Header  `json:"headers"`
	Partial   bool      `json:"partial"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Counters account for every frame and every stopped direction. A nonzero
// stop counter means records are missing for that flow direction; frame
// counters are not flow counts.
type Counters struct {
	Frames           uint64 `json:"frames"`
	EngineLostFrames uint64 `json:"engine_lost_frames"`
	InvalidFrames    uint64 `json:"invalid_frames"`
	NotTCPFrames     uint64 `json:"not_tcp_frames"`
	FragmentFrames   uint64 `json:"fragment_frames"`
	TruncatedFrames  uint64 `json:"truncated_frames"`
	MidstreamFrames  uint64 `json:"midstream_frames"`  // payload frames of flows whose SYN was not seen
	FlowLimitFrames  uint64 `json:"flow_limit_frames"` // frames of flows refused at the flow cap

	Flows            uint64 `json:"flows"`
	IdleClosedFlows  uint64 `json:"idle_closed_flows"`
	OpenAtCloseFlows uint64 `json:"open_at_close_flows"`

	Requests       uint64 `json:"requests"`
	Responses      uint64 `json:"responses"`
	Records        uint64 `json:"records"`
	PartialRecords uint64 `json:"partial_records"`
	RecordsDropped uint64 `json:"records_dropped"` // output bound reached
	DroppedValues  uint64 `json:"dropped_values"`  // approved fields failing their check

	StoppedIncomplete  uint64 `json:"stopped_incomplete"`
	StoppedGap         uint64 `json:"stopped_gap"`
	StoppedBufferLimit uint64 `json:"stopped_buffer_limit"`
	StoppedMidstream   uint64 `json:"stopped_midstream"`
	StoppedTLS         uint64 `json:"stopped_tls"`
	StoppedHTTP2       uint64 `json:"stopped_http2"`
	StoppedUpgrade     uint64 `json:"stopped_upgrade"`
	StoppedConnect     uint64 `json:"stopped_connect"`
	StoppedMalformed   uint64 `json:"stopped_malformed"`
	StoppedHeaderLimit uint64 `json:"stopped_header_limit"`
	StoppedBudget      uint64 `json:"stopped_budget"`
	StoppedPipeline    uint64 `json:"stopped_pipeline"`
	StoppedUnpaired    uint64 `json:"stopped_unpaired"`
}

func (c *Counters) count(r stop) {
	switch r {
	case stopIncomplete:
		c.StoppedIncomplete++
	case stopGap:
		c.StoppedGap++
	case stopBufferLimit:
		c.StoppedBufferLimit++
	case stopMidstream:
		c.StoppedMidstream++
	case stopTLS:
		c.StoppedTLS++
	case stopHTTP2:
		c.StoppedHTTP2++
	case stopUpgrade:
		c.StoppedUpgrade++
	case stopConnect:
		c.StoppedConnect++
	case stopMalformed:
		c.StoppedMalformed++
	case stopHeaderLimit:
		c.StoppedHeaderLimit++
	case stopBudget:
		c.StoppedBudget++
	case stopPipeline:
		c.StoppedPipeline++
	case stopUnpaired:
		c.StoppedUnpaired++
	}
}

// Output bounds: a record encodes to at most maxRecordBytes, so maxRecords
// records plus the envelope stay within the native type's limit.
const (
	maxRecordBytes      = 512
	envelopeBytes       = 4 << 10
	maxRecords          = int((artifact.HTTPHeadersNativeLimit - envelopeBytes) / maxRecordBytes)
	maxContentTypeBytes = 256
)

var (
	mediaType     = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$`)
	contentLength = regexp.MustCompile(`^[0-9]{1,19}$`)
)

// charsets are the registered names a response may state; any other value
// is dropped rather than echoed.
var charsets = func() map[string]bool {
	m := map[string]bool{}
	for _, c := range strings.Fields("utf-8 utf-16 utf-16le utf-16be us-ascii shift_jis euc-jp euc-kr iso-2022-jp gb2312 gbk gb18030 big5 koi8-r koi8-u") {
		m[c] = true
	}
	for i := 1; i <= 16; i++ {
		m[fmt.Sprintf("iso-8859-%d", i)] = true
	}
	for i := 1250; i <= 1258; i++ {
		m[fmt.Sprintf("windows-%d", i)] = true
	}
	return m
}()

var methods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true, "CONNECT": true, "OPTIONS": true, "TRACE": true, "PATCH": true}

// projectMethod keeps a standard method and maps every other token to OTHER.
func projectMethod(m string) string {
	if methods[m] {
		return m
	}
	return "OTHER"
}

func (p *Projector) record(e pending, resp *http.Response) Record {
	r := Record{Timestamp: e.at, Method: e.method, Headers: []Header{}}
	if resp.StatusCode >= 100 && resp.StatusCode <= 599 {
		r.Status = resp.StatusCode
	} else {
		p.counters.DroppedValues++
		r.Partial = true
	}
	if v, ok := p.approved(resp.Header, "Content-Type", projectContentType); ok {
		r.Headers = append(r.Headers, Header{Name: "content-type", Value: v})
	}
	if v, ok := p.approved(resp.Header, "Content-Length", func(v string) (string, bool) { return v, contentLength.MatchString(v) }); ok {
		r.Headers = append(r.Headers, Header{Name: "content-length", Value: v})
	}
	return r
}

// approved returns a present field's value only if it is single and passes
// its check; any other present value is dropped and counted.
func (p *Projector) approved(h http.Header, name string, check func(string) (string, bool)) (string, bool) {
	vs := h.Values(name)
	if len(vs) == 0 {
		return "", false
	}
	if len(vs) == 1 {
		if v, ok := check(vs[0]); ok {
			return v, true
		}
	}
	p.counters.DroppedValues++
	return "", false
}

// projectContentType keeps the media type and a token charset; other
// parameters are not part of the projection.
func projectContentType(v string) (string, bool) {
	if len(v) > maxContentTypeBytes {
		return "", false
	}
	mt, params, err := mime.ParseMediaType(v)
	if err != nil || !mediaType.MatchString(mt) {
		return "", false
	}
	if cs, ok := params["charset"]; ok {
		cs = strings.ToLower(cs)
		if !charsets[cs] {
			return "", false
		}
		return mt + "; charset=" + cs, true
	}
	return mt, true
}

func (p *Projector) addRecord(r Record) {
	if r.Headers == nil {
		r.Headers = []Header{}
	}
	if len(p.records) >= maxRecords {
		p.counters.RecordsDropped++
		return
	}
	p.counters.Records++
	if r.Partial {
		p.counters.PartialRecords++
	}
	p.records = append(p.records, r)
}

func (p *Projector) projection(end time.Time) Projection {
	recs := append([]Record(nil), p.records...)
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Timestamp.Before(recs[j].Timestamp) })
	if recs == nil {
		recs = []Record{}
	}
	l := p.limits
	return Projection{
		Format: artifact.HTTPHeadersFormat, Protocol: "http1", StartedAt: p.started, EndedAt: end,
		Limits:  LimitsRecord{MaxFlows: l.MaxFlows, MaxHeaderBytes: l.MaxHeaderBytes, MaxFlowBytes: l.MaxFlowBytes, MaxTotalBytes: l.MaxTotalBytes, IdleTimeoutSeconds: int64(l.IdleTimeout / time.Second), Snaplen: Snaplen},
		Records: recs, Counters: p.counters,
	}
}

// Encode returns the canonical JSON document: fixed field order, UTC
// RFC 3339 times, records in time order. It never exceeds the native limit.
func (pr Projection) Encode() ([]byte, error) {
	b, err := json.Marshal(pr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > artifact.HTTPHeadersNativeLimit {
		return nil, artifact.ErrLimit
	}
	return b, nil
}
