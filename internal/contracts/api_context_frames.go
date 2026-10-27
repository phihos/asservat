package contracts

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
)

const (
	APIContextStartPath  = "/internal/v1/context/start-exchange"
	APIContextStartMedia = "application/vnd.asservat.api-context-exchange.v1"
	// Hello, work, at most sixteen ADR-171 operation pairs, result, receipt,
	// the ADR-178 source frames and the ADR-179 query pairs.
	APIContextMaximumFrames        = 36 + APIContextMaximumSourceFrames + 2*APIContextMaximumQueries
	APIContextMaximumExchangeBytes = 2 << 20
)

type APIContextFrameKind byte

const (
	APIContextHelloFrame APIContextFrameKind = 1 + iota
	APIContextWorkFrame
	// Kinds 3 and 4 were the retired identity-question frames (ADR-171). They
	// are never reused and always rejected.
	_
	_
	APIContextResultFrame
	APIContextReceiptFrame
	APIContextOperationRequestFrame
	APIContextOperationResponseFrame
	// ADR-178: the hub requests and the region supplies its own current
	// connector identity source observation.
	APIContextSourceRequestFrame
	APIContextSourceFrame
	// ADR-179: a pre-work target query from the hub and the region's answer.
	APIContextQueryFrame
	APIContextAnswerFrame
)

// History has a distinct range; retired/unknown common kinds remain rejected.
const (
	HistoryWorkFrame APIContextFrameKind = 32 + iota
	HistoryRequestFrame
	HistoryResponseFrame
	HistoryReceiptFrame
)

// ADR-178 source frames per exchange: one after Hello, a request and reply at
// attach and at work send, one immediately before the result, and a request
// and reply before each ADR-179 query.
const (
	APIContextMaximumSourceFrames = 6 + 2*APIContextMaximumQueries
	APIContextSourceBytes         = 64 << 10
)

// ADR-179 pre-work target queries reuse the operation and reply DTOs; their
// sequence counts queries, 1 to APIContextMaximumQueries.
const APIContextMaximumQueries = 8

// ADR-171 hub-run execution: one regional operation per request/response.
const (
	APIContextMaximumOperations = 16
	APIContextOperationBytes    = 32 << 10
)

type APIContextFrame struct {
	Kind    APIContextFrameKind
	Payload []byte
}

func apiContextFrameLimit(kind APIContextFrameKind) int {
	switch kind {
	case APIContextHelloFrame:
		return APIContextWorkBytes
	case APIContextWorkFrame, HistoryWorkFrame:
		return APIContextSignedWorkBytes
	case APIContextResultFrame, APIContextReceiptFrame, HistoryReceiptFrame:
		return 1024
	case APIContextOperationRequestFrame, APIContextOperationResponseFrame, APIContextQueryFrame, APIContextAnswerFrame:
		return APIContextOperationBytes
	case HistoryRequestFrame, HistoryResponseFrame:
		return HistoryCiphertextFrameBytes
	case APIContextSourceRequestFrame:
		return 1024
	case APIContextSourceFrame:
		return APIContextSourceBytes
	default:
		return 0
	}
}
func ReadAPIContextFrame(r io.Reader) (APIContextFrame, error) {
	var out APIContextFrame
	if r == nil {
		return out, ErrAPIContextProtocol
	}
	var header [5]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return out, ErrAPIContextProtocol
	}
	out.Kind = APIContextFrameKind(header[0])
	size := binary.BigEndian.Uint32(header[1:])
	limit := apiContextFrameLimit(out.Kind)
	if limit == 0 || size == 0 || uint64(size) > uint64(limit) {
		return APIContextFrame{}, ErrAPIContextProtocol
	}
	out.Payload = make([]byte, int(size))
	if _, e := io.ReadFull(r, out.Payload); e != nil {
		clear(out.Payload)
		return APIContextFrame{}, ErrAPIContextProtocol
	}
	return out, nil
}
func WriteAPIContextFrame(w io.Writer, f APIContextFrame) error {
	limit := apiContextFrameLimit(f.Kind)
	if w == nil || limit == 0 || len(f.Payload) == 0 || len(f.Payload) > limit {
		return ErrAPIContextProtocol
	}
	var header [5]byte
	header[0] = byte(f.Kind)
	binary.BigEndian.PutUint32(header[1:], uint32(len(f.Payload)))
	if n, e := w.Write(header[:]); e != nil || n != len(header) {
		return ErrAPIContextProtocol
	}
	if n, e := w.Write(f.Payload); e != nil || n != len(f.Payload) {
		return ErrAPIContextProtocol
	}
	return nil
}

type APIContextHello struct {
	Format  string            `json:"format"`
	Channel APIContextChannel `json:"channel"`
}

// Result is a bounded disposition, not evidence or a catalog publication.
// The receipt acknowledges delivery of this result only, never acquisition.
type APIContextResult struct {
	Format     string `json:"format"`
	ExchangeID string `json:"exchangeId"`
	CaptureID  string `json:"captureId"`
	State      string `json:"state"`
}
type APIContextReceipt struct {
	Format     string `json:"format"`
	ExchangeID string `json:"exchangeId"`
	CaptureID  string `json:"captureId"`
	State      string `json:"state"`
}

// APIContextOperation is one hub request for a cluster-local operation of the
// verified work. Body is the method's closed JSON value; it never carries
// native evidence bytes or key material.
type APIContextOperation struct {
	Format   string          `json:"format"`
	Sequence int             `json:"sequence"`
	Method   string          `json:"method"`
	Body     json.RawMessage `json:"body"`
}

// APIContextOperationReply carries the result or a closed failure label; a
// failure may still carry partial facts such as an acquisition instant.
type APIContextOperationReply struct {
	Format   string          `json:"format"`
	Sequence int             `json:"sequence"`
	Method   string          `json:"method"`
	Body     json.RawMessage `json:"body,omitempty"`
	Failure  string          `json:"failure,omitempty"`
}

func EncodeAPIContextOperation(v APIContextOperation) ([]byte, error) {
	return canonicalAPIContext(v, APIContextOperationBytes)
}
func DecodeAPIContextOperation(b []byte) (APIContextOperation, error) {
	v, e := decodeClosedRPC[APIContextOperation](bytes.NewReader(b), APIContextOperationBytes)
	if e != nil || v.Format != APIContextExchangeFormat || v.Sequence < 1 || v.Sequence > APIContextMaximumOperations || v.Method == "" || len(v.Method) > 32 {
		return APIContextOperation{}, ErrAPIContextProtocol
	}
	return v, nil
}
func EncodeAPIContextOperationReply(v APIContextOperationReply) ([]byte, error) {
	return canonicalAPIContext(v, APIContextOperationBytes)
}
func DecodeAPIContextOperationReply(b []byte) (APIContextOperationReply, error) {
	v, e := decodeClosedRPC[APIContextOperationReply](bytes.NewReader(b), APIContextOperationBytes)
	if e != nil || v.Format != APIContextExchangeFormat || v.Sequence < 1 || v.Sequence > APIContextMaximumOperations || v.Method == "" || len(v.Failure) > 32 {
		return APIContextOperationReply{}, ErrAPIContextProtocol
	}
	return v, nil
}

func EncodeAPIContextHello(v APIContextHello) ([]byte, error) {
	return canonicalAPIContext(v, APIContextWorkBytes)
}
func DecodeAPIContextHello(b []byte) (APIContextHello, error) {
	v, e := decodeClosedRPC[APIContextHello](bytes.NewReader(b), APIContextWorkBytes)
	if e != nil {
		return APIContextHello{}, ErrAPIContextProtocol
	}
	return v, nil
}
func EncodeAPIContextResult(v APIContextResult) ([]byte, error) { return canonicalAPIContext(v, 1024) }
func DecodeAPIContextResult(b []byte) (APIContextResult, error) {
	v, e := decodeClosedRPC[APIContextResult](bytes.NewReader(b), 1024)
	if e != nil {
		return APIContextResult{}, ErrAPIContextProtocol
	}
	return v, nil
}
func EncodeAPIContextReceipt(v APIContextReceipt) ([]byte, error) {
	return canonicalAPIContext(v, 1024)
}
func DecodeAPIContextReceipt(b []byte) (APIContextReceipt, error) {
	v, e := decodeClosedRPC[APIContextReceipt](bytes.NewReader(b), 1024)
	if e != nil {
		return APIContextReceipt{}, ErrAPIContextProtocol
	}
	return v, nil
}

// APIContextSourceRequest asks the region for a fresh source observation.
type APIContextSourceRequest struct {
	Format     string `json:"format"`
	ExchangeID string `json:"exchangeId"`
	Sequence   int    `json:"sequence"`
}

// APIContextSource carries the region's own current connector identity source
// observation for one exchange. Sequence 0 follows Hello; requested sources
// echo their request; the last precedes the result.
type APIContextSource struct {
	Format     string          `json:"format"`
	ExchangeID string          `json:"exchangeId"`
	Sequence   int             `json:"sequence"`
	Source     json.RawMessage `json:"source"`
}

func EncodeAPIContextSourceRequest(v APIContextSourceRequest) ([]byte, error) {
	return canonicalAPIContext(v, 1024)
}
func DecodeAPIContextSourceRequest(b []byte) (APIContextSourceRequest, error) {
	v, e := decodeClosedRPC[APIContextSourceRequest](bytes.NewReader(b), 1024)
	if e != nil || v.Format != APIContextExchangeFormat || v.Sequence < 1 || v.Sequence >= APIContextMaximumSourceFrames {
		return APIContextSourceRequest{}, ErrAPIContextProtocol
	}
	return v, nil
}
func EncodeAPIContextSource(v APIContextSource) ([]byte, error) {
	return canonicalAPIContext(v, APIContextSourceBytes)
}
func DecodeAPIContextSource(b []byte) (APIContextSource, error) {
	v, e := decodeClosedRPC[APIContextSource](bytes.NewReader(b), APIContextSourceBytes)
	if e != nil || v.Format != APIContextExchangeFormat || v.Sequence < 0 || v.Sequence >= APIContextMaximumSourceFrames || len(v.Source) == 0 {
		return APIContextSource{}, ErrAPIContextProtocol
	}
	return v, nil
}
