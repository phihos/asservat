package contracts

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestAPIContextFramesEnforceKindSpecificBoundsBeforePayloadRead(t *testing.T) {
	for _, kind := range []APIContextFrameKind{APIContextHelloFrame, APIContextWorkFrame, APIContextResultFrame, APIContextReceiptFrame, APIContextOperationRequestFrame, APIContextOperationResponseFrame, APIContextSourceRequestFrame, APIContextSourceFrame, APIContextQueryFrame, APIContextAnswerFrame, HistoryWorkFrame, HistoryRequestFrame, HistoryResponseFrame, HistoryReceiptFrame} {
		limit := apiContextFrameLimit(kind)
		var wire bytes.Buffer
		payload := bytes.Repeat([]byte{'x'}, limit)
		if e := WriteAPIContextFrame(&wire, APIContextFrame{Kind: kind, Payload: payload}); e != nil {
			t.Fatal(kind, e)
		}
		out, e := ReadAPIContextFrame(&wire)
		if e != nil || out.Kind != kind || !bytes.Equal(out.Payload, payload) {
			t.Fatal(kind, e)
		}
		if e = WriteAPIContextFrame(&wire, APIContextFrame{Kind: kind, Payload: append(payload, 'x')}); e == nil {
			t.Fatal("oversize accepted", kind)
		}
		var header [5]byte
		header[0] = byte(kind)
		binary.BigEndian.PutUint32(header[1:], uint32(limit+1))
		if _, e = ReadAPIContextFrame(bytes.NewReader(header[:])); e == nil {
			t.Fatal("oversize header accepted", kind)
		}
	}
	for _, bad := range [][]byte{nil, {0, 0, 0, 0, 1, 'x'}, {255, 0, 0, 0, 1, 'x'}, {3, 0, 0, 0, 1, 'x'}, {4, 0, 0, 0, 1, 'x'}, {13, 0, 0, 0, 1, 'x'}, {1, 0, 0, 0, 0}, {1, 0, 0, 0, 2, 'x'}} {
		if _, e := ReadAPIContextFrame(bytes.NewReader(bad)); e == nil {
			t.Fatal("malformed frame accepted")
		}
	}
}
