package contracts

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type observationHeaderOnly struct {
	header      []byte
	payloadRead bool
}

func (r *observationHeaderOnly) Read(p []byte) (int, error) {
	if len(r.header) == 0 {
		r.payloadRead = true
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, r.header)
	r.header = r.header[n:]
	return n, nil
}

func TestClusterObservationFramesRejectOversizedBeforeReadingBody(t *testing.T) {
	for _, kind := range []ClusterObservationFrameKind{ClusterObservationHelloFrame, ClusterObservationProbeFrame, ClusterObservationSourceFrame, ClusterObservationReadFrame, ClusterObservationResultFrame, ClusterObservationReceiptFrame} {
		limit := clusterObservationFrameLimit(kind)
		var wire bytes.Buffer
		p := bytes.Repeat([]byte{'x'}, limit)
		if e := WriteClusterObservationFrame(&wire, ClusterObservationFrame{Kind: kind, Payload: p}); e != nil {
			t.Fatal(kind, e)
		}
		got, e := ReadClusterObservationFrame(&wire)
		if e != nil || got.Kind != kind || !bytes.Equal(got.Payload, p) {
			t.Fatal(kind, e)
		}
		var header [5]byte
		header[0] = byte(kind)
		binary.BigEndian.PutUint32(header[1:], uint32(limit+1))
		r := &observationHeaderOnly{header: header[:]}
		if _, e = ReadClusterObservationFrame(r); e == nil || r.payloadRead {
			t.Fatal("oversize caused body read", kind)
		}
		if e = WriteClusterObservationFrame(&wire, ClusterObservationFrame{Kind: kind, Payload: append(p, 'x')}); e == nil {
			t.Fatal("oversize write", kind)
		}
	}
	// The complete largest valid conversation fits its fixed aggregate cap;
	// changing one frame bound must not silently permit an oversized exchange.
	maximum := 2*(1024+5) + 4*(2*OwnerObservationBytes+5) + 4*(ConnectorObservationBytes+5) + 2*(ClusterObservationBytes+5)
	if maximum > ClusterObservationExchangeBytes || 1+2*ConnectorObservationChecks+3 != ClusterObservationMaximumFrames {
		t.Fatal("closed frame accounting inconsistent")
	}
}

func TestClusterObservationFramesHaveNoCaptureOrCredentialFallback(t *testing.T) {
	for _, bad := range [][]byte{nil, {0, 0, 0, 0, 1, 'x'}, {255, 0, 0, 0, 1, 'x'}, {1, 0, 0, 0, 0}, {1, 0, 0, 0, 2, 'x'}} {
		if _, e := ReadClusterObservationFrame(bytes.NewReader(bad)); e == nil {
			t.Fatal("malformed frame accepted")
		}
	}
	valid := ClusterObservationHello{Format: ClusterObservationExchangeFormat, ExchangeID: "e", RootID: "r", ClusterID: "c"}
	b, e := EncodeClusterObservationHello(valid)
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"captureID", "token", "url", "proof", "requestedAt", "notAfter"} {
		bad := append(append([]byte{}, b[:len(b)-1]...), []byte(`,"`+field+`":"x"}`)...)
		if _, e := DecodeClusterObservationHello(bad); e == nil {
			t.Fatal("unexpected bootstrap member accepted", field)
		}
	}
}
