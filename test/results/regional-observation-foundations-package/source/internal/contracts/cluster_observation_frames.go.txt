package contracts

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	ClusterObservationExchangeFormat = "cluster-observation-exchange/v1"
	ClusterObservationExchangePath   = "/internal/cluster-observation/exchange/v1"
	ClusterObservationExchangeMedia  = "application/vnd.asservat.cluster-observation-exchange.v1"
	// Hello; four exact fresh source questions/replies (two around each
	// registry read); one metadata selection/result; final delivery receipt.
	ClusterObservationMaximumFrames = 12
	ClusterObservationExchangeBytes = 512 << 10
)

type ClusterObservationFrameKind byte

const (
	ClusterObservationHelloFrame ClusterObservationFrameKind = 1 + iota
	ClusterObservationProbeFrame
	ClusterObservationSourceFrame
	ClusterObservationReadFrame
	ClusterObservationResultFrame
	ClusterObservationReceiptFrame
)

type ClusterObservationFrame struct {
	Kind    ClusterObservationFrameKind
	Payload []byte
}

func clusterObservationFrameLimit(k ClusterObservationFrameKind) int {
	switch k {
	case ClusterObservationHelloFrame, ClusterObservationReceiptFrame:
		return 1024
	case ClusterObservationProbeFrame:
		return 2 * OwnerObservationBytes
	case ClusterObservationSourceFrame:
		return ConnectorObservationBytes
	case ClusterObservationReadFrame, ClusterObservationResultFrame:
		return ClusterObservationBytes
	default:
		return 0
	}
}

// Framing does not authenticate a conversation. The concrete transport also
// enforces the closed sequence, aggregate count/bytes, exact original channel
// and current proof before and after every actual read or write.
func ReadClusterObservationFrame(r io.Reader) (ClusterObservationFrame, error) {
	var zero ClusterObservationFrame
	if r == nil {
		return zero, ErrClusterObservationProtocol
	}
	var header [5]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return zero, ErrClusterObservationProtocol
	}
	kind := ClusterObservationFrameKind(header[0])
	size := binary.BigEndian.Uint32(header[1:])
	limit := clusterObservationFrameLimit(kind)
	if limit == 0 || size == 0 || uint64(size) > uint64(limit) {
		return zero, ErrClusterObservationProtocol
	}
	payload := make([]byte, int(size))
	if _, e := io.ReadFull(r, payload); e != nil {
		clear(payload)
		return zero, ErrClusterObservationProtocol
	}
	return ClusterObservationFrame{Kind: kind, Payload: payload}, nil
}
func WriteClusterObservationFrame(w io.Writer, f ClusterObservationFrame) error {
	limit := clusterObservationFrameLimit(f.Kind)
	if w == nil || limit == 0 || len(f.Payload) == 0 || len(f.Payload) > limit {
		return ErrClusterObservationProtocol
	}
	var header [5]byte
	header[0] = byte(f.Kind)
	binary.BigEndian.PutUint32(header[1:], uint32(len(f.Payload)))
	if n, e := w.Write(header[:]); e != nil || n != len(header) {
		return ErrClusterObservationProtocol
	}
	if n, e := w.Write(f.Payload); e != nil || n != len(f.Payload) {
		return ErrClusterObservationProtocol
	}
	return nil
}

// A standby hello identifies only routing and finite socket residency. It
// carries no authority interval, target metadata, caller, capture or evidence.
type ClusterObservationHello struct {
	Format     string `json:"format"`
	ExchangeID string `json:"exchangeID"`
	RootID     string `json:"rootID"`
	ClusterID  string `json:"clusterID"`
}

// Each Probe requests a new local source/Pod proof. Owner proof is for this
// exact live TLS channel and the original attached request; it never extends
// that request, nor authenticates another connection after reconnection.
type ClusterObservationProbe struct {
	Format     string                `json:"format"`
	ExchangeID string                `json:"exchangeID"`
	Ordinal    int                   `json:"ordinal"`
	Owner      OwnerObservationReply `json:"owner"`
}

type ClusterObservationReceipt struct {
	Format        string `json:"format"`
	ExchangeID    string `json:"exchangeID"`
	RequestID     string `json:"requestID"`
	Challenge     string `json:"challenge"`
	RequestDigest string `json:"requestDigest"`
}

func EncodeClusterObservationHello(v ClusterObservationHello) ([]byte, error) {
	return canonicalAPIContext(v, 1024)
}
func DecodeClusterObservationHello(b []byte) (ClusterObservationHello, error) {
	return decodeClosedRPC[ClusterObservationHello](bytes.NewReader(b), 1024)
}
func EncodeClusterObservationProbe(v ClusterObservationProbe) ([]byte, error) {
	return canonicalAPIContext(v, 2*OwnerObservationBytes)
}
func DecodeClusterObservationProbe(b []byte) (ClusterObservationProbe, error) {
	return decodeClosedRPC[ClusterObservationProbe](bytes.NewReader(b), 2*OwnerObservationBytes)
}
func EncodeClusterObservationReceipt(v ClusterObservationReceipt) ([]byte, error) {
	return canonicalAPIContext(v, 1024)
}
func DecodeClusterObservationReceipt(b []byte) (ClusterObservationReceipt, error) {
	return decodeClosedRPC[ClusterObservationReceipt](bytes.NewReader(b), 1024)
}
