package contracts

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const NativeExchangeFormat = "asservat-context-native/v1"
const NativeExchangeMedia = "application/vnd.asservat.context-native.v1"
const NativeWorkerPath = "/internal/download-native/v1/worker"
const NativeOwnerPath = "/internal/download-native/v1/owner"
const NativeControlBytes = 64 << 10

// A command includes the already-bounded context audience, retention rules and
// four copy receipts, plus a closed placement/processing proof. Their conservative
// escaped encoding is at most 574075 bytes;
// this separate ceiling does not expand Hello, acknowledgement or data frames.
const NativeCommandBytes = 640 << 10
const NativeDataBytes = 1 << 20

// This first qualified mechanism needs one context read, not an unbounded RPC
// session. Generic large-response accounting does not broaden this frame cap.
const NativeMaximumFrames = 32

var ErrNativeProtocol = errors.New("native exchange unavailable")

type NativeFrameKind byte

const (
	NativeHelloFrame NativeFrameKind = iota + 1
	NativeCommandFrame
	NativeMetadataFrame
	NativeDataFrame
	NativeAcknowledgeFrame
	NativeCommitFrame
	NativeDoneFrame
)

// Frame allocation is bounded before payload I/O. Read/write ownership belongs
// to the caller; plaintext buffers must be cleared after joined use. No framing
// value supplies authority, retries or an automatic reconnect instruction.
// NativeStream is the purpose-specific bounded native frame channel shared by
// the transport and the exact-owner TLS adapter. It has no RPC dispatch surface.
type NativeStream interface {
	Context() context.Context
	Receive(context.Context) (NativeFrame, error)
	Send(context.Context, NativeFrame) error
	Close() error
}

type NativeFrame struct {
	Kind    NativeFrameKind
	Payload []byte
}

func nativeFrameLimit(kind NativeFrameKind) int {
	if kind == NativeCommandFrame {
		return NativeCommandBytes
	}
	if kind == NativeDataFrame {
		return NativeDataBytes
	}
	if kind >= NativeHelloFrame && kind <= NativeDoneFrame {
		return NativeControlBytes
	}
	return 0
}

func ReadNativeFrame(r io.Reader) (NativeFrame, error) {
	var header [5]byte
	if r == nil {
		return NativeFrame{}, ErrNativeProtocol
	}
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return NativeFrame{}, ErrNativeProtocol
	}
	kind, size := NativeFrameKind(header[0]), int64(binary.BigEndian.Uint32(header[1:]))
	if size <= 0 || size > int64(nativeFrameLimit(kind)) {
		return NativeFrame{}, ErrNativeProtocol
	}
	frame := NativeFrame{Kind: kind, Payload: make([]byte, int(size))}
	if _, err := io.ReadFull(r, frame.Payload); err != nil {
		clear(frame.Payload)
		return NativeFrame{}, ErrNativeProtocol
	}
	return frame, nil
}

func WriteNativeFrame(w io.Writer, f NativeFrame) error {
	if w == nil || len(f.Payload) == 0 || len(f.Payload) > nativeFrameLimit(f.Kind) {
		return ErrNativeProtocol
	}
	var header [5]byte
	header[0] = byte(f.Kind)
	binary.BigEndian.PutUint32(header[1:], uint32(len(f.Payload)))
	if n, err := w.Write(header[:]); err != nil || n != len(header) {
		return ErrNativeProtocol
	}
	if n, err := w.Write(f.Payload); err != nil || n != len(f.Payload) {
		return ErrNativeProtocol
	}
	return nil
}

// Worker-hop hello leaves OperationID empty and Fence zero: the connector
// resolves the existing exact operation independently. All owner-hop messages
// and commands include the full reference. No worker chooses its hub owner.
// NativeReference carries routing/fencing identities only. A receiver must
// independently bind actual peer, live operation and stored current authority.
type NativeReference struct {
	InstallationID string `json:"installationID"`
	SessionID      string `json:"sessionID,omitempty"`
	QueryID        string `json:"queryID,omitempty"`
	WorkerID       string `json:"workerID"`
	OperationID    string `json:"operationID"`
	Fence          int64  `json:"fence"`
}
type NativeHello struct {
	Format    string          `json:"format"`
	Reference NativeReference `json:"reference"`
	Nonce     string          `json:"nonce"`
	// Dedicated projected Pod token for current TokenReview/live-worker proof.
	// This is not a human credential and is never persisted or logged.
	WorkerToken []byte `json:"workerToken"`
	// Empty on the worker hop; the trusted connector supplies the exact leaf
	// from actual TLS on the owner hop. It does not claim this was hub TLS.
	WorkerLeaf []byte `json:"workerLeaf"`
}

// Source contains the exact private verified expectation/copy facts, never
// caller object keys or authentication claims. The accepted source reader and
// operation gate supply it; decoding JSON does not confer read or key rights.
type NativeCommand struct {
	Format        string          `json:"format"`
	Reference     NativeReference `json:"reference"`
	Nonce         string          `json:"nonce"`
	Kind          string          `json:"kind"`
	Source        json.RawMessage `json:"source"`
	Operation     json.RawMessage `json:"operation"`
	Projection    json.RawMessage `json:"projection,omitempty"`
	ParentID      string          `json:"parentID"`
	Generation    int64           `json:"generation"`
	WindowID      string          `json:"windowID"`
	LeaseSequence int64           `json:"leaseSequence"`
	Offset        int64           `json:"offset"`
	Length        int64           `json:"length"`
	Until         string          `json:"until"`
}
type NativeMetadata struct {
	Format    string          `json:"format"`
	Reference NativeReference `json:"reference"`
	Nonce     string          `json:"nonce"`
	Metadata  json.RawMessage `json:"metadata"`
}

// Acknowledge is a finite response to one exact phase. A relay cannot turn a
// successful upstream send into the final HTTP handoff acknowledgement.
type NativeAcknowledge struct {
	Format    string          `json:"format"`
	Reference NativeReference `json:"reference"`
	Nonce     string          `json:"nonce"`
	Phase     string          `json:"phase"`
	Bytes     int64           `json:"bytes"`
}

func DecodeNativeHello(b []byte) (NativeHello, error) { return decodeNativeControl[NativeHello](b) }
func DecodeNativeCommand(b []byte) (NativeCommand, error) {
	return decodeNativeBounded[NativeCommand](b, NativeCommandBytes)
}
func DecodeNativeMetadata(b []byte) (NativeMetadata, error) {
	return decodeNativeControl[NativeMetadata](b)
}
func DecodeNativeAcknowledge(b []byte) (NativeAcknowledge, error) {
	return decodeNativeControl[NativeAcknowledge](b)
}
func decodeNativeControl[T any](b []byte) (T, error) {
	return decodeNativeBounded[T](b, NativeControlBytes)
}
func decodeNativeBounded[T any](b []byte, limit int64) (T, error) {
	v, err := decodeClosedRPC[T](bytes.NewReader(b), limit)
	if err != nil {
		var zero T
		return zero, ErrNativeProtocol
	}
	return v, nil
}
