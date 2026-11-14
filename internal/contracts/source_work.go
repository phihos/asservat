package contracts

import (
	"bytes"
	"encoding/json"
	"time"
)

const SourceWorkFormat = "ordinary-packet-source-work/v1"

// Canonical little-endian BPF bytes avoid verbose per-instruction JSON. The
// existing real signers accept at most16KiB signing input;11KiB payload leaves
// bounded room for JWS base64/protected headers and its final64-byte signature.
// Finite capture limits remain unchanged.
const SourceWorkBytes = 11 << 10
const SourceSignedWorkBytes = 16 << 10

type SourceWork struct {
	Format        string            `json:"format"`
	Channel       APIContextChannel `json:"channel"`
	Target        json.RawMessage   `json:"target,omitempty"`
	Node          json.RawMessage   `json:"node,omitempty"`
	Source        json.RawMessage   `json:"source,omitempty"`
	ProgramLE     []byte            `json:"programLE"`
	NotAfter      time.Time         `json:"notAfter"`
	Stop          bool              `json:"stop"`
	StopIssuedAt  time.Time         `json:"stopIssuedAt"`
	StopSnapshot  json.RawMessage   `json:"stopSnapshot,omitempty"`
	StopRecording json.RawMessage   `json:"stopRecording,omitempty"`
	StopProfile   json.RawMessage   `json:"stopProfile,omitempty"`
}

func EncodeSourceWork(w SourceWork) ([]byte, error) { return canonicalAPIContext(w, SourceWorkBytes) }
func DecodeSourceWork(b []byte) (SourceWork, error) {
	w, e := decodeOpenRPC[SourceWork](bytes.NewReader(b), SourceWorkBytes)
	if e != nil || w.Format != SourceWorkFormat || (len(w.StopProfile) == 0 && len(w.StopRecording) == 0 && (len(w.Target) == 0 || len(w.Node) == 0)) {
		return SourceWork{}, ErrAPIContextProtocol
	}
	return w, nil
}

// Source replies reuse only the existing finite result/receipt frame ordering.
// The semantic payload stays distinct and never invents a capture identifier.
type SourceReply struct {
	CaptureID          string `json:"captureID,omitempty"`
	SnapshotID         string `json:"snapshotID,omitempty"`
	RecordingAttemptID string `json:"recordingAttemptID,omitempty"`
	ProfileAttemptID   string `json:"profileAttemptID,omitempty"`
	Format             string `json:"format"`
	SourceID           string `json:"sourceID"`
	Fence              string `json:"fence"`
	State              string `json:"state"`
}

func EncodeSourceReply(w SourceReply) ([]byte, error) { return canonicalAPIContext(w, 1024) }
func DecodeSourceReply(b []byte) (SourceReply, error) {
	w, e := decodeOpenRPC[SourceReply](bytes.NewReader(b), 1024)
	if e != nil || w.Format != SourceWorkFormat || !(len(w.SourceID) == 36 && len(w.Fence) == 36 && w.ProfileAttemptID == "" && w.RecordingAttemptID == "" || w.SourceID == "" && w.Fence == "" && len(w.CaptureID) == 36 && (len(w.ProfileAttemptID) == 36 && w.RecordingAttemptID == "" || len(w.RecordingAttemptID) == 36 && w.ProfileAttemptID == "") && w.SnapshotID == "") || (w.State != "queued" && w.State != "unavailable" && w.State != "received") {
		return SourceReply{}, ErrAPIContextProtocol
	}
	return w, nil
}
