package contracts

import (
	"bytes"
	"encoding/json"
)

const (
	HistoryWorkFormat       = "history-work/v1"
	HistoryCiphertextFormat = "history-ciphertexts/v1"
	// Four bounded ciphertexts: data192KiB, index4KiB, manifest128KiB,
	// commit32KiB. JSON array overhead13, plus each exact base64 expansion.
	HistoryBundleBytes = 13 + 4*(((192<<10)+2)/3+((4<<10)+2)/3+((128<<10)+2)/3+((32<<10)+2)/3)
	// Four receipts each have version+ETag strings of <=1024bytes. JSON may
	// expand each ASCII '<', '>' or '&' to six bytes; the remaining16KiB
	// covers bounded authority/identity/completion and punctuation.
	HistoryEnvelopeBytes        = 4*2*1024*6 + APIContextSignedWorkBytes
	HistoryCiphertextFrameBytes = HistoryBundleBytes + HistoryEnvelopeBytes
)

type HistoryWork struct {
	Format    string            `json:"format"`
	Channel   APIContextChannel `json:"channel"`
	Authority json.RawMessage   `json:"authority"`
}

func EncodeHistoryWork(w HistoryWork) ([]byte, error) {
	return canonicalAPIContext(w, APIContextWorkBytes)
}
func DecodeHistoryWork(b []byte) (HistoryWork, error) {
	w, e := decodeClosedRPC[HistoryWork](bytes.NewReader(b), APIContextWorkBytes)
	if e != nil || w.Format != HistoryWorkFormat || len(w.Authority) == 0 {
		return HistoryWork{}, ErrAPIContextProtocol
	}
	return w, nil
}

// HistoryCiphertextMessage is a distinct finite family. Its bundle is encoded
// once as an array of base64 ciphertext strings, never plaintext or evidence.
// RawMessage keeps base64 allocation behind each role's independent codec bound.
type HistoryCiphertextMessage struct {
	Format           string          `json:"format"`
	OperationID      string          `json:"operationId"`
	Bundle           json.RawMessage `json:"bundle,omitempty"`
	Copies           json.RawMessage `json:"copies,omitempty"`
	WriterCompletion json.RawMessage `json:"writerCompletion,omitempty"`
	DeleteCompletion json.RawMessage `json:"deleteCompletion,omitempty"`
	Failure          string          `json:"failure,omitempty"`
}

func EncodeHistoryCiphertexts(w HistoryCiphertextMessage) ([]byte, error) {
	b, e := canonicalAPIContext(w, HistoryCiphertextFrameBytes)
	if e != nil {
		return nil, e
	}
	if _, e = DecodeHistoryCiphertexts(b); e != nil {
		clear(b)
		return nil, e
	}
	return b, nil
}
func DecodeHistoryCiphertexts(b []byte) (HistoryCiphertextMessage, error) {
	w, e := decodeClosedRPC[HistoryCiphertextMessage](bytes.NewReader(b), HistoryCiphertextFrameBytes)
	if e != nil || w.Format != HistoryCiphertextFormat || len(w.OperationID) != 36 || len(w.Bundle) > HistoryBundleBytes || len(w.Copies)+len(w.WriterCompletion)+len(w.DeleteCompletion)+len(w.Failure) > HistoryEnvelopeBytes-1024 || len(w.Failure) > 32 {
		return HistoryCiphertextMessage{}, ErrAPIContextProtocol
	}
	return w, nil
}
