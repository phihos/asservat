package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func EncodeHistoryCiphertexts(b HistoryCiphertexts) ([]byte, error) {
	if !b.Valid() {
		return nil, artifact.ErrLimit
	}
	v, e := json.Marshal(b)
	if e != nil || len(v) > HistoryBundleMaxBytes {
		clear(v)
		return nil, artifact.ErrLimit
	}
	return v, nil
}
func DecodeHistoryCiphertexts(b []byte) (HistoryCiphertexts, error) {
	var out HistoryCiphertexts
	if len(b) == 0 || len(b) > HistoryBundleMaxBytes {
		return out, artifact.ErrLimit
	}
	var raw []json.RawMessage
	d := json.NewDecoder(bytes.NewReader(b))
	if d.Decode(&raw) != nil || d.Decode(new(any)) != io.EOF || len(raw) != len(out) {
		return out, artifact.ErrInvalid
	}
	limits := HistoryCiphertextLimits()
	for i, r := range raw {
		if int64(len(r)) > 2+((limits[i]+2)/3)*4 || json.Unmarshal(r, &out[i]) != nil || len(out[i]) == 0 || int64(len(out[i])) > limits[i] {
			out.Clear()
			return HistoryCiphertexts{}, artifact.ErrLimit
		}
	}
	return out, nil
}
func HistoryCiphertextsDigest(b HistoryCiphertexts) (artifact.Digest, error) {
	w, e := EncodeHistoryCiphertexts(b)
	if e != nil {
		return artifact.Digest{}, e
	}
	defer clear(w)
	return sha256.Sum256(w), nil
}
func HistoryCopiesDigest(c artifact.Copies) artifact.Digest {
	b, _ := json.Marshal(c)
	return sha256.Sum256(b)
}

type HistoryDeleteCompletion struct {
	RootID, CaptureID, AttemptID, OperationID, ProcessEpoch string
	ExpectationDigest, CopiesDigest                         artifact.Digest
	DeletionFence                                           int64
	CompletedAt, NotAfter                                   time.Time
}

func (c HistoryDeleteCompletion) Valid(a HistoryOperationAuthority) bool {
	e := a.Expectation
	return a.Operation == "purge" && e.Valid() && c.RootID == e.RootID && c.CaptureID == e.CaptureID && c.AttemptID == e.Registration.Location.AttemptID && c.OperationID == a.RequestID && c.ProcessEpoch == a.ExecutorEpoch && c.ExpectationDigest == HistoryExpectationDigest(e) && c.CopiesDigest == a.CopiesDigest && c.DeletionFence == a.DeletionFence && c.NotAfter.Equal(a.NotAfter) && !c.CompletedAt.Before(a.StartedAt) && !c.CompletedAt.After(a.NotAfter)
}
