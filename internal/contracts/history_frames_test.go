package contracts

import (
	"asservat.local/asservat/internal/domain/capture"
	"bytes"
	"encoding/json"
	"testing"
)

func TestHistoryFrameUsesDerivedBundleBoundWithoutWideningCommonFrames(t *testing.T) {
	if HistoryBundleBytes != capture.HistoryBundleMaxBytes || APIContextOperationBytes != 32<<10 {
		t.Fatal("bundle/common bound drift")
	}
	var b capture.HistoryCiphertexts
	for i, n := range capture.HistoryCiphertextLimits() {
		b[i] = bytes.Repeat([]byte{255}, int(n))
	}
	encoded, e := capture.EncodeHistoryCiphertexts(b)
	if e != nil || len(encoded) != HistoryBundleBytes {
		t.Fatal("maximum codec bound not exact", len(encoded), e)
	}
	m := HistoryCiphertextMessage{Format: HistoryCiphertextFormat, OperationID: "00000000-0000-4000-8000-000000000001", Bundle: encoded}
	payload, e := EncodeHistoryCiphertexts(m)
	if e != nil {
		t.Fatal(e)
	}
	var wire bytes.Buffer
	if WriteAPIContextFrame(&wire, APIContextFrame{Kind: HistoryRequestFrame, Payload: payload}) != nil {
		t.Fatal("history rejected bounded ciphertext")
	}
	if _, e = ReadAPIContextFrame(&wire); e != nil {
		t.Fatal(e)
	}
	if WriteAPIContextFrame(&wire, APIContextFrame{Kind: APIContextQueryFrame, Payload: payload}) == nil {
		t.Fatal("history payload entered common query")
	}
	m.Bundle = json.RawMessage(bytes.Repeat([]byte{' '}, HistoryBundleBytes+1))
	if _, e = EncodeHistoryCiphertexts(m); e == nil {
		t.Fatal("oversized bundle accepted")
	}
}
