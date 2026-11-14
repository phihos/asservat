package contracts

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAPIContextClosedOperationEncoding(t *testing.T) {
	b, e := EncodeAPIContextOperation(APIContextOperation{Format: APIContextExchangeFormat, Sequence: 1, Method: "read-process", Body: json.RawMessage(`{}`)})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeAPIContextOperation(b); e != nil {
		t.Fatal(e)
	}
	// ADR-333: a field of a newer peer is ignored.
	if v, e := DecodeAPIContextOperation(append([]byte(`{"addedByNewerPeer":"x",`), b[1:]...)); e != nil || v.Method != "read-process" {
		t.Fatal("newer field refused", e)
	}
	for name, payload := range map[string][]byte{
		"duplicate": append([]byte(`{"sequence":1,`), b[1:]...),
		"array":     []byte(`[]`),
		"null":      bytes.Replace(b, []byte(`"sequence":1`), []byte(`"sequence":null`), 1),
		"absent":    bytes.Replace(b, []byte(`,"sequence":1`), nil, 1),
		"zero":      bytes.Replace(b, []byte(`"sequence":1`), []byte(`"sequence":0`), 1),
		"over":      bytes.Replace(b, []byte(`"sequence":1`), []byte(`"sequence":17`), 1),
		"trailing":  append(append([]byte{}, b...), []byte(`{}`)...),
		"oversize":  bytes.Repeat([]byte(" "), APIContextOperationBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeAPIContextOperation(payload); e == nil {
				t.Fatal("unsafe wire accepted")
			}
		})
	}
	if _, e := EncodeAPIContextOperation(APIContextOperation{Format: APIContextExchangeFormat, Sequence: 1, Method: "x", Body: json.RawMessage(`"` + string(bytes.Repeat([]byte("x"), APIContextOperationBytes)) + `"`)}); e == nil {
		t.Fatal("oversize frame encoded")
	}
}
