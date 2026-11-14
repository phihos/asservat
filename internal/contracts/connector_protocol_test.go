package contracts

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Cross-release decoding ignores unknown members but keeps the closed
// decoder's rules for known ones (ADR-333): encoding/json matches names
// case-insensitively, so a wrong-case alias must not reach a known field.
func TestOpenDecoderIgnoresUnknownButKeepsKnownFieldsExact(t *testing.T) {
	b, e := EncodeAPIContextOperation(APIContextOperation{Format: APIContextExchangeFormat, Sequence: 1, Method: "read-process", Body: json.RawMessage(`{"known":1}`)})
	if e != nil {
		t.Fatal(e)
	}
	for name, payload := range map[string][]byte{
		"unknown-top":    append([]byte(`{"addedByNewerPeer":{"x":[1,2]},`), b[1:]...),
		"unknown-nested": bytes.Replace(b, []byte(`{"known":1}`), []byte(`{"added":true,"known":1}`), 1),
	} {
		if v, e := DecodeAPIContextOperation(payload); e != nil || v.Method != "read-process" || v.Sequence != 1 {
			t.Fatal(name, "refused", e)
		}
	}
	for name, payload := range map[string][]byte{
		"wrong-case":        bytes.Replace(b, []byte(`"sequence"`), []byte(`"Sequence"`), 1),
		"wrong-case-shadow": append([]byte(`{"Method":"finish",`), b[1:]...),
		"duplicate":         append([]byte(`{"sequence":1,`), b[1:]...),
		"null":              bytes.Replace(b, []byte(`"method":"read-process"`), []byte(`"method":null`), 1),
		"noncanonical":      bytes.Replace(b, []byte(`"sequence":1`), []byte(`"sequence":1.0`), 1),
	} {
		if _, e := DecodeAPIContextOperation(payload); e == nil {
			t.Fatal(name, "accepted")
		}
	}
}
