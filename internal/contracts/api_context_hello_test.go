package contracts

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAPIContextHelloRequiresOriginalConversationEnd(t *testing.T) {
	until := time.Now().UTC().Add(30 * time.Second).Truncate(time.Microsecond)
	value := APIContextHello{Format: APIContextExchangeFormat, Channel: APIContextChannel{ExchangeID: "one"}, StandbyUntil: until}
	encoded, e := EncodeAPIContextHello(value)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeAPIContextHello(encoded)
	if e != nil || !got.StandbyUntil.Equal(until) {
		t.Fatal("original end changed", e)
	}
	value.StandbyUntil = time.Time{}
	if _, e = EncodeAPIContextHello(value); e == nil {
		t.Fatal("missing original end encoded")
	}
	for _, payload := range []string{`{"format":"api-context-exchange/v1","channel":{}}`, `{"format":"api-context-exchange/v1","channel":{},"standbyUntil":null}`, `{"format":"api-context-exchange/v1","channel":{},"standbyUntil":"bad"}`} {
		if _, e = DecodeAPIContextHello([]byte(payload)); e == nil {
			t.Fatal("missing or malformed original end decoded")
		}
	}
	var fields map[string]any
	if e = json.Unmarshal(encoded, &fields); e != nil {
		t.Fatal(e)
	}
	fields["futureAuthority"] = true
	unknown, _ := json.Marshal(fields)
	if _, e = DecodeAPIContextHello(unknown); e == nil {
		t.Fatal("unknown field decoded")
	}
}
