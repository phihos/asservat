package contracts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestLiveOwnerClosedFramesAndBounds(t *testing.T) {
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	until := time.Now().Add(time.Second)
	for _, kind := range []string{"current", "identity", "result", "error", "done"} {
		f := LiveOwnerFrame{Kind: kind, Nonce: nonce, Sequence: 1, Until: until}
		if kind == "identity" {
			f.Identity = json.RawMessage(`{"current":true}`)
		}
		if kind == "result" {
			f.Result = json.RawMessage(`{"batch":{}}`)
		}
		if kind == "error" {
			f.Failure = "unavailable"
		}
		b, _ := json.Marshal(f)
		if _, e := DecodeLiveOwnerFrame(bytes.NewReader(b)); e != nil {
			t.Fatal(kind, e)
		}
		for _, mode := range []string{"nonce", "sequence", "extra", "union", "too-large"} {
			g := f
			switch mode {
			case "nonce":
				g.Nonce = "x"
			case "sequence":
				g.Sequence = NativeMaximumFrames + 1
			case "union":
				if kind == "identity" {
					g.Result = json.RawMessage(`{}`)
				} else {
					g.Identity = json.RawMessage(`{}`)
				}
			case "too-large":
				g.Kind = "result"
				g.Identity = nil
				g.Failure = ""
				g.Result = json.RawMessage(`"` + string(bytes.Repeat([]byte{'a'}, LiveOwnerResultBytes)) + `"`)
			}
			bad, _ := json.Marshal(g)
			if mode == "extra" {
				bad = append(bad[:len(bad)-1], []byte(`,"unknown":true}`)...)
			}
			if _, e := DecodeLiveOwnerFrame(bytes.NewReader(bad)); e == nil {
				t.Fatal("accepted invalid frame", kind, mode)
			}
		}
	}
	h := LiveOwnerHello{Format: LiveOwnerFormat, RootID: "11111111-1111-4111-8111-111111111111", OwnerID: "11111111-1111-4111-8111-111111111111", CallID: "11111111-1111-4111-8111-111111111111", Nonce: nonce, Until: until, Actor: LiveOwnerActor{Issuer: "https://issuer.invalid", Subject: "human", ClientID: "console", Kind: "human"}, Command: json.RawMessage(`{"read":{}}`), Policy: LiveOwnerPolicy{UID: "policy", Generation: 1, Digest: [32]byte{1}}}
	b, _ := json.Marshal(h)
	if _, e := DecodeLiveOwnerHello(bytes.NewReader(b)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(append([]byte{}, b...), []byte(`{}`)...), append(b[:len(b)-1], []byte(`,"token":"forbidden"}`)...)} {
		if _, e := DecodeLiveOwnerHello(bytes.NewReader(bad)); e == nil {
			t.Fatal("nonclosed owner Hello")
		}
	}
}
