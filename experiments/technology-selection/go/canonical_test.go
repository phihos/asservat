package feasibility

import (
	"encoding/json/jsontext"
	"testing"
)

func TestStandardLibraryJCS(t *testing.T) {
	cases := map[string]string{
		` {"b":2,"a":1} `: `{"a":1,"b":2}`,
		`{"values":[1E30,4.50,2e-3,0.000000000000000000000000001,-0]}`: `{"values":[1e+30,4.5,0.002,1e-27,0]}`,
		`{"\ufffd":1,"\ud83d\ude00":2}`:                                `{"😀":2,"�":1}`,
	}
	for input, want := range cases {
		v := jsontext.Value(input)
		if e := v.Canonicalize(); e != nil {
			t.Fatal(e)
		}
		if string(v) != want {
			t.Fatalf("got %s want %s", v, want)
		}
		if e := v.Canonicalize(); e != nil || string(v) != want {
			t.Fatal("not idempotent")
		}
	}
	for _, input := range []string{`{"a":1,"a":2}`, `{"s":"\ud800"}`, `{"n":NaN}`, string([]byte{'"', 0xff, '"'})} {
		v := jsontext.Value(input)
		if e := v.Canonicalize(); e == nil {
			t.Fatalf("invalid accepted: %q", input)
		}
	}
	t.Log("Go standard-library RFC 8785 samples, UTF-16 key ordering, duplicate names and invalid Unicode; full contract numeric-domain corpus remains pending")
}
