package bootstrap

import (
	"bytes"
	"testing"
)

func TestEventLogDoublesPerEvent(t *testing.T) {
	var out bytes.Buffer
	log := eventLog(&out, "x")
	for range 5 {
		log("a")
		log("b")
	}
	want := "x: a (1)\nx: b (1)\nx: a (2)\nx: b (2)\nx: a (4)\nx: b (4)\n"
	if out.String() != want {
		t.Fatalf("%q", out.String())
	}
}
