package execution

import (
	"bytes"
	"testing"
)

func TestGoProfileAuthorizationHasOneFiniteHeaderValue(t *testing.T) {
	for _, test := range []struct {
		value []byte
		valid bool
	}{
		{nil, false}, {[]byte("Bearer synthetic"), true}, {bytes.Repeat([]byte{'x'}, GoProfileAuthorizationLimit), true}, {bytes.Repeat([]byte{'x'}, GoProfileAuthorizationLimit+1), false}, {[]byte("Bearer x\r\nX-Other: y"), false}, {[]byte{0}, false}, {[]byte{127}, false}, {[]byte("Béarer x"), false},
	} {
		if ValidGoProfileAuthorization(test.value) != test.valid {
			t.Fatal("authorization header boundary", len(test.value))
		}
	}
}
