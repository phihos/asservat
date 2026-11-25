package hub

import (
	"encoding/json"
	"testing"
)

// A question for statistics names only taps that count packets. A key
// named twice is read by Go as its last value and may be read by sharkd as
// its first: such a question is none.
func TestTapsAreNamedOnce(t *testing.T) {
	for question, allowed := range map[string]bool{
		`{"tap0":"phs","tap1":"conv:TCP","filter":"tcp"}`: true,
		`{"tap0":"follow:tcp","tap0":"phs"}`:              false,
		`{"tap0":"phs","tap0":"phs"}`:                     false,
		`{"tap0":"follow:tcp"}`:                           false,
		`{"tap0":"phs"} {"tap0":"follow:tcp"}`:            false,
	} {
		if got := allowedTaps(json.RawMessage(question)); got != allowed {
			t.Errorf("%s: allowed %v", question, got)
		}
	}
}
