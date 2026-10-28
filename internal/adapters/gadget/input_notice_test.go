package gadget

import "testing"

func TestObservedInputRequiresExactEnginePrefix(t *testing.T) {
	for _, c := range []struct {
		captured int
		wire     uint32
		snaplen  int
		want     bool
	}{
		{134, 1514, 134, true}, {64, 64, 134, true}, {134, 134, 134, true},
		{133, 1514, 134, false}, {135, 1514, 134, false}, {0, 0, 134, false},
		{0, 64, 134, false}, {65, 64, 134, false}, {-1, 64, 134, false}, {64, 64, 0, false},
		{134, ^uint32(0), 134, true},
	} {
		if got := completePrefix(c.captured, c.wire, c.snaplen); got != c.want {
			t.Fatalf("prefix %v: %v", c, got)
		}
	}
}
