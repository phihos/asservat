package hub

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// What fails inside the hub is in its log, not in an answer: a database's
// or a store's words name queries and paths.
func TestInternalErrorsAreNotTold(t *testing.T) {
	for _, err := range []error{errors.New(`pq: relation "captures" at /data/blobs/x`), fmt.Errorf("read: %w", context.DeadlineExceeded)} {
		if said := told(err).msg; said != "internal error" {
			t.Errorf("told %q", said)
		}
	}
	if said := told(errStatus{422, "the file is binary"}).msg; said != "the file is binary" {
		t.Errorf("the hub's own word became %q", said)
	}
}

// When a capture stops being shared, what colleagues have open of it
// closes; what its requester has open stays.
func TestUnsharingEndsColleaguesViews(t *testing.T) {
	ended := map[string]bool{}
	v := views{open: map[string]*view{}}
	for _, who := range []string{"alice", "bob"} {
		v.open[who] = &view{user: who, capture: "c", end: func() { ended[who] = true }}
	}
	v.open["other"] = &view{user: "bob", capture: "d", end: func() { ended["other"] = true }}
	v.endOf("c", "alice")
	if ended["alice"] || !ended["bob"] || ended["other"] {
		t.Fatal(ended)
	}
}
