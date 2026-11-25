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
// closes; what its requester and administrators have open stays, since
// they see it shared or not.
func TestUnsharingEndsColleaguesViews(t *testing.T) {
	ended := map[string]bool{}
	v := views{open: map[string]*view{}}
	for who, shared := range map[string]bool{"alice": false, "root": false, "bob": true} {
		v.open[who] = &view{user: who, capture: "c", shared: shared, end: func() { ended[who] = true }}
	}
	v.open["other"] = &view{user: "bob", capture: "d", shared: true, end: func() { ended["other"] = true }}
	v.endOf("c", true)
	if ended["alice"] || ended["root"] || !ended["bob"] || ended["other"] {
		t.Fatal(ended)
	}
	v.endOf("c", false)
	if !ended["alice"] || !ended["root"] || ended["other"] {
		t.Fatal("deleting the capture left views of it open", ended)
	}
}
