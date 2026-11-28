package hub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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

type refusingBlobs struct{ Blobs }

func (refusingBlobs) Put(context.Context, string, io.Reader) error {
	return errors.New("The specified bucket does not exist: evidence at minio.infra.svc:9000")
}
func (refusingBlobs) Delete(context.Context, string) error { return nil }

// An evidence store that does not take a file, as a bucket that is not
// there, is said as that: a recording then tells its user what failed, not
// "500 internal error". The store's own words stay in the hub's log.
func TestAStoreThatTakesNoFileIsSaid(t *testing.T) {
	h := &Hub{Config: Config{Blobs: refusingBlobs{}, MasterKey: bytes.Repeat([]byte{7}, 32)}}
	_, err := h.keep(context.Background(), "api-1/app.log", strings.NewReader("a line\n"))
	said := told(err)
	if said.code != http.StatusServiceUnavailable || !strings.Contains(said.msg, "evidence store") || strings.Contains(said.msg, "minio") {
		t.Fatalf("told %d %q", said.code, said.msg)
	}
	// Who stopped waiting is not told that the store failed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.keep(ctx, "api-1/app.log", strings.NewReader("a line\n")); told(err).code == http.StatusServiceUnavailable {
		t.Fatalf("a request that was given up is told %q", told(err).msg)
	}
}
