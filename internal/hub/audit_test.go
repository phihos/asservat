package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"asservat.local/asservat/internal/api"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

// An installation that sends its logs to a SIEM gets the audit log there
// too: with AuditTo, every entry is also written as one line of JSON, the
// same as GET /api/audit returns it. Without it nothing is written.
func TestAuditEntriesAreAlsoWrittenAsLines(t *testing.T) {
	dsn := os.Getenv("ASSERVAT_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSERVAT_TEST_DSN is not set")
	}
	ctx := context.Background()
	store, err := OpenStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Nothing is written unless it was asked for.
	actor := "auditor-" + uuid.NewString()[:8]
	if err := store.Audit(ctx, actor, "capture.request", "", map[string]string{"workload": "Deployment/api"}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	store.AuditTo(&out)
	// A capture is named only while it exists; none is needed for the line.
	if err := store.Audit(ctx, actor, "artifact.download", "", map[string]string{"file": "api-1/capture.pcap"}); err != nil {
		t.Fatal(err)
	}
	// Entries of the same moment stay whole lines.
	var all sync.WaitGroup
	for range 20 {
		all.Go(func() { store.Audit(ctx, actor, "artifact.view", "", map[string]string{"file": "api-1/app.log"}) })
	}
	all.Wait()

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 21 {
		t.Fatalf("%d lines, want 21: %s", len(lines), out.String())
	}
	var first struct {
		Log    string            `json:"log"`
		ID     int64             `json:"id"`
		At     time.Time         `json:"at"`
		Actor  string            `json:"actor"`
		Action string            `json:"action"`
		Detail map[string]string `json:"detail"`
	}
	for _, line := range lines {
		if err := json.Unmarshal([]byte(line), &first); err != nil {
			t.Fatalf("a line is no JSON: %q: %v", line, err)
		}
	}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first.Log != "audit" || first.Actor != actor || first.Action != "artifact.download" || first.Detail["file"] != "api-1/capture.pcap" || time.Since(first.At) > time.Minute {
		t.Fatalf("the line: %s", lines[0])
	}
	// An entry about a capture names it by its ID and its number.
	c := api.Capture{ID: uuid.NewString(), Requester: actor, State: api.StateRunning, ExpiresAt: time.Now().Add(time.Hour)}
	c.Cluster, c.Namespace, c.Workload = "a"+c.ID[:8], "payments", "Deployment/api"
	if err := store.CreateCapture(ctx, c); err != nil {
		t.Fatal(err)
	}
	defer store.DeleteCapture(ctx, c.ID)
	out.Reset()
	if err := store.Audit(ctx, actor, "capture.request", c.ID, nil); err != nil {
		t.Fatal(err)
	}
	var about struct {
		Capture string `json:"capture"`
		Number  int64  `json:"number"`
	}
	if err := json.Unmarshal(out.Bytes(), &about); err != nil || about.Capture != c.ID || about.Number == 0 {
		t.Fatalf("the line of an entry about a capture: %s (%v)", out.String(), err)
	}
	// A line that cannot be written leaves the entry in the log.
	store.AuditTo(failingWriter{})
	if err := store.Audit(ctx, actor, "capture.stop", c.ID, nil); err != nil {
		t.Fatal("an entry whose line could not be written:", err)
	}
	store.AuditTo(&out)

	// The line is the entry of the log: the same number and moment.
	log, err := store.AuditLog(ctx, time.Now().Add(time.Hour), math.MaxInt64, 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range log {
		if e.ID == first.ID {
			if !e.At.Equal(first.At) || e.Actor != actor {
				t.Fatalf("the entry %+v is not the line %s", e, lines[0])
			}
			return
		}
	}
	t.Fatal("the line names no entry of the log:", lines[0])
}

// The console's audit log follows what happens: every entry is hinted at
// on the stream of events, as "audit", which names nothing. A change of a
// capture is hinted at as "changed", as before, and the two are told apart:
// who watches captures is not made to load them anew for every file that
// someone opens.
func TestAnAuditEntryIsHintedAt(t *testing.T) {
	dsn := os.Getenv("ASSERVAT_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSERVAT_TEST_DSN is not set")
	}
	ctx := context.Background()
	store, err := OpenStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h, err := New(Config{Store: store, Blobs: DirBlobs(t.TempDir()), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour, WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	hints := make(chan string, 8)
	h.mu.Lock()
	h.watchers[hints] = struct{}{}
	h.mu.Unlock()
	if err := store.Audit(ctx, "auditor", "artifact.view", "", map[string]string{"name": "api-1/app.log"}); err != nil {
		t.Fatal(err)
	}
	select {
	case hint := <-hints:
		if hint != "audit" {
			t.Fatalf("an audit entry is hinted at as %q", hint)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an audit entry is not hinted at")
	}
	h.notify("")
	if hint := <-hints; hint != "changed" {
		t.Fatalf("a change is hinted at as %q", hint)
	}
}
