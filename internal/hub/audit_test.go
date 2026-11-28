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
)

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
