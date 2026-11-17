package presentation

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStatusWaitSelectsTheStatusReadID(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000030"
	for _, c := range []struct {
		name, raw string
		want      string
	}{
		{"get_capture", `{"capture_id":"` + id + `","after_revision":3}`, id},
		{"get_grant", `{"grant_id":"` + id + `","after_revision":3}`, id},
		{"download_artifact", `{"action":"status","download_id":"` + id + `","after_revision":3}`, id},
		{"download_artifact", `{"action":"cancel","download_id":"` + id + `","after_revision":3}`, ""},
		{"get_capture", `{"capture_id":"` + id + `"}`, ""},
		{"get_case", `{"capture_id":"` + id + `","after_revision":3}`, ""},
		{"get_query_result", `{"query_handle":"` + id + `","after_revision":3}`, id},
		{"get_query_result", `{"query_handle":"` + id + `"}`, ""},
	} {
		if got, after := statusWait(c.name, []byte(c.raw)); got != c.want || got != "" && after != 3 {
			t.Errorf("%s %s: %q %d", c.name, c.raw, got, after)
		}
	}
	if replyRevision([]byte(`{"status":"ok","data":{"revision":7}}`)) != 7 || replyRevision([]byte(`{"status":"pending","data":{"revision":2}}`)) != 2 || replyRevision([]byte(`{"status":"error","data":{"revision":7}}`)) != 0 {
		t.Fatal("revision")
	}
}

// get_query_result with after_revision waits for the query's worker-ready
// notification and then reads the result, instead of returning pending.
func TestQueryResultWaitsForWorkerReadyNotification(t *testing.T) {
	s, f, _, _ := bridgeAuditFixture(t)
	changes := NewChanges()
	s.config.Changes = changes
	f.ready = false
	first, err := s.Call(t.Context(), f, "get_extract", extractInput("fileExcerpt", bridgeInput()))
	if err != nil || !strings.Contains(string(first.Body), `"status":"pending"`) {
		t.Fatalf("begin: %v %s", err, first.Body)
	}
	_ = first.Close(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		f.setReady(true)
		changes.Publish(f.q.ID)
	}()
	started := time.Now()
	reply, err := s.Call(t.Context(), f, "get_query_result", []byte(`{"query_handle":"`+f.q.ID+`","after_revision":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close(context.Background())
	if !strings.Contains(string(reply.Body), `"status":"ok"`) || time.Since(started) > 10*time.Second {
		t.Fatalf("waited %s: %s", time.Since(started), reply.Body)
	}
}
