package presentation

import "testing"

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
	} {
		if got, after := statusWait(c.name, []byte(c.raw)); got != c.want || got != "" && after != 3 {
			t.Errorf("%s %s: %q %d", c.name, c.raw, got, after)
		}
	}
	if replyRevision([]byte(`{"status":"ok","data":{"revision":7}}`)) != 7 || replyRevision([]byte(`{"status":"pending","data":{"revision":2}}`)) != 2 || replyRevision([]byte(`{"status":"error","data":{"revision":7}}`)) != 0 {
		t.Fatal("revision")
	}
}
