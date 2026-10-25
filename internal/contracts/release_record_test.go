package contracts

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func releaseTestImage(n int) string {
	return fmt.Sprintf("registry.example.test:5000/asservat@sha256:%064x", n)
}

func TestReleaseRecordLifecycle(t *testing.T) {
	r, err := NewReleaseRecord("11111111-1111-4111-8111-111111111111", releaseTestImage(1), 81)
	if err != nil {
		t.Fatal(err)
	}
	launch := ReleaseWorkloads{HubAPI: ReleaseWorkload{Launch: 2}, HubWorker: ReleaseWorkload{Launch: 3}}
	up, err := r.Next(releaseTestImage(2), 82, launch)
	if err != nil {
		t.Fatal(err)
	}
	if up.Revision != 2 || up.Original != releaseTestImage(1) || up.Previous != releaseTestImage(1) || up.Image != releaseTestImage(2) || up.Schema != 82 ||
		up.Workloads.HubAPI != (ReleaseWorkload{2, 3, 2}) || up.Workloads.HubWorker != (ReleaseWorkload{3, 4, 3}) || len(up.History) != 2 || len(r.History) != 1 {
		t.Fatalf("revision 2: %+v", up)
	}
	if _, err = up.Next(releaseTestImage(3), 82, launch); err == nil {
		t.Fatal("next change before settling")
	}
	settled, err := up.Settled()
	if err != nil || settled.Previous != "" || settled.Workloads.HubAPI.PreviousGeneration != 0 || up.Previous == "" {
		t.Fatal("settle", err)
	}
	back, err := settled.Next(releaseTestImage(1), 81, ReleaseWorkloads{})
	if err != nil || back.Revision != 3 || back.Workloads.HubAPI.Generation != 4 || back.Original != releaseTestImage(1) {
		t.Fatal("rollback", err)
	}
	if e, ok := back.HistoryEntry(releaseTestImage(2)); !ok || e.Revision != 2 || e.Schema != 82 {
		t.Fatal("history entry", e)
	}
	// The history keeps the newest 16 entries.
	cur := back
	for i := 0; i < 30; i++ {
		if cur, err = cur.Settled(); err != nil {
			t.Fatal(err)
		}
		if cur, err = cur.Next(releaseTestImage(100+i), 82, ReleaseWorkloads{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(cur.History) != ReleaseRecordHistoryLimit || cur.History[ReleaseRecordHistoryLimit-1].Revision != cur.Revision || cur.Original != releaseTestImage(1) {
		t.Fatalf("history %d", len(cur.History))
	}
	raw, err := EncodeReleaseRecord(cur)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeReleaseRecord(bytes.NewReader(raw)); err != nil || got.Revision != cur.Revision {
		t.Fatal("round trip", err)
	}
}

func TestReleaseRecordValidateRejectsInconsistency(t *testing.T) {
	r, _ := NewReleaseRecord("11111111-1111-4111-8111-111111111111", releaseTestImage(1), 81)
	up, _ := r.Next(releaseTestImage(2), 82, ReleaseWorkloads{HubAPI: ReleaseWorkload{Launch: 2}, HubWorker: ReleaseWorkload{Launch: 3}})
	for name, change := range map[string]func(*ReleaseRecord){
		"revision gap":          func(r *ReleaseRecord) { r.History[0].Revision = 0 },
		"revision ahead":        func(r *ReleaseRecord) { r.Revision = 3 },
		"history not current":   func(r *ReleaseRecord) { r.History[1].Image = releaseTestImage(9) },
		"history schema":        func(r *ReleaseRecord) { r.History[1].Schema = 81 },
		"previous not history":  func(r *ReleaseRecord) { r.Previous = releaseTestImage(9) },
		"original changed":      func(r *ReleaseRecord) { r.Original = releaseTestImage(9) },
		"generation step":       func(r *ReleaseRecord) { r.Workloads.HubAPI.Generation++ },
		"previous generation":   func(r *ReleaseRecord) { r.Workloads.HubWorker.PreviousGeneration = 1 },
		"unpinned image":        func(r *ReleaseRecord) { r.Image = "registry.example.test/asservat:latest" },
		"format":                func(r *ReleaseRecord) { r.Format = "asservat-release/v2" },
		"empty history":         func(r *ReleaseRecord) { r.History = nil },
		"previous equals image": func(r *ReleaseRecord) { r.Previous = r.Image },
	} {
		c := up
		c.History = append([]ReleaseHistoryEntry(nil), up.History...)
		change(&c)
		if c.Validate() == nil {
			t.Error(name, "accepted")
		}
	}
	r.Workloads.HubAPI.Launch = 2
	if r.Validate() == nil {
		t.Error("revision 1 with generations accepted")
	}
}

func TestReleaseRecordDecodingIsStrict(t *testing.T) {
	r, _ := NewReleaseRecord("11111111-1111-4111-8111-111111111111", releaseTestImage(1), 81)
	raw, _ := EncodeReleaseRecord(r)
	for name, body := range map[string]string{
		"unknown field": strings.Replace(string(raw), "{", `{"extra":true,`, 1),
		"second value":  string(raw) + "{}",
		"reordered":     strings.Replace(string(raw), `"format":"asservat-release/v1","installationID":"11111111-1111-4111-8111-111111111111"`, `"installationID":"11111111-1111-4111-8111-111111111111","format":"asservat-release/v1"`, 1),
		"oversized":     string(raw) + strings.Repeat(" ", ReleaseRecordMaxBytes),
	} {
		if body == string(raw) {
			t.Fatal(name, "unchanged")
		}
		if _, err := DecodeReleaseRecord(strings.NewReader(body)); err == nil {
			t.Error(name, "accepted")
		}
	}
	if _, err := DecodeReleaseRecord(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
}
