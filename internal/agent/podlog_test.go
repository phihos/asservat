package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"asservat.local/asservat/internal/api"
)

// logged appends lines to a log file as a container runtime writes them.
func logged(t *testing.T, file string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

// A container's log files on the node are read from their end on: whole
// lines without the runtime's prefix, a line written in parts as one, on
// into the file that follows a rotation and into that of the container's
// next instance.
func TestPodLogFollowsTheNodesFiles(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "0.log")
	logged(t, current, "2026-11-23T12:00:00.000000001Z stdout F from before the watch")
	logged(t, filepath.Join(dir, "0.log.20261123-110000"), "2026-11-23T11:00:00Z stdout F rotated long ago")
	l, err := openPodLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 100)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.follow(ctx, func(line []byte) { lines <- string(line) }) }()
	want := func(expected ...string) {
		t.Helper()
		for _, line := range expected {
			select {
			case got := <-lines:
				if got != line {
					t.Fatalf("line %q, want %q", got, line)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("no line %q", line)
			}
		}
	}
	logged(t, current,
		"2026-11-23T12:00:01.000000001Z stdout F served a request",
		"2026-11-23T12:00:02.000000001Z stderr P a line that the runtime ",
		"2026-11-23T12:00:02.000000002Z stderr P wrote in ",
		"2026-11-23T12:00:02.000000003Z stderr F three parts")
	want("served a request", "a line that the runtime wrote in three parts")
	// A line whose end is not written yet waits for it.
	f, _ := os.OpenFile(current, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("2026-11-23T12:00:03Z stdout F half a ")
	time.Sleep(20 * time.Millisecond)
	f.WriteString("line\n")
	f.Close()
	want("half a line")
	// The kubelet rotates: the file is renamed, the runtime goes on writing
	// to it until it has opened a new one.
	if err := os.Rename(current, current+".20261123-120004"); err != nil {
		t.Fatal(err)
	}
	logged(t, current+".20261123-120004", "2026-11-23T12:00:04Z stdout F the last of the old file")
	logged(t, current, "2026-11-23T12:00:05Z stdout F the first of the new file")
	want("the last of the old file", "the first of the new file")
	// The container's next instance writes its own file.
	logged(t, filepath.Join(dir, "1.log"), "2026-11-23T12:00:06Z stdout F started again")
	logged(t, filepath.Join(dir, "1.log"), "2026-11-23T12:00:07Z stdout F and goes on")
	want("started again", "and goes on")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-lines:
		t.Fatalf("a line too many: %q", line)
	default:
	}

	// Without the directory, or without a log file in it, the caller is told.
	if _, err := openPodLog(filepath.Join(dir, "none")); err == nil {
		t.Fatal("a directory that does not exist was opened")
	}
	if _, err := openPodLog(t.TempDir()); err == nil {
		t.Fatal("a directory without a log file was opened")
	}
}

func BenchmarkPodLogTake(b *testing.B) {
	dir := b.TempDir()
	os.WriteFile(filepath.Join(dir, "0.log"), []byte(strings.Repeat("2026-11-23T12:00:00.123456789Z stdout F served GET /api/items in 12ms status=200\n", 10000)), 0o600)
	l, err := openPodLog(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer l.changes.Close()
	pattern := regexp.MustCompile(`(?i)timeout|panic`)
	b.ReportAllocs()
	for b.Loop() {
		l.files[0].f.Seek(0, io.SeekStart)
		if err := l.take(l.files[0], func(line []byte) { pattern.Match(line) }); err != nil {
			b.Fatal(err)
		}
	}
}

// A log watch reads the pod's log files on its node and not the stream of
// the API server, which here would answer "fake logs".
func TestLogWatchReadsTheNodesFiles(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api-1", UID: "0f8a"},
		Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "app"}, {Name: "proxy"}}},
	}
	kube := fake.NewClientset(pod)
	reports := make(chan api.Trigger, 10)
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report api.Trigger
		json.NewDecoder(r.Body).Decode(&report)
		reports <- report
	}))
	defer hub.Close()
	a := &Agent{HubURL: hub.URL, Node: "node-a", Kube: kube, HTTP: http.DefaultClient, Proc: t.TempDir()}
	dir := filepath.Join(a.Proc, "1", "root", "var", "log", "pods", "shop_api-1_0f8a", "app")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logged(t, filepath.Join(dir, "0.log"), "2026-11-23T12:00:00Z stdout F upstream timeout before the watch")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := api.Watch{ID: "w1", When: api.Condition{Kind: api.OnLog, Params: map[string]string{"pattern": "timeout|fake", "container": "app"}}}
	go a.follow(ctx, ctx, w, pod)
	// The watch reads from when it has opened the file: lines are written
	// until one is reported.
	var report api.Trigger
	for waited := 0; report.Message == ""; waited++ {
		logged(t, filepath.Join(dir, "0.log"), "2026-11-23T12:00:01Z stdout F upstream timeout after 30s")
		select {
		case report = <-reports:
		case <-time.After(20 * time.Millisecond):
			if waited > 500 {
				t.Fatal("no report of the matching line")
			}
		}
	}
	if want := `a log line of container app matches "timeout|fake": upstream timeout after 30s`; report.Message != want || report.Pod != "api-1" {
		t.Fatalf("report %q of pod %q", report.Message, report.Pod)
	}
	if asked := slices.ContainsFunc(kube.Actions(), func(action k8stesting.Action) bool {
		return strings.Contains(action.GetSubresource(), "log")
	}); asked {
		t.Fatal("the API server was asked for the pod's logs")
	}
}
