package api

import (
	"strings"
	"testing"
)

func TestValidateAndSensitive(t *testing.T) {
	base := func(kind string, params map[string]string) CaptureRequest {
		return CaptureRequest{Cluster: "prod", Namespace: "payments", Workload: "Deployment/api", Kind: kind, Params: params}
	}
	for _, c := range []struct {
		name      string
		r         CaptureRequest
		valid     bool
		sensitive bool
	}{
		{"pod state", base(KindPodState, nil), true, false},
		{"logs", base(KindLogs, map[string]string{"previous": "true", "tailLines": "100"}), true, false},
		{"header pcap", base(KindPcap, map[string]string{"filter": "tcp port 80"}), true, false},
		{"payload pcap", base(KindPcap, map[string]string{"payload": "true"}), true, true},
		{"core dump", base(KindCoredump, nil), true, true},
		{"strace", base(KindStrace, nil), true, false},
		{"strace with strings", base(KindStrace, map[string]string{"strings": "true"}), true, true},
		{"profile endpoints", base(KindPprof, map[string]string{"endpoints": "6060/go-cpu,6060/go-heap"}), true, false},
		{"profile endpoint with memory", base(KindPprof, map[string]string{"endpoints": "8081/java-threads,8081/java-heapdump"}), true, true},
		{"unknown profile endpoint", base(KindPprof, map[string]string{"port": "8080", "path": "/admin/export"}), true, true},
		{"profile without endpoint", base(KindPprof, nil), false, false},
		{"profile with port only", base(KindPprof, map[string]string{"port": "6060"}), false, false},
		{"profile endpoint not in the catalog", base(KindPprof, map[string]string{"endpoints": "6060/go-everything"}), false, false},
		{"profile endpoint without port", base(KindPprof, map[string]string{"endpoints": "go-cpu"}), false, false},
		{"profile endpoint twice", base(KindPprof, map[string]string{"endpoints": "6060/go-cpu,6060/go-cpu"}), false, false},
		{"profile endpoints and a path", base(KindPprof, map[string]string{"endpoints": "6060/go-cpu", "port": "1", "path": "/x"}), false, false},
		{"unknown kind", base("thoughts", nil), false, false},
		{"foreign parameter", base(KindPodState, map[string]string{"filter": "x"}), false, false},
		{"bad boolean", base(KindPcap, map[string]string{"payload": "yes"}), false, false},
		{"bad path", base(KindPprof, map[string]string{"port": "1", "path": "x; rm"}), false, false},
		{"bad workload", CaptureRequest{Cluster: "prod", Namespace: "payments", Workload: "api", Kind: KindLogs}, false, false},
	} {
		err := c.r.Validate()
		if (err == nil) != c.valid {
			t.Errorf("%s: valid=%v, got %v", c.name, c.valid, err)
		}
		if c.valid && c.r.Sensitive() != c.sensitive {
			t.Errorf("%s: sensitive=%v", c.name, !c.sensitive)
		}
	}
	r := base(KindPcap, nil)
	if r.Validate() != nil || r.DurationSeconds != 30 {
		t.Error("pcap duration does not default to 30 seconds")
	}
	// The short form with one kind becomes a recording.
	if r.Kind != "" || r.Params != nil || len(r.Recordings) != 1 || r.Recordings[0].Kind != KindPcap {
		t.Errorf("normalized request %+v", r)
	}
}

// A request holds several recordings with one time frame; it is sensitive
// if any of them is.
func TestSeveralRecordings(t *testing.T) {
	request := func(recordings ...Recording) CaptureRequest {
		return CaptureRequest{Cluster: "prod", Namespace: "payments", Workload: "Deployment/api", Recordings: recordings}
	}
	logs, packets := Recording{Kind: KindLogs}, Recording{Kind: KindPcap, Params: map[string]string{"filter": "tcp port 5432"}}
	r := request(logs, packets, Recording{Kind: KindPodState})
	if err := r.Validate(); err != nil || r.Sensitive() || r.DurationSeconds != 30 {
		t.Error("three ordinary recordings", err, r.Sensitive(), r.DurationSeconds)
	}
	if r.Recording(KindPcap).Params["filter"] != "tcp port 5432" || r.Recording(KindCoredump) != nil {
		t.Error("recording by kind")
	}
	r = request(logs, Recording{Kind: KindPodState})
	if err := r.Validate(); err != nil || r.DurationSeconds != 0 {
		t.Error("recordings without a time frame", err, r.DurationSeconds)
	}
	r = request(logs, packets, Recording{Kind: KindCoredump})
	if err := r.Validate(); err != nil || !r.Sensitive() {
		t.Error("a request with a core dump is sensitive as a whole", err)
	}
	// The short form adds to the list.
	r = request(logs)
	r.Kind, r.Params = KindPcap, map[string]string{"payload": "true"}
	if err := r.Validate(); err != nil || len(r.Recordings) != 2 || !r.Sensitive() {
		t.Error("short form next to recordings", err, r.Recordings)
	}
	for name, r := range map[string]CaptureRequest{
		"no recording":         request(),
		"a kind twice":         request(logs, packets, logs),
		"a bad recording":      request(logs, Recording{Kind: KindPprof}),
		"a foreign parameter":  request(Recording{Kind: KindLogs, Params: map[string]string{"filter": "x"}}),
		"twice via short form": {Cluster: "prod", Namespace: "payments", Workload: "Deployment/api", Kind: KindLogs, Recordings: []Recording{logs}},
	} {
		if r.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The same endpoint on two ports gets two file names.
func TestProfileTargets(t *testing.T) {
	names := func(list string) string {
		targets, err := Recording{Kind: KindPprof, Params: map[string]string{"endpoints": list}}.ProfileTargets()
		if err != nil {
			t.Fatal(err)
		}
		out := ""
		for _, target := range targets {
			out += target.File + " "
		}
		return out
	}
	if got := names("6060/go-cpu,6060/go-goroutines"); got != "cpu.pprof goroutines.txt " {
		t.Error(got)
	}
	if got := names("6060/go-cpu,6061/go-cpu"); got != "6060-cpu.pprof 6061-cpu.pprof " {
		t.Error(got)
	}
	// Every endpoint of the catalog has a distinct ID and file within its family.
	seen := map[string]bool{}
	for _, f := range ProfileFamilies {
		files := map[string]bool{}
		for _, e := range f.Endpoints {
			if seen[e.ID] || files[e.File] || e.File == "" || e.Timed != (len(e.Path) != len(strings.ReplaceAll(e.Path, "{seconds}", ""))) {
				t.Errorf("catalog entry %+v", e)
			}
			seen[e.ID], files[e.File] = true, true
		}
	}
}

func TestViewerOf(t *testing.T) {
	for name, want := range map[string]string{
		"api-1/capture.pcap": "pcap", "api-1/web.log": "log", "api-1/web.previous.log": "log", "api-1/web.strace": "strace",
		"api-1/pod.json": "kube", "api-1/events.json": "kube", "api-1/core.web": "core", "api-1/core.web.1234.analysis.json": "core", "api-1/heap.pprof": "pprof", "api-1/other.json": "",
		"api-1/goroutines.txt": "stacks", "api-1/8080-threaddump.txt": "stacks", "api-1/trace.out": "gotrace", "api-1/6060-trace.out": "gotrace", "api-1/profile.out": "", "api-1/heapdump.hprof": "heap", "api-1/heap.gcdump": "heap", "api-1/memory.dmp": "", "api-1/trace.nettrace": "pprof",
	} {
		if got := ViewerOf(name); got != want {
			t.Errorf("ViewerOf(%q) = %q, want %q", name, got, want)
		}
	}
}

// A sampled profile, of CPU time or of memory growth, runs for the time
// frame, takes no parameters and holds no memory contents or payload.
func TestSampledProfiles(t *testing.T) {
	for _, kind := range []string{KindCPU, KindMemory} {
		r := CaptureRequest{Cluster: "edge", Namespace: "shop", Workload: "Deployment/web", Kind: kind}
		if err := r.Validate(); err != nil || r.DurationSeconds != 30 || !r.Recordings[0].Timed(false) || r.Recordings[0].Sensitive() {
			t.Fatal(kind, err, r)
		}
		r = CaptureRequest{Cluster: "edge", Namespace: "shop", Workload: "Deployment/web", Kind: kind, Params: map[string]string{"container": "web"}}
		if err := r.Validate(); err == nil {
			t.Fatal(kind, "a parameter was accepted")
		}
	}
}

// A log condition needs a pattern that is a regular expression.
func TestLogCondition(t *testing.T) {
	for name, c := range map[string]Condition{
		"no pattern":                       {Kind: OnLog},
		"a broken pattern":                 {Kind: OnLog, Params: map[string]string{"pattern": "timeout("}},
		"a bad container":                  {Kind: OnLog, Params: map[string]string{"pattern": "timeout", "container": "Not A Name"}},
		"a parameter of another condition": {Kind: OnNotReady, Params: map[string]string{"pattern": "timeout"}},
	} {
		if err := c.Validate(); err == nil {
			t.Error(name, "was accepted")
		}
	}
	c := Condition{Kind: OnLog, Params: map[string]string{"pattern": `(?i)timeout|panic`, "container": "app"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
