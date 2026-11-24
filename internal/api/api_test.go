package api

import (
	"strings"
	"testing"
	"time"
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
	// A JVM's own diagnostics are named with their container, which may
	// read like a port. Their files differ from those of Actuator's
	// endpoints, and of two containers from each other.
	if got := names("8080/java-threads,app/jvm-threads,app/jvm-heapdump"); got != "threaddump.txt jvm-threaddump.txt jvm-heapdump.hprof " {
		t.Error(got)
	}
	if got := names("8080/jvm-recording,app/jvm-recording,8080/go-cpu"); got != "8080-jvm-recording.jfr app-jvm-recording.jfr cpu.pprof " {
		t.Error(got)
	}
	for list, want := range map[string]string{
		"app/go-cpu": "unknown", "8080/jvm-load": "unknown", "jvm-threads": "unknown", "App/jvm-threads": "unknown", "/jvm-threads": "unknown", "app/jvm-threads,app/jvm-threads": "twice",
	} {
		if _, err := (Recording{Kind: KindPprof, Params: map[string]string{"endpoints": list}}).ProfileTargets(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("endpoints %q: %v", list, err)
		}
	}
	// Of a JVM's diagnostics only the heap dump holds memory, and only the
	// flight recording runs for the time frame.
	for id, want := range map[string][2]bool{"jvm-threads": {false, false}, "jvm-histogram": {false, false}, "jvm-heapdump": {true, false}, "jvm-recording": {false, true}} {
		rec := Recording{Kind: KindPprof, Params: map[string]string{"endpoints": "app/" + id}}
		if rec.Sensitive() != want[0] || rec.Timed(false) != want[1] {
			t.Errorf("%s: sensitive %v, timed %v", id, rec.Sensitive(), rec.Timed(false))
		}
	}
	// Every endpoint of the catalog has a distinct ID and file within its family.
	seen := map[string]bool{}
	for _, e := range JVMDiagnostics {
		if seen[e.ID] || !e.Attach || e.Path != "" || e.File == "" {
			t.Errorf("catalog entry %+v", e)
		}
		seen[e.ID] = true
	}
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

// A capture's files are shown under the recording that made them.
func TestRecordingOf(t *testing.T) {
	for name, want := range map[string]string{
		"api-1/capture.pcap": KindPcap, "api-1/pod.json": KindPodState, "api-1/events.json": KindPodState, "api-1/app.log": KindLogs, "api-1/app.previous.log": KindLogs,
		"api-1/app.strace": KindStrace, "api-1/sampled-cpu.pprof": KindCPU, "api-1/sampled-memory.pprof": KindMemory,
		"api-1/core.app": KindCoredump, "api-1/core.app.analysis.json": KindCoredump, "api-1/core.app.files.tar": KindCoredump,
		"api-1/cpu.pprof": "", "api-1/heap.pprof": "", "api-1/goroutines.txt": "", "api-1/heapdump.hprof": "",
	} {
		if got := RecordingOf(name); got != want {
			t.Errorf("RecordingOf(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestViewerOf(t *testing.T) {
	for name, want := range map[string]string{
		"api-1/capture.pcap": "pcap", "api-1/web.log": "log", "api-1/web.previous.log": "log", "api-1/web.strace": "strace",
		"api-1/pod.json": "kube", "api-1/events.json": "kube", "api-1/core.web": "core", "api-1/core.web.1234.analysis.json": "core", "api-1/heap.pprof": "pprof", "api-1/other.json": "",
		"api-1/goroutines.txt": "stacks", "api-1/8080-threaddump.txt": "stacks", "api-1/jvm-threaddump.txt": "stacks", "api-1/app-jvm-heapdump.hprof": "heap", "api-1/jvm-recording.jfr": "", "api-1/jvm-histogram.txt": "log", "api-1/trace.out": "gotrace", "api-1/6060-trace.out": "gotrace", "api-1/profile.out": "", "api-1/heapdump.hprof": "heap", "api-1/heap.gcdump": "heap", "api-1/memory.dmp": "", "api-1/trace.nettrace": "pprof",
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

// The threshold of a usage condition is a share, a size or a number of CPUs.
func TestParseAbove(t *testing.T) {
	for _, c := range []struct {
		kind, in string
		want     Above
	}{
		{OnMemory, "80%", Above{80, true}}, {OnMemory, "500Mi", Above{500 << 20, false}}, {OnMemory, "2G", Above{2e9, false}}, {OnMemory, "1048576", Above{1 << 20, false}},
		{OnCPU, "1.5", Above{1.5, false}}, {OnCPU, "1500m", Above{1.5, false}}, {OnCPU, "90%", Above{90, true}}, {OnThrottle, "25%", Above{25, true}},
	} {
		if got, err := ParseAbove(c.kind, c.in); err != nil || got != c.want {
			t.Errorf("ParseAbove(%s, %q) = %v, %v", c.kind, c.in, got, err)
		}
	}
	for _, c := range [][2]string{{OnMemory, "much"}, {OnMemory, "-5Mi"}, {OnCPU, "2 cores"}, {OnThrottle, "3"}, {OnCPU, "NaN"}, {OnMemory, ""}} {
		if _, err := ParseAbove(c[0], c[1]); err == nil {
			t.Errorf("ParseAbove(%s, %q) was accepted", c[0], c[1])
		}
	}
	for name, c := range map[string]Condition{
		"no threshold": {Kind: OnMemory}, "negative seconds": {Kind: OnCPU, Params: map[string]string{"above": "1", "seconds": "-1"}},
		"a pattern": {Kind: OnMemory, Params: map[string]string{"above": "80%", "pattern": "x"}},
	} {
		if err := c.Validate(); err == nil {
			t.Error(name, "was accepted")
		}
	}
	for _, c := range []struct {
		kind, in string
		want     Above
	}{
		{OnPressure, "20%", Above{20, true}}, {OnGrowth, "100Mi", Above{100 << 20, false}}, {OnThreads, "500", Above{500, false}},
		{OnFiles, "1000", Above{1000, false}}, {OnRetransmits, "10", Above{10, false}}, {OnTCPFailures, "0.5", Above{0.5, false}},
	} {
		if got, err := ParseAbove(c.kind, c.in); err != nil || got != c.want {
			t.Errorf("ParseAbove(%s, %q) = %v, %v", c.kind, c.in, got, err)
		}
	}
	// A time comes once, or again after every so many seconds.
	at := time.Date(2026, 12, 1, 3, 0, 0, 0, time.UTC)
	once := Condition{Kind: OnTime, Params: map[string]string{"at": "2026-12-01T03:00:00Z"}}
	hourly := Condition{Kind: OnTime, Params: map[string]string{"at": "2026-12-01T03:00:00Z", "every": "3600"}}
	for _, c := range []struct {
		when       Condition
		now        time.Time
		last, next time.Time
	}{
		{once, at.Add(-time.Minute), time.Time{}, at}, {once, at, at, time.Time{}}, {once, at.Add(time.Hour), at, time.Time{}},
		{hourly, at.Add(-time.Minute), time.Time{}, at}, {hourly, at.Add(59 * time.Minute), at, at.Add(time.Hour)},
		{hourly, at.Add(150 * time.Minute), at.Add(2 * time.Hour), at.Add(3 * time.Hour)},
	} {
		if last, next := c.when.Due(c.now); !last.Equal(c.last) || !next.Equal(c.next) {
			t.Errorf("Due(%v) of %v = %v, %v", c.now, c.when.Params, last, next)
		}
	}
	for name, c := range map[string]Condition{
		"pressure as a number":     {Kind: OnPressure, Params: map[string]string{"above": "3"}},
		"pressure of the network":  {Kind: OnPressure, Params: map[string]string{"above": "20%", "of": "network"}},
		"threads as a share":       {Kind: OnThreads, Params: map[string]string{"above": "80%"}},
		"growth without a time":    {Kind: OnGrowth, Params: map[string]string{"above": "100Mi"}},
		"of for another condition": {Kind: OnMemory, Params: map[string]string{"above": "80%", "of": "io"}},
	} {
		if err := c.Validate(); err == nil {
			t.Error(name, "was accepted")
		}
	}
	ok := Condition{Kind: OnThrottle, Params: map[string]string{"above": "25%", "seconds": "30", "container": "app"}}
	if err := ok.Validate(); err != nil || !ok.Usage() {
		t.Fatal(err)
	}
}

// In a watch, packets and the sampled CPU profile are kept running so that
// they reach back; memory growth only on request, because it costs the
// node while the watch waits. "before" overrides either.
func TestRecordingsThatReachBack(t *testing.T) {
	for _, c := range []struct {
		rec  Recording
		want bool
	}{
		{Recording{Kind: KindPcap}, true}, {Recording{Kind: KindCPU}, true}, {Recording{Kind: KindMemory}, false}, {Recording{Kind: KindLogs}, false},
		{Recording{Kind: KindStrace}, false}, {Recording{Kind: KindStrace, Params: map[string]string{"before": "true"}}, true},
		{Recording{Kind: KindCPU, Params: map[string]string{"before": "false"}}, false}, {Recording{Kind: KindMemory, Params: map[string]string{"before": "true"}}, true},
	} {
		if got := c.rec.Buffers(); got != c.want {
			t.Errorf("%v reaches back: %v", c.rec, got)
		}
	}
	bad := CaptureRequest{Cluster: "edge", Namespace: "shop", Workload: "Deployment/web", Recordings: []Recording{{Kind: KindLogs, Params: map[string]string{"before": "true"}}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("logs took before")
	}
	bad.Recordings = []Recording{{Kind: KindCPU, Params: map[string]string{"before": "yes"}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("before took a value that is neither true nor false")
	}
	w := Watch{CaptureRequest: CaptureRequest{DurationSeconds: 30}}
	if w.Before() != 30*time.Second {
		t.Fatal("without beforeSeconds a watch reaches back its time frame", w.Before())
	}
	if w.BeforeSeconds = 120; w.Before() != 2*time.Minute {
		t.Fatal(w.Before())
	}
}
