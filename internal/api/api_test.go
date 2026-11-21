package api

import "testing"

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
		{"pprof", base(KindPprof, map[string]string{"port": "6060"}), true, false},
		{"pprof without port", base(KindPprof, nil), false, false},
		{"unknown kind", base("memory", nil), false, false},
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
