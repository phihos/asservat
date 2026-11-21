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
}
