package processes

import (
	"asservat.local/asservat/internal/domain/artifact"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func processNativeFixture() (artifact.ProcessInventory, artifact.ContextExpectation, time.Time, time.Time) {
	n := time.Now().UTC()
	boot := "10000000-0000-4000-8000-000000000001"
	id := "containerd://" + strings.Repeat("a", 64)
	p := artifact.ProcessInventory{Format: artifact.ProcessFormat, PodUID: "pod", NodeUID: "node", NodeBootID: boot, Mode: artifact.ProcessAll, StartedAt: n, CompletedAt: n.Add(time.Millisecond), Origins: []artifact.ProcessOrigin{{RuntimeID: id, MainPID: 100, Outcome: "observed"}}, Processes: []artifact.ProcessRecord{{Identity: artifact.ProcessIdentity{PodUID: "pod", NodeBootID: boot, RuntimeID: id, HostPID: 100, StartTimeTicks: 1000, CgroupPath: "/pod/container", CgroupID: 10}, NamespacePID: 1, ObservedAt: n, Main: true, State: "S", UID: 1000, Threads: 1, ExecutablePath: "/app/server"}}, Gaps: []string{"socketOwnersUnsupported"}}
	e := artifact.ContextExpectation{PodUID: "pod", NativeType: artifact.ProcessesArtifact, DataClass: "metadata", ActionID: "a0123456789abcdef01234567", Registration: artifact.Registration{NativeLimit: artifact.ProcessNativeLimit}, Processes: &artifact.ProcessCapture{ActionID: "a0123456789abcdef01234567", Mode: artifact.ProcessAll, MaxNativeBytes: artifact.ProcessNativeLimit, TimeoutMillis: 5000, Composition: []byte(`{}`)}}
	return p, e, n, n.Add(time.Millisecond)
}

func TestProcessNativeStrictEOFAndSource(t *testing.T) {
	p, e, from, until := processNativeFixture()
	raw, _ := json.Marshal(p)
	c, err := NewProcessCheck(e, from, until)
	if err != nil || c.Write(raw) != nil || c.Close() != nil {
		t.Fatal("valid full native refused", err)
	}
	for name, body := range map[string][]byte{"tail": append(append([]byte(nil), raw...), []byte(`{}`)...), "duplicate": []byte(strings.Replace(string(raw), `"format":`, `"format":"other","format":`, 1)), "unknown": []byte(strings.Replace(string(raw), `"format":`, `"argv":"private","format":`, 1)), "invalid UTF8": []byte(strings.Replace(string(raw), "/app/server", string([]byte{'/', 255}), 1)), "wrongPod": []byte(strings.ReplaceAll(string(raw), `"pod"`, `"other"`))} {
		t.Run(name, func(t *testing.T) {
			c, err := NewProcessCheck(e, from, until)
			if err != nil {
				t.Fatal(err)
			}
			if c.Write(body) == nil && c.Close() == nil {
				t.Fatal("invalid or foreign native accepted")
			}
		})
	}
}

func TestProcessNativeMaximumRowsAndPathsStayBounded(t *testing.T) {
	p, _, _, _ := processNativeFixture()
	for n := 1; n < artifact.ProcessMaxRecords; n++ {
		r := p.Processes[0]
		r.Main = false
		r.Identity.HostPID += uint32(n)
		r.ExecutablePath = "/" + strings.Repeat("x", 4095)
		p.Processes = append(p.Processes, r)
	}
	raw, _ := json.Marshal(p)
	if !p.Valid() || int64(len(raw)) > artifact.ProcessNativeLimit {
		t.Fatal("maximum metadata shape exceeds original cap", len(raw))
	}
	if _, e := DecodeProcesses(raw); e != nil {
		t.Fatal(e)
	}
	p.Processes = append(p.Processes, p.Processes[len(p.Processes)-1])
	raw, _ = json.Marshal(p)
	if _, e := DecodeProcesses(raw); e == nil {
		t.Fatal("record limit exceeded")
	}
}
