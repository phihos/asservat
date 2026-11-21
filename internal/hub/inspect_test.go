package hub_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/api"
	"asservat.local/asservat/internal/hub"
)

// The hub merges what the node agents see into choices for the user: the
// programs of a workload and its connections, each with a packet filter.
func TestInspection(t *testing.T) {
	dsn := os.Getenv("ASSERVAT_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSERVAT_TEST_DSN is not set")
	}
	store, err := hub.OpenStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h, err := hub.New(hub.Config{Store: store, Blobs: hub.DirBlobs(t.TempDir()), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour, AdminGroups: []string{"admins"},
		Users: []hub.StaticUser{{Name: "alice", Token: "alice-token"}, {Name: "mallory", Token: "mallory-token"}, {Name: "root", Token: "root-token", Groups: []string{"admins"}}}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h.Handler())
	defer server.Close()
	f := fixture{t, server.URL}
	cluster := "inspect" + hex.EncodeToString([]byte(time.Now().Format("150405.000")))[:10]
	_, b := f.call("root-token", "POST", "/api/clusters", map[string]string{"name": cluster})
	var joined struct{ Token string }
	json.Unmarshal(b, &joined)
	defer f.call("root-token", "DELETE", "/api/clusters/"+cluster, nil)

	// A scripted agent on node-a. The workload's third pod runs on node-b,
	// which has no agent.
	asked := make(chan api.Query, 16)
	answer := func(q api.Query) api.Reply {
		switch q.Op {
		case "review":
			return api.Reply{Allowed: q.User == "alice"}
		case "resolve":
			return api.Reply{Pods: []api.Pod{{Name: "api-1", Node: "node-a"}, {Name: "api-2", Node: "node-a"}, {Name: "api-3", Node: "node-b"}}}
		case "processes":
			python := api.Process{Container: "app", Executable: "/usr/local/bin/python3.12", Name: "gunicorn"}
			out := []api.Process{}
			for _, pod := range q.Pods {
				master, worker, big, proxy := python, python, python, api.Process{Pod: pod, Container: "proxy", Executable: "/usr/sbin/nginx", Name: "nginx", Main: true, ResidentBytes: 5 << 20}
				master.Pod, master.Main, master.ResidentBytes = pod, true, 30<<20
				worker.Pod, worker.ResidentBytes = pod, 200<<20
				big.Pod, big.ResidentBytes = pod, 210<<20
				out = append(out, master, worker, big, proxy, api.Process{Pod: pod, Container: "app", Executable: "/bin/sleep", Name: "sleep", ResidentBytes: 1 << 20})
			}
			return api.Reply{Processes: out}
		case "traffic":
			return api.Reply{Flows: []api.Flow{
				{Direction: api.FlowIn, Protocol: "tcp", Port: 8080, Packets: 40, Bytes: 9000, PeerList: []string{"10.0.1.7", "10.0.1.8"}},
				{Direction: api.FlowIn, Protocol: "tcp", Port: 8080, Packets: 10, Bytes: 1000, PeerList: []string{"10.0.1.8", "10.0.1.9"}},
				{Direction: api.FlowOut, Protocol: "tcp", Port: 5432, Peer: "10.96.0.12", Packets: 30, Bytes: 5000},
				{Direction: api.FlowOut, Protocol: "tcp", Port: 5432, Peer: "10.96.0.12", Packets: 30, Bytes: 5000},
				{Direction: api.FlowOut, Protocol: "udp", Port: 53, Peer: "10.96.0.10", Packets: 4, Bytes: 400},
				{Direction: api.FlowLocal, Protocol: "tcp", Port: 9000, Packets: 2, Bytes: 120},
			}}
		case "peers":
			names := map[string]string{"10.96.0.12": "Service db"}
			if q.All {
				names["10.96.0.10"] = "Service kube-system/kube-dns"
			}
			return api.Reply{Names: names}
		}
		return api.Reply{Error: "unexpected query " + q.Op}
	}
	req, _ := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/agent/stream?node=node-a", nil)
	req.Header.Set("Authorization", "Bearer "+joined.Token)
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	go func() {
		lines := bufio.NewReader(stream.Body)
		for {
			line, err := lines.ReadBytes('\n')
			if err != nil {
				return
			}
			var c api.Command
			if json.Unmarshal(line, &c) != nil || c.Type != "query" {
				continue
			}
			asked <- *c.Query
			body, _ := json.Marshal(answer(*c.Query))
			reply, _ := http.NewRequest("POST", server.URL+"/agent/replies/"+c.ID, bytes.NewReader(body))
			reply.Header.Set("Authorization", "Bearer "+joined.Token)
			if res, err := http.DefaultClient.Do(reply); err == nil {
				res.Body.Close()
			}
		}
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, b := f.call("alice-token", "GET", "/api/clusters", nil); strings.Contains(string(b), `"node-a"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent did not connect")
		}
	}
	base := "/api/clusters/" + cluster + "/namespaces/payments"
	get := func(token, method, path string) (int, api.Inspection) {
		t.Helper()
		code, b := f.call(token, method, base+path, nil)
		var in api.Inspection
		json.Unmarshal(b, &in)
		return code, in
	}

	if code, _ := get("mallory-token", "GET", "/processes?workload=Deployment/api"); code != 403 {
		t.Fatal("processes listed without the exec right", code)
	}
	code, in := get("alice-token", "GET", "/processes?workload=Deployment/api")
	if code != 200 || strings.Join(in.Pods, ",") != "api-1,api-2" || strings.Join(in.NotInspected, ",") != "api-3" || len(in.Processes) != 3 {
		t.Fatalf("processes %d %+v", code, in)
	}
	// Per container the main program first; counts and sizes over all pods.
	want := []api.ProcessChoice{
		{Container: "app", Executable: "/usr/local/bin/python3.12", Name: "gunicorn", Main: true, Processes: 6, Pods: 2, LargestResidentBytes: 210 << 20},
		{Container: "app", Executable: "/bin/sleep", Name: "sleep", Processes: 2, Pods: 2, LargestResidentBytes: 1 << 20},
		{Container: "proxy", Executable: "/usr/sbin/nginx", Name: "nginx", Main: true, Processes: 2, Pods: 2, LargestResidentBytes: 5 << 20},
	}
	for i := range want {
		if in.Processes[i] != want[i] {
			t.Fatalf("process choice %d: %+v", i, in.Processes[i])
		}
	}

	if code, _ := get("mallory-token", "POST", "/traffic?workload=Deployment/api"); code != 403 {
		t.Fatal("traffic sampled without the exec right", code)
	}
	if code, _ := get("alice-token", "POST", "/traffic?workload=Deployment/api&seconds=600"); code != 400 {
		t.Fatal("a sample longer than a request", code)
	}
	for len(asked) > 0 {
		<-asked
	}
	code, in = get("alice-token", "POST", "/traffic?workload=Deployment/api&seconds=3")
	if code != 200 || in.Seconds != 3 || len(in.Flows) != 4 {
		t.Fatalf("traffic %d %+v", code, in)
	}
	for q := range asked {
		if q.Op == "traffic" {
			if q.Seconds != 3 || strings.Join(q.Pods, ",") != "api-1,api-2" || q.Namespace != "payments" {
				t.Fatalf("traffic query %+v", q)
			}
			break
		}
	}
	type row struct {
		label, filter string
		packets, pods int
	}
	rows := []row{}
	for _, f := range in.Flows {
		rows = append(rows, row{f.Label, f.Filter, f.Packets, f.Pods})
	}
	// Most bytes first. The user may know the Service of their namespace,
	// not the one of another.
	wantRows := []row{
		{"Incoming on TCP port 8080 from 3 peers", "tcp port 8080", 50, 2},
		{"To Service db (10.96.0.12) on TCP port 5432 (usually PostgreSQL)", "host 10.96.0.12 and tcp port 5432", 60, 2},
		{"To 10.96.0.10 on UDP port 53 (usually DNS)", "host 10.96.0.10 and udp port 53", 4, 1},
		{"Inside the pod on TCP port 9000", "tcp port 9000 and (net 127.0.0.0/8 or host ::1)", 2, 1},
	}
	for i := range wantRows {
		if rows[i] != wantRows[i] {
			t.Fatalf("flow %d: %+v", i, rows[i])
		}
	}
	// An administrator learns the names of the whole cluster.
	_, in = get("root-token", "POST", "/traffic?workload=Deployment/api")
	if in.Seconds != 5 || in.Flows[2].Label != "To Service kube-system/kube-dns (10.96.0.10) on UDP port 53 (usually DNS)" {
		t.Fatalf("an administrator's sample %+v", in.Flows)
	}
	if _, b := f.call("root-token", "GET", "/api/audit?limit=20", nil); !strings.Contains(string(b), `"traffic.sample"`) {
		t.Error("the audit log lacks the traffic sample")
	}
}
