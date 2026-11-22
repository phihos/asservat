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
	cluster := "inspect" + hex.EncodeToString([]byte(time.Now().Format("150405.000")))[:10]
	joined := hub.Cluster{Name: cluster, Token: "join-token-of-the-inspected-cluster-0123456789"}
	h, err := hub.New(hub.Config{Store: store, Blobs: hub.DirBlobs(t.TempDir()), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour, AdminGroups: []string{"admins"}, Clusters: []hub.Cluster{joined},
		Users: []hub.StaticUser{{Name: "alice", Token: "alice-token"}, {Name: "mallory", Token: "mallory-token"}, {Name: "root", Token: "root-token", Groups: []string{"admins"}}}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h.Handler())
	t.Cleanup(server.Close) // after the agent's stream, which is closed by a later cleanup
	f := fixture{t, server.URL}

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
			// The agent could not record the second pod.
			return api.Reply{Skipped: []string{"api-2"}, Flows: []api.Flow{
				{Direction: api.FlowIn, Protocol: "tcp", Port: 8080, Packets: 40, Bytes: 9000, PeerList: []string{"10.0.1.7", "10.0.1.8"}},
				{Direction: api.FlowIn, Protocol: "tcp", Port: 8080, Packets: 10, Bytes: 1000, PeerList: []string{"10.0.1.8", "10.0.1.9"}},
				{Direction: api.FlowOut, Protocol: "tcp", Port: 5432, Peer: "10.96.0.12", Packets: 30, Bytes: 5000},
				{Direction: api.FlowOut, Protocol: "tcp", Port: 5432, Peer: "10.96.0.12", Packets: 30, Bytes: 5000},
				{Direction: api.FlowOut, Protocol: "udp", Port: 53, Peer: "10.96.0.10", Packets: 4, Bytes: 400},
				{Direction: api.FlowLocal, Protocol: "tcp", Port: 9000, Packets: 2, Bytes: 120},
			}}
		case "profiles":
			return api.Reply{Ports: []int{6060, 8080}, Profiles: []api.ProfileTarget{
				{Port: 6060, ProfileEndpoint: api.ProfileEndpoint{ID: "go-cpu"}}, {Port: 6060, ProfileEndpoint: api.ProfileEndpoint{ID: "go-heap"}},
				{Port: 8080, ProfileEndpoint: api.ProfileEndpoint{ID: "java-heapdump"}}, {Port: 8080, ProfileEndpoint: api.ProfileEndpoint{ID: "made-up"}}}}
		case "peers":
			names := map[string]string{"10.96.0.12": "Service db"}
			if q.All {
				names["10.96.0.10"] = "Service kube-system/kube-dns"
			}
			return api.Reply{Names: names}
		}
		return api.Reply{Error: "unexpected query " + q.Op}
	}
	scriptedAgent(t, f, joined.Token, "node-a", func(q api.Query) api.Reply {
		asked <- q
		return answer(q)
	})
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
	if code != 200 || in.Seconds != 3 || len(in.Flows) != 4 || strings.Join(in.Pods, ",") != "api-1" || strings.Join(in.NotInspected, ",") != "api-2,api-3" {
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
	// Profile endpoints: what the agent found, described by the catalog.
	if code, _ := get("mallory-token", "POST", "/profiles?workload=Deployment/api"); code != 403 {
		t.Fatal("profile endpoints looked for without the exec right", code)
	}
	code, in = get("alice-token", "POST", "/profiles?workload=Deployment/api")
	if code != 200 || len(in.Profiles) != 3 || len(in.Ports) != 2 {
		t.Fatalf("profiles %d %+v", code, in)
	}
	if p := in.Profiles[0]; p.Port != 6060 || p.ID != "go-cpu" || p.Name != "CPU profile" || !p.Timed || p.Sensitive || p.File != "cpu.pprof" || !strings.HasPrefix(p.Runtime, "Go") {
		t.Fatalf("profile endpoint %+v", p)
	}
	if p := in.Profiles[2]; p.Port != 8080 || p.ID != "java-heapdump" || !p.Sensitive {
		t.Fatalf("profile endpoint %+v", p)
	}
	_, b := f.call("root-token", "GET", "/api/audit?limit=20", nil)
	for _, action := range []string{"traffic.sample", "profile.discover"} {
		if !strings.Contains(string(b), `"`+action+`"`) {
			t.Error("the audit log lacks", action)
		}
	}
}

// scriptedAgent connects as a node's agent, answers the hub's queries with
// answer and returns the other commands that the hub sends.
func scriptedAgent(t *testing.T, f fixture, token, node string, answer func(api.Query) api.Reply) <-chan api.Command {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), "GET", f.url+"/agent/stream?node="+node, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.Body.Close() })
	commands := make(chan api.Command, 16)
	go func() {
		lines := bufio.NewReader(stream.Body)
		for {
			line, err := lines.ReadBytes('\n')
			if err != nil {
				return
			}
			var c api.Command
			if json.Unmarshal(line, &c) != nil {
				continue
			}
			if c.Type != "query" {
				commands <- c
				continue
			}
			body, _ := json.Marshal(answer(*c.Query))
			reply, _ := http.NewRequest("POST", f.url+"/agent/replies/"+c.ID, bytes.NewReader(body))
			reply.Header.Set("Authorization", "Bearer "+token)
			if res, err := http.DefaultClient.Do(reply); err == nil {
				res.Body.Close()
			}
		}
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, b := f.call("root-token", "GET", "/api/clusters", nil); strings.Contains(string(b), `"`+node+`"`) {
			return commands
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent did not connect")
		}
	}
}

// With self-approval allowed, an administrator's sensitive request starts at
// once. A running capture shows the progress of its recordings and how much
// of the time frame is left, and can be stopped with what it has.
func TestOwnApprovalProgressAndStop(t *testing.T) {
	dsn := os.Getenv("ASSERVAT_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSERVAT_TEST_DSN is not set")
	}
	store, err := hub.OpenStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cluster := "own" + hex.EncodeToString([]byte(time.Now().Format("150405.000")))[:10]
	joined := hub.Cluster{Name: cluster, Token: "join-token-of-the-administrator's-cluster-0123456789"}
	h, err := hub.New(hub.Config{Store: store, Blobs: hub.DirBlobs(t.TempDir()), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour, AdminGroups: []string{"admins"}, AllowSelfApproval: true, Clusters: []hub.Cluster{joined},
		Users: []hub.StaticUser{{Name: "alice", Token: "alice-token"}, {Name: "mallory", Token: "mallory-token"}, {Name: "root", Token: "root-token", Groups: []string{"admins"}}}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h.Handler())
	t.Cleanup(server.Close) // after the agent's stream, which is closed by a later cleanup
	f := fixture{t, server.URL}
	commands := scriptedAgent(t, f, joined.Token, "node-a", func(q api.Query) api.Reply {
		return api.Reply{Allowed: q.User == "alice", Pods: []api.Pod{{Name: "api-1", Node: "node-a"}}, Selector: "app=api"}
	})

	for token, own := range map[string]bool{"root-token": true, "alice-token": false} {
		if _, b := f.call(token, "GET", "/api/me", nil); strings.Contains(string(b), `"selfApproval":true`) != own {
			t.Fatal("self approval of", token, string(b))
		}
	}
	sensitive := api.CaptureRequest{Cluster: cluster, Namespace: "payments", Workload: "Deployment/api", DurationSeconds: 60,
		Recordings: []api.Recording{{Kind: api.KindCoredump}, {Kind: api.KindPcap}, {Kind: api.KindPodState}}}
	var mine, theirs api.Capture
	code, b := f.call("root-token", "POST", "/api/captures", sensitive)
	json.Unmarshal(b, &mine)
	if code != 201 || mine.State != api.StateQueued || mine.Approver != "root" || !mine.Sensitive {
		t.Fatal("an administrator's own sensitive request", code, mine.State, mine.Approver)
	}
	code, b = f.call("alice-token", "POST", "/api/captures", sensitive)
	json.Unmarshal(b, &theirs)
	if code != 201 || theirs.State != api.StatePendingApproval || theirs.Approver != "" {
		t.Fatal("a user's sensitive request", code, theirs.State)
	}
	// Captures are numbered as they are requested; people call them by that.
	if first, second := f.capture("root-token", mine.ID).Number, f.capture("alice-token", theirs.ID).Number; first < 1 || second <= first {
		t.Fatal("numbers of two captures", first, second)
	}
	var watch api.Watch
	code, b = f.call("root-token", "POST", "/api/watches", sensitive)
	json.Unmarshal(b, &watch)
	if code != 201 || watch.Approver != "root" {
		t.Fatal("an administrator's own sensitive watch", code, watch)
	}
	defer f.call("root-token", "DELETE", "/api/watches/"+watch.ID, nil)

	// The task reaches the agent at once; its reports become the progress.
	next := func(kind string) api.Command {
		t.Helper()
		for {
			select {
			case c := <-commands:
				if c.Type == kind {
					return c
				}
			case <-time.After(10 * time.Second):
				t.Fatal("no command", kind)
			}
		}
	}
	if c := next("task"); c.ID != mine.ID {
		t.Fatal("task", c)
	}
	report := func(state string, recordings ...api.RecordingStatus) int {
		t.Helper()
		body, _ := json.Marshal(api.TaskStatus{Pod: "api-1", State: state, Recordings: recordings})
		req, _ := http.NewRequest("POST", server.URL+"/agent/captures/"+mine.ID+"/status", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+joined.Token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code, _ := f.call("root-token", "POST", "/api/captures/"+mine.ID+"/stop", nil); code != 409 {
		t.Fatal("stopped a capture that does not run yet", code)
	}
	waiting := []api.RecordingStatus{{Kind: api.KindCoredump, State: api.StateRunning}, {Kind: api.KindPcap, State: api.StateRunning}, {Kind: api.KindPodState, State: api.StateRunning}}
	if report(api.StateRunning, waiting...) != 200 {
		t.Fatal("progress report")
	}
	waiting[2].State = api.StateCompleted
	waiting[0].State, waiting[0].Message = api.StateFailed, "no such process"
	if report(api.StateRunning, waiting...) != 200 {
		t.Fatal("progress report")
	}
	got := f.capture("root-token", mine.ID)
	recs := got.Tasks[0].Recordings
	if got.State != api.StateRunning || len(recs) != 3 || recs[0].State != api.StateFailed || recs[0].Message != "no such process" || recs[1].State != api.StateRunning || recs[1].StartedAt == nil || recs[2].State != api.StateCompleted {
		t.Fatalf("progress %+v", recs)
	}
	// The packet capture has just begun its 60 seconds.
	if got.RemainingSeconds == nil || *got.RemainingSeconds < 55 || *got.RemainingSeconds > 60 {
		t.Fatal("remaining", got.RemainingSeconds)
	}
	if code, _ := f.call("mallory-token", "POST", "/api/captures/"+mine.ID+"/stop", nil); code != 404 {
		t.Fatal("another user stopped the capture", code)
	}
	if code, _ := f.call("root-token", "POST", "/api/captures/"+mine.ID+"/stop", nil); code != 200 {
		t.Fatal("stop", code)
	}
	if c := next("stop"); c.ID != mine.ID {
		t.Fatal("the agent was told to stop", c)
	}
	// An agent that connects now learns with its task that the capture was stopped.
	if open, err := store.OpenTasks(t.Context(), cluster, "node-a"); err != nil || len(open) != 1 || !open[0].Task.Stopped || !open[0].Task.Started {
		t.Fatal("open task of a stopped capture", open, err)
	}
	if got := f.capture("root-token", mine.ID); got.StoppedAt == nil {
		t.Fatal("the capture does not show that it was stopped")
	}
	// The agent ends the packet capture and completes the task: the capture
	// is complete with what it has, and nothing remains of the time frame.
	waiting[1].State, waiting[1].Message = api.StateCompleted, "stopped early"
	if report(api.StateCompleted, waiting...) != 200 {
		t.Fatal("final report")
	}
	got = f.capture("root-token", mine.ID)
	if got.State != api.StateCompleted || got.RemainingSeconds != nil || got.Tasks[0].Recordings[1].Message != "stopped early" {
		t.Fatalf("stopped capture %+v", got)
	}
	// It is complete although the core dump failed, and says so at first sight.
	if got.Message != "1 of 3 recordings failed" {
		t.Fatalf("a completed capture with a failed recording says %q", got.Message)
	}
	_, b = f.call("root-token", "GET", "/api/audit?limit=30", nil)
	for _, action := range []string{"capture.approve", "capture.stop", "watch.approve"} {
		if !strings.Contains(string(b), `"`+action+`"`) {
			t.Error("the audit log lacks", action)
		}
	}
}
