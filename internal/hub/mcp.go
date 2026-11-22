package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"asservat.local/asservat/internal/api"
)

// The MCP endpoint (Model Context Protocol, streamable HTTP without
// server-initiated messages) lets an AI agent work with the caller's
// permissions: every tool runs the same checks as the REST API.

type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	call        func(ctx context.Context, h *Hub, u User, args json.RawMessage) (any, error)
}

func object(properties string, required ...string) json.RawMessage {
	r, _ := json.Marshal(required)
	if required == nil {
		r = []byte("[]")
	}
	return json.RawMessage(`{"type":"object","properties":{` + properties + `},"required":` + string(r) + `}`)
}

const captureProperties = `"cluster":{"type":"string"},"namespace":{"type":"string"},
"workload":{"type":"string","description":"Deployment/name, StatefulSet/name, DaemonSet/name or Pod/name"},
"pods":{"type":"array","items":{"type":"string"},"description":"Restrict to these pods; default all pods of the workload"},
"recordings":{"type":"array","description":"What to record, at most one of each kind. All recordings start together on the same pods, share durationSeconds and, if any needs approval, one approval.","items":{"type":"object","properties":{
 "kind":{"enum":["pod-state","logs","pcap","coredump","strace","pprof","cpu","memory"]},
 "params":{"type":"object","additionalProperties":{"type":"string"},"description":"logs: container, previous, tailLines. pcap: filter (tcpdump syntax), payload (true needs approval). coredump: container, process. strace: container, process, strings (true needs approval). process is an executable from list_processes. pprof: endpoints, a comma-separated list of <port>/<endpoint> from find_profile_endpoints, fetched at once; or port and path for an endpoint the catalog does not know (needs approval). cpu: no parameters; a CPU profile of all processes of the pod, sampled from the node, for applications without a profile endpoint (Go, C, C++, Rust, Python, Java, Node.js, Ruby, PHP, Perl, .NET, Erlang); the file sampled-cpu.pprof is in pprof's format. memory: no parameters; which code makes the pod's memory grow during the time frame, from the stacks at its page faults, for the same runtimes; sampled-memory.pprof counts page faults and the bytes they bring in. It shows growth while it records, not what was allocated before; a core dump shows that."}},"required":["kind"]}},
"kind":{"enum":["pod-state","logs","pcap","coredump","strace","pprof","cpu","memory"],"description":"Short form for a single recording, with params"},
"params":{"type":"object","additionalProperties":{"type":"string"}},
"durationSeconds":{"type":"integer","description":"The time frame of pcap, strace, cpu, memory, pprof and followed logs; default 30"},
"reason":{"type":"string","description":"Shown to the approving administrator"}`

// mcpReadLimit bounds one read_artifact result so that it fits a model's
// context; a caller pages with offset.
const mcpReadLimit = 64 << 10

var mcpTools = []mcpTool{
	{Name: "list_clusters", Description: "List the clusters of this installation and the nodes whose agent is connected.", InputSchema: object(""),
		call: func(ctx context.Context, h *Hub, u User, _ json.RawMessage) (any, error) {
			out := map[string][]string{}
			for _, n := range h.clusterNames() {
				out[n] = h.agents.nodes(n)
			}
			return out, nil
		}},
	{Name: "list_namespaces", Description: "List the namespaces of a cluster whose workloads you may capture.", InputSchema: object(`"cluster":{"type":"string"}`, "cluster"),
		call: func(ctx context.Context, h *Hub, u User, args json.RawMessage) (any, error) {
			var in struct{ Cluster string }
			if err := json.Unmarshal(args, &in); err != nil {
				return nil, err
			}
			return h.namespaces(ctx, u, in.Cluster)
		}},
	{Name: "list_workloads", Description: "List the workloads (Kind/name) of a namespace you may capture.", InputSchema: object(`"cluster":{"type":"string"},"namespace":{"type":"string"}`, "cluster", "namespace"),
		call: func(ctx context.Context, h *Hub, u User, args json.RawMessage) (any, error) {
			var in struct{ Cluster, Namespace string }
			if err := json.Unmarshal(args, &in); err != nil {
				return nil, err
			}
			if err := h.allowed(ctx, u, in.Cluster, in.Namespace); err != nil {
				return nil, err
			}
			r, err := h.agents.query(ctx, in.Cluster, "", api.Query{Op: "workloads", Namespace: in.Namespace})
			return r.Workloads, err
		}},
	{Name: "list_processes", Description: "List the programs that run in the pods of a workload, per container, with their process counts and memory. Use an executable as the process parameter of a coredump or strace capture to target that program instead of the container's main process.",
		InputSchema: object(`"cluster":{"type":"string"},"namespace":{"type":"string"},"workload":{"type":"string"}`, "cluster", "namespace", "workload"),
		call: func(ctx context.Context, h *Hub, u User, args json.RawMessage) (any, error) {
			var in struct{ Cluster, Namespace, Workload string }
			if err := json.Unmarshal(args, &in); err != nil {
				return nil, err
			}
			return h.Processes(ctx, u, in.Cluster, in.Namespace, in.Workload)
		}},
	{Name: "sample_traffic", Description: "Look at the packet headers of a workload's pods for a few seconds and list their connections: incoming ports, outgoing peers (named if they are Services or pods you may know) and traffic inside the pod. Every flow carries a filter for the filter parameter of a pcap capture or watch; join several with \"or\". An empty list means no packets in that time, not that the workload has no connections.",
		InputSchema: object(`"cluster":{"type":"string"},"namespace":{"type":"string"},"workload":{"type":"string"},"seconds":{"type":"integer","description":"1 to 30; default 5"}`, "cluster", "namespace", "workload"),
		call: func(ctx context.Context, h *Hub, u User, args json.RawMessage) (any, error) {
			var in struct {
				Cluster, Namespace, Workload string
				Seconds                      int
			}
			if err := json.Unmarshal(args, &in); err != nil {
				return nil, err
			}
			return h.Traffic(ctx, u, in.Cluster, in.Namespace, in.Workload, in.Seconds)
		}},
	{Name: "find_profile_endpoints", Description: "Look for the profile endpoints that a workload's pods serve: Go net/http/pprof (also libraries for other languages that serve its paths), C or C++ with gperftools or brpc, Java with Spring Boot Actuator and .NET with dotnet-monitor. It asks each listening port of a pod for the index page of these; that starts no profiling. Use the found port and endpoint as <port>/<endpoint> in the endpoints parameter of a pprof recording. Endpoints marked sensitive return memory contents and need approval. Also returns the ports that the pod listens on.",
		InputSchema: object(`"cluster":{"type":"string"},"namespace":{"type":"string"},"workload":{"type":"string"}`, "cluster", "namespace", "workload"),
		call: func(ctx context.Context, h *Hub, u User, args json.RawMessage) (any, error) {
			var in struct{ Cluster, Namespace, Workload string }
			if err := json.Unmarshal(args, &in); err != nil {
				return nil, err
			}
			return h.Profiles(ctx, u, in.Cluster, in.Namespace, in.Workload)
		}},
	{Name: "request_capture", Description: "Record evidence from the pods of a workload: one or several recordings that run together. Captures that can contain memory or payload contents (coredump, pcap with payload, strace with strings) wait in state PendingApproval until an administrator approves them; follow the state with get_capture.",
		InputSchema: object(captureProperties, "cluster", "namespace", "workload"),
		call: func(ctx context.Context, h *Hub, u User, args json.RawMessage) (any, error) {
			var in api.CaptureRequest
			if err := json.Unmarshal(args, &in); err != nil {
				return nil, err
			}
			return h.Request(ctx, u, in)
		}},
	{Name: "watch_crashes", Description: "Record evidence automatically when a container of the workload crashes (exits with a failure, including out of memory): the same arguments as request_capture, applied to the crashed pod. Useful: pod-state, logs (they then include the crashed instance of each container) and pcap, which then holds the packets of the durationSeconds before the crash. A watch for evidence that needs approval waits until an administrator approves the watch; its captures then start without another approval. A coredump watch records the core of the crashed process and needs the core handler on the cluster's nodes. The captures appear in list_captures.",
		InputSchema: object(captureProperties+`,"count":{"type":"integer","description":"How many crashes to record before the watch ends; default 1"}`, "cluster", "namespace", "workload"),
		call: func(ctx context.Context, h *Hub, u User, args json.RawMessage) (any, error) {
			var in api.WatchRequest
			if err := json.Unmarshal(args, &in); err != nil {
				return nil, err
			}
			return h.Watch(ctx, u, in)
		}},
	{Name: "list_watches", Description: "List your watches that still wait for crashes.", InputSchema: object(""),
		call: func(ctx context.Context, h *Hub, u User, _ json.RawMessage) (any, error) { return h.watches(ctx, u) }},
	{Name: "delete_watch", Description: "End a watch.", InputSchema: object(`"id":{"type":"string"}`, "id"),
		call: func(ctx context.Context, h *Hub, u User, args json.RawMessage) (any, error) {
			var in struct{ ID string }
			if err := json.Unmarshal(args, &in); err != nil {
				return nil, err
			}
			return "deleted", h.Unwatch(ctx, u, in.ID)
		}},
	{Name: "list_captures", Description: "List your most recent captures with their state and files.", InputSchema: object(""),
		call: func(ctx context.Context, h *Hub, u User, _ json.RawMessage) (any, error) {
			return h.captures(ctx, u, time.Now().Add(time.Hour), defaultPage)
		}},
	{Name: "get_capture", Description: "Read one capture: its state, per-pod tasks and the stored files.", InputSchema: object(`"id":{"type":"string"}`, "id"),
		call: func(ctx context.Context, h *Hub, u User, args json.RawMessage) (any, error) {
			var in struct{ ID string }
			if err := json.Unmarshal(args, &in); err != nil {
				return nil, err
			}
			return h.visible(ctx, u, in.ID)
		}},
	{Name: "read_artifact", Description: "Read up to 64 KiB of a capture's text file (logs, JSON, strace) from a byte offset. Binary files (pcap, core, pprof) are downloaded from /api/captures/{id}/artifacts/{name} for local tools.",
		InputSchema: object(`"id":{"type":"string"},"name":{"type":"string"},"offset":{"type":"integer"}`, "id", "name"),
		call: func(ctx context.Context, h *Hub, u User, args json.RawMessage) (any, error) {
			var in struct {
				ID, Name string
				Offset   int64
			}
			if err := json.Unmarshal(args, &in); err != nil {
				return nil, err
			}
			c, err := h.visible(ctx, u, in.ID)
			if err != nil {
				return nil, err
			}
			a, err := h.Store.Artifact(ctx, c.ID, in.Name)
			if err != nil {
				return nil, err
			}
			key, err := unwrapKey(h.MasterKey, a.Key)
			if err != nil {
				return nil, err
			}
			blob, err := h.Blobs.Get(ctx, a.Blob)
			if err != nil {
				return nil, err
			}
			defer blob.Close()
			if err := h.Store.Audit(ctx, u.Name, "artifact.read", c.ID, map[string]any{"name": a.Name, "offset": in.Offset}); err != nil {
				return nil, err
			}
			var buf bytes.Buffer
			if err := decrypt(&window{w: &buf, skip: in.Offset, max: mcpReadLimit}, blob, key); err != nil && !errors.Is(err, errWindowFull) {
				return nil, fmt.Errorf("read %s: %w", a.Name, err)
			}
			if bytes.IndexByte(buf.Bytes(), 0) >= 0 {
				return nil, fmt.Errorf("%s is binary; download /api/captures/%s/artifacts/%s", a.Name, c.ID, a.Name)
			}
			return map[string]any{"size": a.Size, "offset": in.Offset, "text": string(bytes.ToValidUTF8(buf.Bytes(), nil))}, nil
		}},
}

// window keeps max bytes after skipping the first skip bytes.
type window struct {
	w         io.Writer
	skip, max int64
}

func (s *window) Write(p []byte) (int, error) {
	n := len(p)
	if s.skip >= int64(n) {
		s.skip -= int64(n)
		return n, nil
	}
	p = p[s.skip:]
	s.skip = 0
	if int64(len(p)) > s.max {
		p = p[:s.max]
	}
	s.max -= int64(len(p))
	s.w.Write(p)
	if s.max == 0 {
		return n, errWindowFull
	}
	return n, nil
}

// errWindowFull ends the decryption once the requested bytes are read.
var errWindowFull = errors.New("window full")

func (h *Hub) mcp(w http.ResponseWriter, r *http.Request, u User) error {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return errStatus{http.StatusBadRequest, "invalid JSON-RPC request"}
	}
	if req.ID == nil { // a notification
		w.WriteHeader(http.StatusAccepted)
		return nil
	}
	var result any
	var rpcErr any
	switch req.Method {
	case "initialize":
		result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "asservat", "version": "0"}}
	case "ping":
		result = map[string]any{}
	case "tools/list":
		result = map[string]any{"tools": mcpTools}
	case "tools/call":
		text, isError := "unknown tool "+req.Params.Name, true
		for _, t := range mcpTools {
			if t.Name != req.Params.Name {
				continue
			}
			if len(req.Params.Arguments) == 0 {
				req.Params.Arguments = json.RawMessage("{}")
			}
			out, err := t.call(r.Context(), h, u, req.Params.Arguments)
			if err != nil {
				text = err.Error()
			} else {
				b, _ := json.Marshal(out)
				text, isError = string(b), false
			}
		}
		result = map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": isError}
	default:
		rpcErr = map[string]any{"code": -32601, "message": "method not found"}
	}
	out := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	if rpcErr != nil {
		out["error"] = rpcErr
	} else {
		out["result"] = result
	}
	return reply(w, out)
}
