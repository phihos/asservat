// Package api holds the types shared by the hub, the node agents and clients.
package api

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Capture kinds. Every kind produces files in the tool's own format.
const (
	KindPodState = "pod-state" // pod object and its events as JSON
	KindLogs     = "logs"      // container logs
	KindPcap     = "pcap"      // packet capture (tcpdump)
	KindCoredump = "coredump"  // core of the container's main process (gcore)
	KindStrace   = "strace"    // system call trace
	KindPprof    = "pprof"     // HTTP profile endpoint, e.g. Go net/http/pprof
)

// Capture states.
const (
	StatePendingApproval = "PendingApproval"
	StateQueued          = "Queued"
	StateRunning         = "Running"
	StateCompleted       = "Completed"
	StateFailed          = "Failed"
	StateDenied          = "Denied"
	StateCancelled       = "Cancelled"
)

// CaptureRequest is what a user submits.
type CaptureRequest struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	// Workload is "Deployment/name", "StatefulSet/name", "DaemonSet/name" or "Pod/name".
	Workload string `json:"workload"`
	// Pods restricts the capture to these pods of the workload; empty means all.
	Pods []string `json:"pods,omitempty"`
	Kind string   `json:"kind"`
	// DurationSeconds bounds pcap, strace, pprof and followed logs.
	DurationSeconds int               `json:"durationSeconds,omitempty"`
	Params          map[string]string `json:"params,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	// Watch is the watch that created the capture and Trigger the agent's
	// report of the crash. Only the hub sets them.
	Watch   string `json:"watch,omitempty"`
	Trigger string `json:"trigger,omitempty"`
}

var (
	workloadPattern = regexp.MustCompile(`^(Deployment|StatefulSet|DaemonSet|Pod)/[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
	namePattern     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
	pathPattern     = regexp.MustCompile(`^/[A-Za-z0-9/_.?=&%-]*$`)
	// An executable's path as the process list shows it.
	executablePattern = regexp.MustCompile(`^/[^\x00-\x1f]*$`)
)

// ValidName reports whether s can name a cluster, namespace, pod or container.
func ValidName(s string) bool { return namePattern.MatchString(s) }

// params lists the parameters each kind accepts.
var params = map[string][]string{
	KindPodState: {},
	KindLogs:     {"container", "previous", "tailLines"},
	KindPcap:     {"filter", "payload"},
	KindCoredump: {"container", "process"},
	KindStrace:   {"container", "strings", "process"},
	KindPprof:    {"port", "path"},
}

// Validate checks the request's shape. Durations default to 30 seconds for
// the kinds that record over time.
func (r *CaptureRequest) Validate() error {
	allowed, ok := params[r.Kind]
	if !ok {
		return fmt.Errorf("unknown kind %q", r.Kind)
	}
	if !namePattern.MatchString(r.Cluster) || !namePattern.MatchString(r.Namespace) || !workloadPattern.MatchString(r.Workload) {
		return fmt.Errorf("cluster, namespace and workload (Kind/name) are required")
	}
	for _, p := range r.Pods {
		if !namePattern.MatchString(p) {
			return fmt.Errorf("invalid pod name %q", p)
		}
	}
	for k := range r.Params {
		found := false
		for _, a := range allowed {
			found = found || a == k
		}
		if !found {
			return fmt.Errorf("kind %s has no parameter %q", r.Kind, k)
		}
	}
	for _, k := range []string{"previous", "payload", "strings"} {
		if v, ok := r.Params[k]; ok && v != "true" && v != "false" {
			return fmt.Errorf("parameter %s must be true or false", k)
		}
	}
	for _, k := range []string{"port", "tailLines"} {
		if v, ok := r.Params[k]; ok {
			if n, err := strconv.Atoi(v); err != nil || n < 1 {
				return fmt.Errorf("parameter %s must be a positive number", k)
			}
		}
	}
	if v, ok := r.Params["container"]; ok && !namePattern.MatchString(v) {
		return fmt.Errorf("invalid container name")
	}
	if v, ok := r.Params["path"]; ok && !pathPattern.MatchString(v) {
		return fmt.Errorf("invalid path")
	}
	if v, ok := r.Params["process"]; ok && !executablePattern.MatchString(v) {
		return fmt.Errorf("process must be the path of an executable, as the process list shows it")
	}
	if r.Kind == KindPprof && r.Params["port"] == "" {
		return fmt.Errorf("pprof needs the port parameter")
	}
	if r.DurationSeconds < 0 {
		return fmt.Errorf("durationSeconds must not be negative")
	}
	if r.DurationSeconds == 0 && (r.Kind == KindPcap || r.Kind == KindStrace || r.Kind == KindPprof) {
		r.DurationSeconds = 30
	}
	return nil
}

// Sensitive reports whether the capture can contain memory or payload
// contents and therefore needs an administrator's approval.
func (r *CaptureRequest) Sensitive() bool {
	switch r.Kind {
	case KindCoredump:
		return true
	case KindPcap:
		return r.Params["payload"] == "true"
	case KindStrace:
		return r.Params["strings"] == "true"
	}
	return false
}

// Capture is a request with its progress and results.
type Capture struct {
	ID string `json:"id"`
	CaptureRequest
	Requester  string     `json:"requester"`
	Sensitive  bool       `json:"sensitive"`
	State      string     `json:"state"`
	Message    string     `json:"message,omitempty"`
	Approver   string     `json:"approver,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	Tasks      []Task     `json:"tasks"`
	Artifacts  []Artifact `json:"artifacts"`
}

// Task is the capture on one pod, run by the agent on the pod's node.
type Task struct {
	Pod     string `json:"pod"`
	Node    string `json:"node"`
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

// Artifact is one stored file of a capture.
type Artifact struct {
	Name   string `json:"name"` // "<pod>/<file>"
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// WatchRequest is what a user submits to record the next crashes of a
// workload: the capture to make whenever one of its containers crashes.
type WatchRequest struct {
	CaptureRequest
	// Count is how many crashes the watch records before it ends; default 1.
	Count int `json:"count,omitempty"`
}

// Watch is a standing request. The node agents observe the workload's pods
// and report a crash to the hub, which creates a capture for the pod.
type Watch struct {
	ID string `json:"id"`
	CaptureRequest
	Requester string `json:"requester"`
	// A sensitive watch waits until an administrator approves it. Its
	// captures then need no further approval.
	Sensitive bool   `json:"sensitive"`
	Approver  string `json:"approver,omitempty"`
	// Selector is the label selector of the workload's pods; empty for Pod/name.
	Selector  string    `json:"selector,omitempty"`
	Remaining int       `json:"remaining"`
	CreatedAt time.Time `json:"createdAt"`
}

// Trigger is an agent's report that a container of a watched pod crashed.
type Trigger struct {
	// ID is chosen by the agent. The capture's task carries it back, so the
	// agent finds what it set aside at the crash.
	ID      string `json:"id"`
	Pod     string `json:"pod"`
	Node    string `json:"node"`
	Message string `json:"message"`
}

// Pod is a resolved capture target.
type Pod struct {
	Name string `json:"name"`
	Node string `json:"node"`
}

// Command is a message from the hub to a node agent on its stream.
type Command struct {
	// Type is "sync", "query", "task", "cancel" or "watches".
	Type string `json:"type"`
	// ID is the query ID or the capture ID.
	ID    string          `json:"id,omitempty"`
	Query *Query          `json:"query,omitempty"`
	Task  *TaskAssignment `json:"task,omitempty"`
	// Tasks of a sync are all open tasks of the agent's node. Sync is the
	// first command of every stream: the agent starts the tasks it missed
	// and stops those that are no longer open.
	Tasks []Command `json:"tasks,omitempty"`
	// Watches of a sync or a "watches" command are all watches of the
	// agent's cluster; the agent stops observing any other.
	Watches []Watch `json:"watches,omitempty"`
}

// Query asks an agent for information. Any agent of a cluster answers the
// questions about the cluster; those about pods go to the agent of their node.
type Query struct {
	// Op is, about the cluster: "resolve" (the pods of a workload),
	// "workload" (the label selector of its pods and its containers),
	// "workloads" (the workloads of a namespace), "namespaces" (the
	// namespaces in which the user may exec into pods, or all without a
	// user), "review" (may the user exec into pods of the namespace) or
	// "peers" (what the IPs belong to: Services and pods of the namespace,
	// or of all namespaces with All). About Pods of the agent's node:
	// "processes" (what runs in them) or "traffic" (their connections,
	// from the packet headers of Seconds).
	Op        string   `json:"op"`
	Namespace string   `json:"namespace"`
	Workload  string   `json:"workload,omitempty"`
	User      string   `json:"user,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	Pods      []string `json:"pods,omitempty"`
	Seconds   int      `json:"seconds,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	All       bool     `json:"all,omitempty"`
}

// Process is a process of a pod's container.
type Process struct {
	Pod       string `json:"pod"`
	Container string `json:"container"`
	// PID is the process ID inside the pod.
	PID        int    `json:"pid"`
	Executable string `json:"executable"`
	Name       string `json:"name"`
	// Main marks the container's main process, the default target.
	Main          bool  `json:"main"`
	ResidentBytes int64 `json:"residentBytes"`
	Threads       int   `json:"threads"`
}

// ProcessChoice is a program that runs in a container of a workload's pods:
// what a core dump or trace can target instead of the main process.
type ProcessChoice struct {
	Container  string `json:"container"`
	Executable string `json:"executable"`
	Name       string `json:"name"`
	// Main marks the program of the container's main process.
	Main bool `json:"main"`
	// Processes counts its processes in all inspected pods, Pods the pods
	// in which it runs.
	Processes int `json:"processes"`
	Pods      int `json:"pods"`
	// LargestResidentBytes is the memory of its largest process: about the
	// size of that process's core.
	LargestResidentBytes int64 `json:"largestResidentBytes"`
}

// Inspection is what the hub learned from a workload's pods.
type Inspection struct {
	// Pods were inspected. NotInspected were not: no agent is connected on
	// their node, or the pod ended or restarted meanwhile.
	Pods         []string `json:"pods"`
	NotInspected []string `json:"notInspected,omitempty"`
	// Processes of a process inspection.
	Processes []ProcessChoice `json:"processes,omitempty"`
	// Seconds and Flows of a traffic sample, most bytes first.
	Seconds int    `json:"seconds,omitempty"`
	Flows   []Flow `json:"flows,omitempty"`
}

// Flow directions, seen from the pod.
const (
	FlowIn    = "in"    // peers connect to a port of the pod
	FlowOut   = "out"   // the pod connects to a peer's port
	FlowLocal = "local" // inside the pod, over loopback
)

// Flow summarizes the packets that pods exchanged over one port: with all
// peers for incoming traffic, with one peer for outgoing traffic.
type Flow struct {
	Direction string `json:"direction"`
	Protocol  string `json:"protocol"` // "tcp" or "udp"
	Port      int    `json:"port"`     // the port of the side that serves
	// Peer is the address that the pod connects to; empty unless outgoing.
	Peer string `json:"peer,omitempty"`
	// PeerName is what the address belongs to, if the user may know.
	PeerName string `json:"peerName,omitempty"`
	// Peers counts the distinct addresses that connected to the pod.
	Peers int `json:"peers,omitempty"`
	// PeerList holds those addresses in an agent's reply, for the hub to
	// count them across pods.
	PeerList []string `json:"peerList,omitempty"`
	Packets  int      `json:"packets"`
	Bytes    int64    `json:"bytes"`
	Pods     int      `json:"pods"`
	// Label describes the flow in words and Filter selects it in a packet
	// capture (tcpdump syntax).
	Label  string `json:"label"`
	Filter string `json:"filter"`
}

// Reply answers a Query.
type Reply struct {
	Error      string    `json:"error,omitempty"`
	Pods       []Pod     `json:"pods,omitempty"`
	Workloads  []string  `json:"workloads,omitempty"`
	Allowed    bool      `json:"allowed,omitempty"`
	Selector   string    `json:"selector,omitempty"`
	Containers []string  `json:"containers,omitempty"`
	Namespaces []string  `json:"namespaces,omitempty"`
	Processes  []Process `json:"processes,omitempty"`
	// Flows of one pod each.
	Flows []Flow `json:"flows,omitempty"`
	// Skipped names the pods of a "processes" or "traffic" query that the
	// agent could not look at, for example because they are gone.
	Skipped []string `json:"skipped,omitempty"`
	// Names maps the IPs of a "peers" query to what they belong to.
	Names map[string]string `json:"names,omitempty"`
}

// TaskAssignment tells an agent to capture one pod on its node.
type TaskAssignment struct {
	Pod     string         `json:"pod"`
	Request CaptureRequest `json:"request"`
	// Started marks a task that the hub knows as running, sent again when
	// the node's agent reconnects. An agent that does not run it lost it.
	Started bool `json:"started,omitempty"`
}

// TaskStatus is an agent's report about its task.
type TaskStatus struct {
	Pod     string `json:"pod"`
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}
