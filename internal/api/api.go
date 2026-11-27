// Package api holds the types shared by the hub, the node agents and clients.
package api

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Capture kinds. Every kind produces files in the tool's own format.
const (
	KindPodState = "pod-state" // pod object and its events as JSON
	KindLogs     = "logs"      // container logs
	KindPcap     = "pcap"      // packet capture (tcpdump)
	KindCoredump = "coredump"  // core of the container's main process (gcore)
	KindStrace   = "strace"    // system call trace
	KindPprof    = "pprof"     // profile endpoints of the application's runtime, and a JVM's own diagnostics
	KindCPU      = "cpu"       // CPU profile sampled from the node, without an endpoint
	KindMemory   = "memory"    // where memory grows, sampled from the node at page faults
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
	// StateWaiting is the state of a recording that starts after another
	// one of its capture.
	StateWaiting = "Waiting"
)

// Recording is one kind of evidence to record, with its parameters.
type Recording struct {
	Kind   string            `json:"kind"`
	Params map[string]string `json:"params,omitempty"`
}

// CaptureRequest is what a user submits: one or more recordings of the same
// pods that start together, share one time frame and one approval.
type CaptureRequest struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	// Workload is "Deployment/name", "StatefulSet/name", "DaemonSet/name" or "Pod/name".
	Workload string `json:"workload"`
	// Pods restricts the capture to these pods of the workload; empty means all.
	Pods []string `json:"pods,omitempty"`
	// Recordings holds at most one recording of each kind.
	Recordings []Recording `json:"recordings,omitempty"`
	// Kind and Params are a short form for a request with one recording.
	// Normalize moves them into Recordings.
	Kind   string            `json:"kind,omitempty"`
	Params map[string]string `json:"params,omitempty"`
	// DurationSeconds is the time frame of the recordings that run over
	// time: pcap, strace, cpu, memory, pprof and followed logs.
	DurationSeconds int    `json:"durationSeconds,omitempty"`
	Reason          string `json:"reason,omitempty"`
	// Watch is the watch that created the capture, Trigger the agent's
	// report that the watch's condition was met and On the kind of that
	// condition. Only the hub sets them.
	Watch   string `json:"watch,omitempty"`
	Trigger string `json:"trigger,omitempty"`
	On      string `json:"on,omitempty"`
}

// AfterCrash tells whether the capture is that of a watch for crashes: the
// pod's container has ended, and what is recorded is what it left behind.
// The capture of any other watch finds the pod as it runs.
func (r *CaptureRequest) AfterCrash() bool {
	return r.Watch != "" && Condition{Kind: r.On}.Crash()
}

// Normalize turns the short form with one kind into a recording.
func (r *CaptureRequest) Normalize() {
	if r.Kind != "" {
		r.Recordings = append(r.Recordings, Recording{Kind: r.Kind, Params: r.Params})
	}
	r.Kind, r.Params = "", nil
}

// Timed reports whether the recording runs for the request's time frame.
func (rec Recording) Timed(followLogs bool) bool {
	switch rec.Kind {
	case KindPcap, KindStrace, KindCPU, KindMemory:
		return true
	case KindLogs:
		return followLogs
	case KindPprof:
		targets, _ := rec.ProfileTargets()
		for _, t := range targets {
			if t.Timed {
				return true
			}
		}
	}
	return false
}

// Recording returns the request's recording of a kind, or nil.
func (r *CaptureRequest) Recording(kind string) *Recording {
	for i := range r.Recordings {
		if r.Recordings[i].Kind == kind {
			return &r.Recordings[i]
		}
	}
	return nil
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
	KindPcap:     {"filter", "payload", "before"},
	KindCoredump: {"container", "process"},
	KindStrace:   {"container", "strings", "process", "before"},
	KindPprof:    {"endpoints", "port", "path"},
	KindCPU:      {"before"},
	KindMemory:   {"before"},
}

// Validate normalizes the request and checks its shape. The time frame
// defaults to 30 seconds if a recording runs over time.
func (r *CaptureRequest) Validate() error {
	r.Normalize()
	if !namePattern.MatchString(r.Cluster) || !namePattern.MatchString(r.Namespace) || !workloadPattern.MatchString(r.Workload) {
		return fmt.Errorf("cluster, namespace and workload (Kind/name) are required")
	}
	for _, p := range r.Pods {
		if !namePattern.MatchString(p) {
			return fmt.Errorf("invalid pod name %q", p)
		}
	}
	if len(r.Recordings) == 0 {
		return fmt.Errorf("choose at least one kind of evidence")
	}
	timed := false
	for i, rec := range r.Recordings {
		if err := rec.validate(); err != nil {
			return err
		}
		// Two recordings of one kind would write the same files.
		for _, earlier := range r.Recordings[:i] {
			if earlier.Kind == rec.Kind {
				return fmt.Errorf("kind %s is requested twice", rec.Kind)
			}
		}
		timed = timed || rec.Kind == KindPcap || rec.Kind == KindStrace || rec.Kind == KindPprof || rec.Kind == KindCPU || rec.Kind == KindMemory
	}
	if r.DurationSeconds < 0 {
		return fmt.Errorf("durationSeconds must not be negative")
	}
	if r.DurationSeconds == 0 && timed {
		r.DurationSeconds = 30
	}
	return nil
}

func (rec Recording) validate() error {
	allowed, ok := params[rec.Kind]
	if !ok {
		return fmt.Errorf("unknown kind %q: the kinds are %s", rec.Kind, strings.Join(slices.Sorted(maps.Keys(params)), ", "))
	}
	for k := range rec.Params {
		found := false
		for _, a := range allowed {
			found = found || a == k
		}
		if !found {
			return fmt.Errorf("kind %s has no parameter %q", rec.Kind, k)
		}
	}
	for _, k := range []string{"previous", "payload", "strings", "before"} {
		if v, ok := rec.Params[k]; ok && v != "true" && v != "false" {
			return fmt.Errorf("parameter %s must be true or false", k)
		}
	}
	for _, k := range []string{"port", "tailLines"} {
		if v, ok := rec.Params[k]; ok {
			if n, err := strconv.Atoi(v); err != nil || n < 1 {
				return fmt.Errorf("parameter %s must be a positive number", k)
			}
		}
	}
	if v, ok := rec.Params["container"]; ok && !namePattern.MatchString(v) {
		return fmt.Errorf("invalid container name")
	}
	if v, ok := rec.Params["path"]; ok && !pathPattern.MatchString(v) {
		return fmt.Errorf("invalid path")
	}
	if v, ok := rec.Params["process"]; ok && !executablePattern.MatchString(v) {
		return fmt.Errorf("process must be the path of an executable, as the process list shows it")
	}
	if rec.Kind == KindPprof {
		_, err := rec.ProfileTargets()
		return err
	}
	return nil
}

// Buffers tells whether the recording, in a watch, is kept running while
// the watch waits, so that its file reaches back before the moment the
// watch's condition is met. The parameter "before" says so; without it the
// recordings do that cost little while they wait: packets and the sampled
// CPU profile. Memory growth slows every page fault on the node meanwhile,
// and a trace of system calls slows the traced process: they are kept
// running only on request.
func (rec Recording) Buffers() bool {
	switch rec.Kind {
	case KindPcap, KindCPU:
		return rec.Params["before"] != "false"
	case KindMemory, KindStrace:
		return rec.Params["before"] == "true"
	}
	return false
}

// Sensitive reports whether the recording can contain memory or payload
// contents.
func (rec Recording) Sensitive() bool {
	switch rec.Kind {
	case KindCoredump:
		return true
	case KindPcap:
		return rec.Params["payload"] == "true"
	case KindStrace:
		return rec.Params["strings"] == "true"
	case KindPprof:
		targets, _ := rec.ProfileTargets()
		for _, t := range targets {
			if t.Sensitive {
				return true
			}
		}
	}
	return false
}

// Sensitive reports whether any recording of the request is sensitive: the
// request then needs an administrator's approval, once for all of it.
func (r *CaptureRequest) Sensitive() bool {
	r.Normalize()
	for _, rec := range r.Recordings {
		if rec.Sensitive() {
			return true
		}
	}
	return false
}

// Capture is a request with its progress and results.
type Capture struct {
	ID string `json:"id"`
	// Number counts the installation's captures up; people call a capture
	// by it, as an exhibit by its number.
	Number int64 `json:"number"`
	CaptureRequest
	Requester string `json:"requester"`
	// Shared: also there, to look at, for everyone who may capture in its namespace.
	Shared     bool       `json:"shared,omitempty"`
	Sensitive  bool       `json:"sensitive"`
	State      string     `json:"state"`
	Message    string     `json:"message,omitempty"`
	Approver   string     `json:"approver,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	// StoppedAt is when a user stopped the capture; its recordings then
	// finish with what they have.
	StoppedAt *time.Time `json:"stoppedAt,omitempty"`
	// RemainingSeconds is how much of the time frame the running
	// recordings still have, when the capture was read; absent when
	// nothing runs over time.
	RemainingSeconds *int       `json:"remainingSeconds,omitempty"`
	Tasks            []Task     `json:"tasks"`
	Artifacts        []Artifact `json:"artifacts"`
}

// Task is the capture on one pod, run by the agent on the pod's node.
type Task struct {
	Pod     string `json:"pod"`
	Node    string `json:"node"`
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
	// Recordings is the progress of each recording on the pod.
	Recordings []RecordingStatus `json:"recordings,omitempty"`
}

// RecordingStatus is the progress of one recording on one pod.
type RecordingStatus struct {
	Kind string `json:"kind"`
	// State is Waiting, Running, Completed or Failed.
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
	// StartedAt is when the hub learned that the recording runs.
	StartedAt *time.Time `json:"startedAt,omitempty"`
}

// Artifact is one stored file of a capture.
type Artifact struct {
	Name   string `json:"name"` // "<pod>/<file>"
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	// Stored is what the file takes of the hub's store, where that is
	// less than its size: a core is stored without its holes.
	Stored int64 `json:"stored,omitempty"`
	// Viewer names the viewer that shows the file in the browser; a file
	// without one only downloads.
	Viewer string `json:"viewer,omitempty"`
	// Recording is the kind of recording that made the file, where its
	// name tells: the files of a profile endpoint are named by the
	// application's endpoints and tell nothing.
	Recording string `json:"recording,omitempty"`
}

// RecordingOf names the kind of recording that an artifact is from, by the
// names the agent gives its files, or "" for a name it gives to none:
// then it is a file of a profile endpoint.
func RecordingOf(name string) string {
	file := name[strings.LastIndex(name, "/")+1:]
	switch {
	case file == "capture.pcap":
		return KindPcap
	case file == "pod.json", file == "events.json":
		return KindPodState
	case strings.HasSuffix(file, ".log"):
		return KindLogs
	case strings.HasSuffix(file, ".strace"):
		return KindStrace
	case file == "sampled-cpu.pprof":
		return KindCPU
	case file == "sampled-memory.pprof":
		return KindMemory
	case strings.HasPrefix(file, "core."):
		return KindCoredump
	}
	return ""
}

// ViewerOf names the viewer for an artifact, or "" if it only downloads.
func ViewerOf(name string) string {
	file := name[strings.LastIndex(name, "/")+1:]
	switch {
	case strings.HasSuffix(file, ".pcap"):
		return "pcap"
	// Logs, and the JVM's class histogram, which is lines of text as well.
	case strings.HasSuffix(file, ".log"), strings.HasSuffix(file, "histogram.txt"):
		return "log"
	// The archive of a core's program files is for a debugger.
	case strings.HasSuffix(file, ".files.tar"):
		return ""
	// A core and gdb's description of it open in the same viewer.
	case strings.HasPrefix(file, "core."):
		return "core"
	// A profile in pprof's format; a .NET trace and a JVM's flight recording, whose samples the hub shows as one.
	case strings.HasSuffix(file, ".pprof"), strings.HasSuffix(file, ".nettrace"), strings.HasSuffix(file, ".jfr"):
		return "pprof"
	// Go's execution trace, as the endpoint catalog names it.
	case strings.HasSuffix(file, "trace.out"):
		return "gotrace"
	case strings.HasSuffix(file, ".strace"):
		return "strace"
	// A heap dump of Java, or .NET's dump of the heap's objects without their contents.
	case strings.HasSuffix(file, ".hprof"), strings.HasSuffix(file, ".gcdump"):
		return "heap"
	// Dumps of goroutines or threads; with a port in front of the name
	// when a capture fetched the same endpoint from several ports.
	case strings.HasSuffix(file, "goroutines.txt"), strings.HasSuffix(file, "threaddump.txt"):
		return "stacks"
	case file == "pod.json", file == "events.json":
		return "kube"
	}
	return ""
}

// The conditions a watch can wait for.
const (
	OnCrash    = "crash"     // a container ends with a failure
	OnRestart  = "restart"   // a container is started again, whatever ended it
	OnNotReady = "not-ready" // the pod stops being ready
	OnLog      = "log"       // a container writes a log line that matches a pattern
	OnMemory   = "memory"    // a container's memory use is above a size or a share of its limit
	OnCPU      = "cpu"       // a container's CPU use is above a number of CPUs or a share of its limit
	OnThrottle = "throttled" // a container is held back by its CPU limit in more than a share of the time
	OnAlert    = "alert"     // a Prometheus alert fires, as Alertmanager tells the hub
	OnEvent    = "event"     // Kubernetes warns about the pod with an event, such as a failed probe or mount
	OnTime     = "time"      // a time comes, once or again and again, as the hub's clock tells
	// OnAsked is not a condition to wait for: it marks the capture of a
	// watch that was asked to record now.
	OnAsked = "asked"
	// More that the agent measures of a container:
	OnPressure    = "pressure"        // it stalls for memory, CPU or I/O in more than a share of the time
	OnGrowth      = "memory-growth"   // its memory use grows by more than a size within a time
	OnThreads     = "threads"         // it has more than a number of threads and processes
	OnFiles       = "open-files"      // its processes hold more than a number of open files
	OnRetransmits = "tcp-retransmits" // its pod retransmits more than a number of TCP segments per second
	OnTCPFailures = "tcp-failures"    // more than a number of its pod's TCP connection attempts fail per second
)

// Condition is what a watch waits for. Without a kind it is a crash.
type Condition struct {
	Kind   string            `json:"kind,omitempty"`
	Params map[string]string `json:"params,omitempty"`
}

// Crash tells whether the condition is a container's crash.
func (c Condition) Crash() bool { return c.Kind == "" || c.Kind == OnCrash }

// eventReason is how Kubernetes writes the reason of an event: one word in
// camel case.
var eventReason = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

// Times reads a time condition: when it is first met and, if it repeats,
// after how long each time.
func (c Condition) Times() (at time.Time, every time.Duration, err error) {
	at, err = time.Parse(time.RFC3339, c.Params["at"])
	if err != nil {
		return at, 0, errors.New(`a time condition needs at: a time such as "2026-12-01T03:00:00Z"`)
	}
	if v, ok := c.Params["every"]; ok {
		seconds, err := strconv.Atoi(v)
		if err != nil || seconds <= 0 {
			return at, 0, errors.New("every is the number of seconds after which the time comes again")
		}
		every = time.Duration(seconds) * time.Second
	}
	return at, every, nil
}

// Due tells for a time condition which of its times was the last to come,
// if one has, and which comes next, if one will.
func (c Condition) Due(now time.Time) (last, next time.Time) {
	at, every, err := c.Times()
	switch {
	case err != nil:
	case now.Before(at):
		next = at
	case every == 0:
		last = at
	default:
		last = at.Add(now.Sub(at) / every * every)
		next = last.Add(every)
	}
	return last, next
}

// conditionParams lists the parameters each kind of condition accepts.
var conditionParams = map[string][]string{
	OnCrash:       {},
	OnRestart:     {},
	OnNotReady:    {},
	OnLog:         {"pattern", "container"},
	OnMemory:      {"above", "seconds", "container"},
	OnCPU:         {"above", "seconds", "container"},
	OnThrottle:    {"above", "seconds", "container"},
	OnAlert:       {"name"},
	OnTime:        {"at", "every"},
	OnEvent:       {"reason"},
	OnPressure:    {"above", "seconds", "container", "of"},
	OnGrowth:      {"above", "seconds", "container"},
	OnThreads:     {"above", "seconds", "container"},
	OnFiles:       {"above", "seconds", "container"},
	OnRetransmits: {"above", "seconds", "container"},
	OnTCPFailures: {"above", "seconds", "container"},
}

// aboveUnits tells for each condition that the agent measures what its
// threshold counts: a size in bytes, CPUs or a plain number, and whether it
// can instead be a share ("80%") of the container's limit or of the time.
var aboveUnits = map[string]struct {
	unit  string // "size", "cpus", "number" or "" for a share only
	share bool
}{
	OnMemory: {"size", true}, OnCPU: {"cpus", true}, OnThrottle: {"", true}, OnPressure: {"", true},
	OnGrowth: {"size", false}, OnThreads: {"number", false}, OnFiles: {"number", false}, OnRetransmits: {"number", false}, OnTCPFailures: {"number", false},
}

// Usage tells whether the condition is about what a container uses, which
// the agent measures at intervals.
func (c Condition) Usage() bool {
	_, measured := aboveUnits[c.Kind]
	return measured
}

// Above is the threshold of a usage condition: a share of the container's
// limit or of the time, or an amount in bytes, CPUs or a plain number.
type Above struct {
	Value   float64
	Percent bool
}

// ParseAbove reads the threshold of a usage condition: "80%" is a share
// where the condition takes one; a size is written such as "500Mi" or
// "2G", CPUs such as "1.5" or "1500m", a number as it is.
func ParseAbove(kind, s string) (Above, error) {
	bad := fmt.Errorf("%q is no threshold for %s", s, kind)
	number := func(s string) (float64, error) {
		n, err := strconv.ParseFloat(s, 64)
		if err != nil || n < 0 || math.IsInf(n, 0) || math.IsNaN(n) {
			return 0, bad
		}
		return n, nil
	}
	takes := aboveUnits[kind]
	if share, ok := strings.CutSuffix(s, "%"); ok {
		if !takes.share {
			return Above{}, bad
		}
		n, err := number(share)
		return Above{Value: n, Percent: true}, err
	}
	switch takes.unit {
	case "size":
		for _, unit := range []struct {
			suffix string
			bytes  float64
		}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"k", 1e3}, {"M", 1e6}, {"G", 1e9}, {"", 1}} {
			if size, ok := strings.CutSuffix(s, unit.suffix); ok {
				n, err := number(size)
				return Above{Value: n * unit.bytes}, err
			}
		}
	case "cpus":
		if milli, ok := strings.CutSuffix(s, "m"); ok {
			n, err := number(milli)
			return Above{Value: n / 1000}, err
		}
		n, err := number(s)
		return Above{Value: n}, err
	case "number":
		n, err := number(s)
		return Above{Value: n}, err
	}
	return Above{}, bad // a share only
}

// Validate sets the default kind and checks the condition's shape.
func (c *Condition) Validate() error {
	if c.Kind == "" {
		c.Kind = OnCrash
	}
	allowed, ok := conditionParams[c.Kind]
	if !ok {
		return fmt.Errorf("unknown condition %q", c.Kind)
	}
	for k := range c.Params {
		if !slices.Contains(allowed, k) {
			return fmt.Errorf("condition %s has no parameter %q", c.Kind, k)
		}
	}
	if c.Kind == OnLog {
		if c.Params["pattern"] == "" {
			return errors.New("a log condition needs a pattern: a regular expression that a line is to match")
		}
		if _, err := regexp.Compile(c.Params["pattern"]); err != nil {
			return fmt.Errorf("the pattern is no regular expression: %v", err)
		}
	}
	if c.Kind == OnAlert && c.Params["name"] == "" {
		return errors.New("an alert condition needs the alert's name")
	}
	if v, ok := c.Params["reason"]; ok && !eventReason.MatchString(v) {
		return errors.New(`reason is that of the events to wait for, such as "Unhealthy" or "BackOff"`)
	}
	if c.Kind == OnTime {
		if _, _, err := c.Times(); err != nil {
			return err
		}
	}
	if c.Usage() {
		if c.Params["above"] == "" {
			return fmt.Errorf("a %s condition needs a threshold: above", c.Kind)
		}
		if _, err := ParseAbove(c.Kind, c.Params["above"]); err != nil {
			return err
		}
		if v, ok := c.Params["seconds"]; ok {
			if n, err := strconv.Atoi(v); err != nil || n < 0 {
				return errors.New("seconds must be a number that is not negative")
			}
		}
		if of, ok := c.Params["of"]; ok && !slices.Contains([]string{"memory", "cpu", "io"}, of) {
			return errors.New("pressure is of memory, cpu or io")
		}
		// Growth is measured over a time, which it needs.
		if seconds, _ := strconv.Atoi(c.Params["seconds"]); c.Kind == OnGrowth && seconds == 0 {
			return errors.New("memory-growth needs seconds: the time within which the memory grows that much")
		}
	}
	if v, ok := c.Params["container"]; ok && !namePattern.MatchString(v) {
		return errors.New("invalid container name")
	}
	return nil
}

// WatchRequest is what a user submits to record a workload whenever a
// condition is met: the capture to make of the pod that meets it.
type WatchRequest struct {
	CaptureRequest
	// When is the condition; a container's crash if empty.
	When Condition `json:"when,omitzero"`
	// BeforeSeconds is how far the recordings that are kept running while
	// the watch waits reach back before the condition is met; the time
	// frame (DurationSeconds) if zero.
	BeforeSeconds int `json:"beforeSeconds,omitempty"`
	// Count is how many times the watch records before it ends; default 1.
	Count int `json:"count,omitempty"`
}

// Watch is a standing request. The node agents observe the workload's pods
// and report to the hub when one meets the condition; the hub then creates
// a capture for that pod.
type Watch struct {
	ID string `json:"id"`
	CaptureRequest
	When          Condition `json:"when"`
	BeforeSeconds int       `json:"beforeSeconds,omitempty"`
	Requester     string    `json:"requester"`
	// A sensitive watch waits until an administrator approves it. Its
	// captures then need no further approval.
	Sensitive bool   `json:"sensitive"`
	Approver  string `json:"approver,omitempty"`
	// Selector is the label selector of the workload's pods; empty for Pod/name.
	Selector  string    `json:"selector,omitempty"`
	Remaining int       `json:"remaining"`
	CreatedAt time.Time `json:"createdAt"`
}

// Before is how far the watch's running recordings reach back.
func (w Watch) Before() time.Duration {
	if w.BeforeSeconds > 0 {
		return time.Duration(w.BeforeSeconds) * time.Second
	}
	return time.Duration(w.DurationSeconds) * time.Second
}

// Trigger is an agent's report that a watched pod met the watch's condition.
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
	// Type is "sync", "query", "task", "stop", "cancel", "watches" or
	// "beat", which asks for nothing and keeps the stream from being
	// silent; an agent passes over a type it does not know. A stop
	// ends the recordings of a capture that run over time and keeps what
	// they recorded; a cancel abandons them.
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
	// "processes" (what runs in them), "traffic" (their connections, from
	// the packet headers of Seconds) or "profiles" (the profile endpoints
	// that the first of them serves, and the diagnostics of its JVMs).
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
	// Profiles are the profile endpoints found in a pod and Ports the TCP
	// ports that it listens on.
	Profiles []ProfileTarget `json:"profiles,omitempty"`
	Ports    []int           `json:"ports,omitempty"`
	// Notes say why a JVM of the pod cannot be asked for its diagnostics.
	Notes []string `json:"notes,omitempty"`
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
	// Profiles, Ports and Notes answer a "profiles" query.
	Profiles []ProfileTarget `json:"profiles,omitempty"`
	Ports    []int           `json:"ports,omitempty"`
	Notes    []string        `json:"notes,omitempty"`
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
	// Stopped marks a task of a capture that a user stopped before the
	// agent received it: its time frame has ended.
	Stopped bool `json:"stopped,omitempty"`
}

// TaskStatus is an agent's report about its task.
type TaskStatus struct {
	Pod     string `json:"pod"`
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
	// Recordings is the state of every recording of the task; absent in a
	// report that does not know them.
	Recordings []RecordingStatus `json:"recordings,omitempty"`
}
