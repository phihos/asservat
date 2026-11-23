package api

import (
	"fmt"
	"strconv"
	"strings"
)

// ProfileEndpoint is an HTTP endpoint that a runtime or a common library
// serves for profiling, by convention, or a diagnostic that a JVM runs when
// it is asked over its attach socket. Asservat knows what each returns and
// can therefore tell which need approval.
type ProfileEndpoint struct {
	// ID names the endpoint in a request.
	ID string `json:"endpoint"`
	// Runtime says what serves it, Name what it returns.
	Runtime string `json:"runtime"`
	Name    string `json:"name"`
	// Path may hold "{seconds}" for the time frame; Timed marks those.
	Path  string `json:"-"`
	Timed bool   `json:"timed"`
	// Attach marks a diagnostic of a JVM, which has no Path: the agent
	// asks the JVM of a container for it over HotSpot's attach socket.
	Attach bool `json:"-"`
	// Sensitive marks endpoints that return memory contents.
	Sensitive bool `json:"sensitive"`
	// File names the stored artifact; Accept is sent as request header.
	File   string `json:"file"`
	Accept string `json:"-"`
}

// ProfileFamily is a set of endpoints that one probe recognizes.
type ProfileFamily struct {
	// A GET of Probe whose body contains Marker shows that the family is
	// served on a port. The probe is an index or information page: it
	// starts no profiling.
	Probe, Marker string
	Endpoints     []ProfileEndpoint
	// Listed marks families whose probe lists the endpoints that are
	// enabled: only those whose path it mentions are offered.
	Listed bool
}

const (
	runtimeGo     = "Go (net/http/pprof)"
	runtimeNative = "C or C++ (gperftools, brpc)"
	runtimeJava   = "Java (Spring Boot Actuator)"
	runtimeDotnet = ".NET (dotnet-monitor)"
	// The name tells what this way does to the container.
	runtimeJVM = "Java (HotSpot's own diagnostics: writes a marker file into the container's /tmp and signals the JVM)"
)

// ProfileFamilies is the catalog. Libraries for other languages that serve
// Go's paths (for example pprof-rs for Rust or pypprof for Python) are found
// as Go if they also serve its index page.
var ProfileFamilies = []ProfileFamily{
	{Probe: "/debug/pprof/", Marker: "goroutine", Endpoints: []ProfileEndpoint{
		{ID: "go-cpu", Runtime: runtimeGo, Name: "CPU profile", Path: "/debug/pprof/profile?seconds={seconds}", Timed: true, File: "cpu.pprof"},
		{ID: "go-heap", Runtime: runtimeGo, Name: "Heap: memory in use", Path: "/debug/pprof/heap", File: "heap.pprof"},
		{ID: "go-allocs", Runtime: runtimeGo, Name: "Allocations since the start", Path: "/debug/pprof/allocs", File: "allocs.pprof"},
		{ID: "go-goroutines", Runtime: runtimeGo, Name: "Goroutine stacks", Path: "/debug/pprof/goroutine?debug=2", File: "goroutines.txt"},
		{ID: "go-block", Runtime: runtimeGo, Name: "Blocking", Path: "/debug/pprof/block", File: "block.pprof"},
		{ID: "go-mutex", Runtime: runtimeGo, Name: "Mutex contention", Path: "/debug/pprof/mutex", File: "mutex.pprof"},
		{ID: "go-trace", Runtime: runtimeGo, Name: "Execution trace", Path: "/debug/pprof/trace?seconds={seconds}", Timed: true, File: "trace.out"},
	}},
	{Probe: "/pprof/symbol", Marker: "num_symbols", Endpoints: []ProfileEndpoint{
		{ID: "native-cpu", Runtime: runtimeNative, Name: "CPU profile", Path: "/pprof/profile?seconds={seconds}", Timed: true, File: "cpu.pprof"},
		{ID: "native-heap", Runtime: runtimeNative, Name: "Heap: memory in use", Path: "/pprof/heap", File: "heap.pprof"},
		{ID: "native-growth", Runtime: runtimeNative, Name: "Heap growth", Path: "/pprof/growth", File: "growth.pprof"},
	}},
	{Probe: "/actuator", Marker: `"_links"`, Listed: true, Endpoints: []ProfileEndpoint{
		{ID: "java-threads", Runtime: runtimeJava, Name: "Thread dump", Path: "/actuator/threaddump", File: "threaddump.txt", Accept: "text/plain"},
		{ID: "java-heapdump", Runtime: runtimeJava, Name: "Heap dump: the whole memory", Path: "/actuator/heapdump", Sensitive: true, File: "heapdump.hprof"},
	}},
	{Probe: "/info", Marker: `"diagnosticPortMode"`, Endpoints: []ProfileEndpoint{
		{ID: "dotnet-trace", Runtime: runtimeDotnet, Name: "CPU and runtime trace", Path: "/trace?durationSeconds={seconds}", Timed: true, File: "trace.nettrace"},
		{ID: "dotnet-gcdump", Runtime: runtimeDotnet, Name: "Heap objects, without their contents", Path: "/gcdump", File: "heap.gcdump"},
		{ID: "dotnet-dump", Runtime: runtimeDotnet, Name: "Memory dump: the whole memory", Path: "/dump", Sensitive: true, File: "memory.dmp"},
	}},
}

// JVMDiagnostics are what a HotSpot JVM gives when it is asked over its
// attach socket, which needs no endpoint in the application. They are all
// that Asservat asks a JVM for: nothing that loads code into it or changes
// its settings. The class histogram and the heap dump stop the JVM while
// it collects and walks its heap.
var JVMDiagnostics = []ProfileEndpoint{
	{ID: "jvm-threads", Runtime: runtimeJVM, Name: "Thread dump", Attach: true, File: "jvm-threaddump.txt"},
	{ID: "jvm-histogram", Runtime: runtimeJVM, Name: "Class histogram: objects and bytes by class; the JVM stops meanwhile", Attach: true, File: "jvm-histogram.txt"},
	{ID: "jvm-heapdump", Runtime: runtimeJVM, Name: "Heap dump: the whole memory; the JVM stops meanwhile", Attach: true, Sensitive: true, File: "jvm-heapdump.hprof"},
	{ID: "jvm-recording", Runtime: runtimeJVM, Name: "Flight recording, for JDK Mission Control", Attach: true, Timed: true, File: "jvm-recording.jfr"},
}

// FindProfileEndpoint returns the catalog's endpoint of an ID.
func FindProfileEndpoint(id string) (ProfileEndpoint, bool) {
	for _, e := range JVMDiagnostics {
		if e.ID == id {
			return e, true
		}
	}
	for _, f := range ProfileFamilies {
		for _, e := range f.Endpoints {
			if e.ID == id {
				return e, true
			}
		}
	}
	return ProfileEndpoint{}, false
}

// ProfileTarget is one endpoint on a port of the pod, or one diagnostic of
// the JVM in a container of the pod: found there, or to fetch from there.
type ProfileTarget struct {
	Port      int    `json:"port,omitempty"`
	Container string `json:"container,omitempty"`
	ProfileEndpoint
}

// ProfileTargets returns what a pprof recording fetches. Its "endpoints"
// parameter lists catalog endpoints as "<port>/<id>", and diagnostics of a
// JVM as "<container>/<id>", separated by commas.
// Instead of it, "port" and "path" name an endpoint that the catalog does
// not know; that one counts as sensitive, because it can return anything,
// and as running for the time frame, so that it is bounded by it.
func (rec Recording) ProfileTargets() ([]ProfileTarget, error) {
	list, path := rec.Params["endpoints"], rec.Params["path"]
	switch {
	case list != "" && (path != "" || rec.Params["port"] != ""):
		return nil, fmt.Errorf("pprof takes either endpoints, or port and path")
	case list == "" && (path == "" || rec.Params["port"] == ""):
		return nil, fmt.Errorf("pprof needs endpoints (<port>/<endpoint>, from the profile endpoints of the workload), or port and path")
	case list == "":
		port, _ := strconv.Atoi(rec.Params["port"])
		return []ProfileTarget{{Port: port, ProfileEndpoint: ProfileEndpoint{ID: "custom", Name: "Endpoint " + path, Path: path, Timed: true, Sensitive: true, File: "profile.out"}}}, nil
	}
	var targets []ProfileTarget
	ports, containers := map[int]bool{}, map[string]bool{}
	for _, item := range strings.Split(list, ",") {
		// The endpoint tells whether a port or a container precedes it.
		where, id, _ := strings.Cut(item, "/")
		endpoint, known := FindProfileEndpoint(id)
		target := ProfileTarget{ProfileEndpoint: endpoint}
		if endpoint.Attach {
			target.Container, known = where, known && ValidName(where)
			containers[where] = true
		} else {
			port, err := strconv.Atoi(where)
			target.Port, known = port, known && err == nil && port >= 1 && port <= 65535
			ports[port] = true
		}
		if !known {
			return nil, fmt.Errorf("unknown profile endpoint %q", item)
		}
		for _, t := range targets {
			if t.Port == target.Port && t.Container == target.Container && t.ID == id {
				return nil, fmt.Errorf("profile endpoint %q is requested twice", item)
			}
		}
		targets = append(targets, target)
	}
	// The same endpoint on two ports, or of two containers, would write the
	// same file.
	for i, t := range targets {
		switch {
		case t.Attach && len(containers) > 1:
			targets[i].File = t.Container + "-" + t.File
		case !t.Attach && len(ports) > 1:
			targets[i].File = strconv.Itoa(t.Port) + "-" + t.File
		}
	}
	return targets, nil
}
