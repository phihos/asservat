package hub

import (
	"strings"
	"testing"
)

// A core is read over MCP as what a debugger shows first: why the process
// stopped, then the stacks of its program, those that are alike told once,
// then the machine's threads. Not the memory map, which the description
// begins with.
func TestCoreAsText(t *testing.T) {
	report := []byte(`{"commandLine":"/app/server --port 8080","executable":"/app/server","stopped":"Program terminated with signal SIGSEGV, Segmentation fault.","runtime":"go1.26.2","withoutDebugInfo":true,"describer":7,
 "mappings":[{"start":"0x1000","end":"0x2000","file":"/app/server"}],
 "modules":[{"file":"/lib/libc.so.6","symbols":true},{"file":"/lib/libx.so","symbols":false}],
 "goroutines":[
  {"id":1,"status":"chan receive","current":true,"threadSystemId":41,"frames":[{"level":0,"function":"runtime.gopark","file":"/go/src/runtime/proc.go","line":463},{"level":1,"function":"main.serve","file":"/src/main.go","line":20,"arguments":[{"name":"port","type":"int","value":"8080"}],"locals":[]}]},
  {"id":7,"status":"select","frames":[{"level":0,"function":"runtime.gopark","file":"/go/src/runtime/proc.go","line":463},{"level":1,"function":"main.worker","file":"/src/work.go","line":9}]},
  {"id":8,"status":"select","frames":[{"level":0,"function":"runtime.gopark","file":"/go/src/runtime/proc.go","line":463},{"level":1,"function":"main.worker","file":"/src/work.go","line":9}]},
  {"id":9,"status":"select","frames":[{"level":0,"function":"runtime.gopark","file":"/go/src/runtime/proc.go","line":463},{"level":1,"function":"main.worker","file":"/src/work.go","line":9}]}],
 "runtimeStacks":[{"runtime":"python","title":"Python threads","version":"3.13","threads":[{"id":1,"name":"","status":"Has the GIL","threadSystemId":41,"frames":[{"level":0,"function":"handle_request","file":"/app/app.py","line":8,"arguments":[],"locals":[{"name":"note","type":"","value":"\"synthetic\""}]}]}]}],
 "threads":[{"id":1,"systemId":41,"name":"server","current":true,"frames":[{"level":0,"function":"","pc":"0x0000000000401000","module":"/app/server","file":"","line":0},{"level":1,"function":"epoll_wait","scanned":true,"module":"/lib/libc.so.6","file":"","line":0}]}]}`)
	text := coreText(report)
	for _, want := range []string{
		"Program terminated with signal SIGSEGV, Segmentation fault.",
		"/app/server --port 8080",
		"go1.26.2, built without debug information: functions and lines, no variables",
		"Python threads 3.13 (1)",
		"thread 1 [Has the GIL] LWP 41\n  #0 handle_request /app/app.py:8\n       note = \"synthetic\"",
		"Goroutines (4)",
		"goroutine 1 [chan receive] LWP 41, the one the core selects\n  #0 runtime.gopark /go/src/runtime/proc.go:463\n  #1 main.serve /src/main.go:20\n       port = 8080",
		"3 goroutines [select]: 7, 8, 9\n  #0 runtime.gopark /go/src/runtime/proc.go:463\n  #1 main.worker /src/work.go:9",
		"Threads (1)",
		"thread 1 \"server\" LWP 41, the one the core selects\n  #0 0x0000000000401000 in /app/server\n  #1 epoll_wait in /lib/libc.so.6 (found by reading the stack)",
		"Without symbols: /lib/libx.so",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "0x1000") {
		t.Error("the text holds the memory map")
	}
	// What the program itself did comes before the machine's threads.
	if strings.Index(text, "Python threads") > strings.Index(text, "Goroutines (") || strings.Index(text, "Goroutines (") > strings.Index(text, "Threads (1)") {
		t.Error("the order of the stacks")
	}
}
