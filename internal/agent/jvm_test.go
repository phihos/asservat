package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"asservat.local/asservat/internal/api"
)

// standIn is a JVM as far as its attach socket goes: it opens the socket
// in its /tmp when it is signalled and finds the marker file, and answers
// the requests that Asservat makes.
type standIn struct {
	t        *testing.T
	tmp      string
	mu       sync.Mutex
	signals  int
	requests []string
	deaf     bool // never opens its socket
}

const standInPID = 7

func (s *standIn) client() attacher {
	return attacher{dir: s.tmp, pid: standInPID, wait: 10 * time.Second, quit: s.quit}
}

func (s *standIn) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// quit is the signal: the JVM looks for the marker and opens its socket.
func (s *standIn) quit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signals++; s.deaf || s.signals > 1 {
		return nil
	}
	if _, err := os.Stat(filepath.Join(s.tmp, ".attach_pid"+strconv.Itoa(standInPID))); err != nil {
		s.t.Errorf("signalled without the marker file: %v", err)
		return nil
	}
	// As a JVM does: a moment later.
	go func() {
		time.Sleep(20 * time.Millisecond)
		s.listen()
	}()
	return nil
}

func (s *standIn) listen() {
	// Through an open directory: the address of a socket holds 108 bytes.
	dir, err := os.Open(s.tmp)
	if err != nil {
		s.t.Fatal(err)
	}
	defer dir.Close()
	// A JVM makes its socket under another name and renames it.
	name := fmt.Sprintf("/proc/self/fd/%d/.java_pid%d", dir.Fd(), standInPID)
	l, err := net.Listen("unix", name+".tmp")
	if err == nil {
		l.(*net.UnixListener).SetUnlinkOnClose(false)
		err = os.Rename(name+".tmp", name)
	}
	if err != nil {
		s.t.Error(err)
		return
	}
	s.t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			s.answer(conn)
		}
	}()
}

func (s *standIn) answer(conn net.Conn) {
	defer conn.Close()
	// The version, the command and three arguments, each ended by a zero.
	var request []byte
	for b := make([]byte, 1); bytes.Count(request, []byte{0}) < 5; request = append(request, b[0]) {
		if _, err := conn.Read(b); err != nil {
			return
		}
	}
	s.mu.Lock()
	s.requests = append(s.requests, string(request))
	s.mu.Unlock()
	words := strings.Split(string(request), "\x00")
	if words[0] != "1" || words[1] != "jcmd" || words[3] != "" || words[4] != "" {
		fmt.Fprint(conn, "101\nOperation not recognized\n")
		return
	}
	write := func(argument, content string) {
		_, file, _ := strings.Cut(argument, "/tmp/")
		if err := os.WriteFile(filepath.Join(s.tmp, file), []byte(content), 0o600); err != nil {
			s.t.Error(err)
		}
	}
	command := strings.Fields(words[2])
	switch command[0] {
	case "Thread.print":
		fmt.Fprint(conn, "0\nFull thread dump\n\"asservat-courier-0\" #1\n")
	case "GC.class_histogram":
		fmt.Fprint(conn, "0\n num #instances #bytes class name\n")
	case "GC.heap_dump":
		write(command[1], "JAVA PROFILE 1.0.2\x00heap")
		fmt.Fprint(conn, "0\nHeap dump file created\n")
	case "JFR.start":
		fmt.Fprint(conn, "0\nStarted recording 1.\n")
	case "JFR.stop":
		write(command[2], "FLR\x00recording")
		fmt.Fprint(conn, "0\nStopped recording.\n")
	default:
		fmt.Fprint(conn, "-1\nUnknown diagnostic command\n")
	}
}

// left names what is in the JVM's /tmp but its socket.
func (s *standIn) left() []string {
	entries, _ := os.ReadDir(s.tmp)
	var names []string
	for _, e := range entries {
		if e.Name() != ".java_pid"+strconv.Itoa(standInPID) {
			names = append(names, e.Name())
		}
	}
	return names
}

func newStandIn(t *testing.T) *standIn {
	return &standIn{t: t, tmp: t.TempDir()}
}

// The marker file is there when the JVM is signalled and gone afterwards,
// and the request is the protocol's.
func TestJVMThreadDump(t *testing.T) {
	s := newStandIn(t)
	var out bytes.Buffer
	if err := s.client().run("jvm-threads", 0, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "asservat-courier-0") {
		t.Errorf("thread dump: %q", out.String())
	}
	if got := s.asked(); len(got) != 1 || got[0] != "1\x00jcmd\x00Thread.print -l\x00\x00\x00" {
		t.Errorf("requests: %q", got)
	}
	if left := s.left(); len(left) != 0 || s.signals != 1 {
		t.Errorf("left in /tmp: %v, signals: %d", left, s.signals)
	}
	// A JVM whose socket is open is not signalled again.
	out.Reset()
	if err := s.client().run("jvm-histogram", 0, strings.NewReader(""), &out); err != nil || !strings.Contains(out.String(), "#instances") || s.signals != 1 {
		t.Errorf("histogram: %q, %v, signals: %d", out.String(), err, s.signals)
	}
}

// Nothing but the catalog's diagnostics reaches a JVM: not the loading of
// an agent library, a changed flag or any other command of the socket.
func TestJVMRequestsAreListed(t *testing.T) {
	s := newStandIn(t)
	for _, request := range []string{"load", "setflag", "jcmd", "datadump", "jvm-recording-stop", "go-heap", "JVMTI.agent_load", ""} {
		if err := s.client().run(request, 0, strings.NewReader(""), io.Discard); err == nil || !strings.Contains(err.Error(), "nothing that Asservat asks") {
			t.Errorf("run(%q): %v", request, err)
		}
	}
	if s.signals != 0 || len(s.left()) != 0 {
		t.Errorf("a refused request signalled (%d) or wrote %v", s.signals, s.left())
	}
	s.listen()
	for _, request := range []string{"load", "setflag", "properties", "dumpheap"} {
		if _, err := s.client().ask(request, strings.NewReplacer()); err == nil {
			t.Errorf("ask(%q) was sent", request)
		}
	}
	if got := s.asked(); len(got) != 0 {
		t.Errorf("requests: %q", got)
	}
	// No request loads or changes anything.
	for name, request := range jvmRequests {
		command := strings.Fields(request[1])[0]
		if request[0] != "jcmd" || !map[string]bool{"Thread.print": true, "GC.class_histogram": true, "GC.heap_dump": true, "JFR.start": true, "JFR.stop": true}[command] {
			t.Errorf("request %s: %q", name, request)
		}
	}
}

type failing struct{}

func (failing) Write([]byte) (int, error) { return 0, errors.New("the pipe is closed") }

// The heap dump is in the container's /tmp only until it is read, also
// when reading it fails.
func TestJVMHeapDumpIsRemoved(t *testing.T) {
	s := newStandIn(t)
	var out bytes.Buffer
	if err := s.client().run("jvm-heapdump", 0, strings.NewReader(""), &out); err != nil || !strings.HasPrefix(out.String(), "JAVA PROFILE") {
		t.Fatalf("heap dump: %q, %v", out.String(), err)
	}
	if left := s.left(); len(left) != 0 {
		t.Errorf("left in /tmp: %v", left)
	}
	if err := s.client().run("jvm-heapdump", 0, strings.NewReader(""), failing{}); err == nil {
		t.Error("a heap dump that could not be handed on succeeded")
	}
	if left := s.left(); len(left) != 0 {
		t.Errorf("left in /tmp after a failure: %v", left)
	}
	asked := s.asked()
	if len(asked) != 2 || asked[0] == asked[1] || !strings.HasPrefix(asked[0], "1\x00jcmd\x00GC.heap_dump /tmp/asservat-") {
		t.Errorf("requests: %q", asked)
	}
}

// A flight recording runs until the time frame ends or it is stopped, and
// its file is removed.
func TestJVMRecording(t *testing.T) {
	s := newStandIn(t)
	stop, stopped := io.Pipe()
	go func() {
		for len(s.asked()) == 0 { // started
			time.Sleep(time.Millisecond)
		}
		stopped.Close()
	}()
	var out bytes.Buffer
	begun := time.Now()
	if err := s.client().run("jvm-recording", time.Hour, stop, &out); err != nil || !strings.HasPrefix(out.String(), "FLR") {
		t.Fatalf("recording: %q, %v", out.String(), err)
	}
	if time.Since(begun) > time.Minute {
		t.Error("the recording was not stopped early")
	}
	asked := s.asked()
	if len(asked) != 2 || !strings.Contains(asked[0], "JFR.start name=asservat-") || !strings.Contains(asked[0], " duration=3660s filename=/tmp/asservat-") || !strings.Contains(asked[1], "JFR.stop name=asservat-") {
		t.Errorf("requests: %q", asked)
	}
	if left := s.left(); len(left) != 0 {
		t.Errorf("left in /tmp: %v", left)
	}
	// Without a stop it ends with the time frame.
	out.Reset()
	never, _ := io.Pipe()
	if err := s.client().run("jvm-recording", 10*time.Millisecond, never, &out); err != nil || !strings.HasPrefix(out.String(), "FLR") {
		t.Errorf("recording for the time frame: %q, %v", out.String(), err)
	}
}

// A JVM that does not open its socket is waited for as long as the JDK's
// client waits, signalled twice, and the marker file is removed.
func TestJVMDoesNotAnswer(t *testing.T) {
	s := newStandIn(t)
	s.deaf = true
	c := s.client()
	c.wait = 100 * time.Millisecond
	err := c.run("jvm-threads", 0, strings.NewReader(""), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "did not open its attach socket") {
		t.Errorf("error: %v", err)
	}
	if left := s.left(); len(left) != 0 || s.signals != 2 {
		t.Errorf("left in /tmp: %v, signals: %d", left, s.signals)
	}
}

// A link in place of the socket or of the JVM's file is not followed.
func TestJVMLinksAreNotFollowed(t *testing.T) {
	s := newStandIn(t)
	elsewhere := filepath.Join(t.TempDir(), "socket")
	l, err := net.Listen("unix", elsewhere)
	if err != nil {
		t.Skip(err) // the path is too long for a socket here
	}
	defer l.Close()
	if err := os.Symlink(elsewhere, filepath.Join(s.tmp, ".java_pid"+strconv.Itoa(standInPID))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.client().ask("jvm-threads", strings.NewReplacer()); err == nil {
		t.Error("a link in place of the socket was followed")
	}
}

// The container's /tmp is opened within the container's root: a link to
// an absolute path leads to the container's directory of that name, and
// nothing is written outside of the root.
func TestJVMTmpIsTheContainers(t *testing.T) {
	root, node := t.TempDir(), t.TempDir()
	// The container's /tmp is a link to a path that is the node's
	// directory when the node follows it, and the container's own
	// directory within the container.
	inside := filepath.Join(root, node)
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(node, filepath.Join(root, "tmp")); err != nil {
		t.Fatal(err)
	}
	tmp, err := openInside(root, "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	s := &standIn{t: t, tmp: inside}
	c := s.client()
	c.dir = "/proc/self/fd/" + strconv.Itoa(int(tmp.Fd()))
	var out bytes.Buffer
	if err := c.run("jvm-heapdump", 0, strings.NewReader(""), &out); err != nil || !strings.HasPrefix(out.String(), "JAVA PROFILE") {
		t.Fatalf("heap dump: %q, %v", out.String(), err)
	}
	if entries, _ := os.ReadDir(node); len(entries) != 0 || s.signals != 1 {
		t.Errorf("written on the node: %v, signals: %d", entries, s.signals)
	}
	// Links that lead upwards stay within the root too.
	os.Remove(filepath.Join(root, "tmp"))
	if err := os.Symlink("../../../.."+node, filepath.Join(root, "tmp")); err != nil {
		t.Fatal(err)
	}
	up, err := openInside(root, "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	var a, b unix.Stat_t
	if unix.Fstat(int(up.Fd()), &a) != nil || unix.Stat(inside, &b) != nil || a.Ino != b.Ino || a.Dev != b.Dev {
		t.Error("a link upwards left the container's root")
	}
}

// fakeJVMProcess writes what findJVM reads of a process.
func fakeJVMProcess(t *testing.T, proc string, pid int, maps, caught, cmdline, environ string) {
	dir := filepath.Join(proc, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := "Name:\tjava\nUid:\t1000\t1001\t1001\t1001\nGid:\t2000\t2001\t2001\t2001\nNSpid:\t" + strconv.Itoa(pid) + "\t7\nSigIgn:\t0000000000000000\nSigCgt:\t" + caught + "\n"
	for name, content := range map[string]string{"maps": maps, "status": status, "cmdline": cmdline, "environ": environ} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Only a HotSpot JVM that handles SIGQUIT and may be attached to is ever
// signalled: everything else is told apart from the node's /proc.
func TestFindJVM(t *testing.T) {
	const (
		hotspot = "7f0000000000-7f0000001000 r--p 00000000 00:1f 1 /opt/java/openjdk/lib/server/libjvm.so\n7f0000001000-7f0000002000 r-xp 00001000 00:1f 1 /opt/java/openjdk/lib/server/libjvm.so\n"
		// SIGQUIT is signal 3: the third bit.
		catches, ignores = "2000000181005ccf", "2000000181005ccb"
	)
	proc := t.TempDir()
	fakeJVMProcess(t, proc, 100, hotspot, catches, "java\x00-jar\x00app.jar\x00", "PATH=/bin\x00")
	fakeJVMProcess(t, proc, 101, "55d000000000-55d000001000 r-xp 00000000 00:1f 2 /bin/busybox\n", catches, "sh\x00", "")
	fakeJVMProcess(t, proc, 102, hotspot+"7f0000003000-7f0000004000 r-xp 00000000 00:1f 3 /opt/java/openjdk/lib/default/libj9vm29.so\n", catches, "java\x00", "")
	fakeJVMProcess(t, proc, 103, hotspot, ignores, "java\x00-Xrs\x00", "")
	fakeJVMProcess(t, proc, 104, hotspot, catches, "java\x00-XX:+DisableAttachMechanism\x00Main\x00", "")
	fakeJVMProcess(t, proc, 105, hotspot, catches, "java\x00Main\x00", "HOME=/\x00JAVA_TOOL_OPTIONS=-Xmx1g -XX:+DisableAttachMechanism\x00")
	// The library's name in a path, or mapped as data only, makes no JVM.
	fakeJVMProcess(t, proc, 106, "7f0000000000-7f0000001000 r--p 00000000 00:1f 1 /data/libjvm.so\n7f0000001000-7f0000002000 r-xp 00000000 00:1f 1 /libjvm.so/program\n", catches, "program\x00", "")
	if j, err := findJVM(proc, 100); err != nil || j != (jvm{pid: 100, inner: 7, uid: 1001, gid: 2001}) {
		t.Errorf("a HotSpot JVM: %+v, %v", j, err)
	}
	for pid, want := range map[int]string{101: "", 106: "", 999: "", 102: "OpenJ9", 103: "does not handle SIGQUIT", 104: "DisableAttachMechanism", 105: "DisableAttachMechanism"} {
		_, err := findJVM(proc, pid)
		switch {
		case want == "" && err != errNoJVM:
			t.Errorf("process %d: %v", pid, err)
		case want != "" && (!errors.As(err, &notAskable{}) || !strings.Contains(err.Error(), want)):
			t.Errorf("process %d: %v, want %s", pid, err, want)
		}
	}
}

// The tests' own program stands in for the agent's when it is started
// again as a JVM's user.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "jvm-attach" {
		if err := AttachJVM(os.Args[2:], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// With ASSERVAT_TEST_JVM, the process ID of a HotSpot JVM that runs
// testdata/Blocked.java in a container, the diagnostics are asked of a
// real JVM as the agent asks them: by a child with the JVM's user, which
// this test must be or be allowed to become. The test signals that
// process. ASSERVAT_TEST_JVM_NO_JFR names a JVM without flight recorder.
func TestRealJVM(t *testing.T) {
	pid, err := strconv.Atoi(os.Getenv("ASSERVAT_TEST_JVM"))
	if err != nil {
		t.Skip("ASSERVAT_TEST_JVM names no JVM")
	}
	j, err := findJVM("/proc", pid)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	held := os.NewFile(uintptr(fd), "pidfd")
	defer held.Close()
	ask := func(id string, seconds int) []byte {
		t.Helper()
		var out bytes.Buffer
		endpoint, _ := api.FindProfileEndpoint(id)
		err := attachAs(t.Context(), t.Context(), "/proc", j, held, api.ProfileTarget{ProfileEndpoint: endpoint}, seconds, func(name string, r io.Reader) error {
			_, err := io.Copy(&out, r)
			return err
		})
		if err != nil {
			t.Errorf("%s: %v", id, err)
		}
		// Nothing of it stays in the container.
		entries, _ := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "root", "tmp"))
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "asservat-") || strings.HasPrefix(e.Name(), ".attach_pid") {
				t.Errorf("left in the container's /tmp after %s: %s", id, e.Name())
			}
		}
		return out.Bytes()
	}
	excerpt := func(b []byte, lines int) string {
		all := strings.SplitN(string(b), "\n", lines+1)
		return strings.Join(all[:min(lines, len(all))], "\n")
	}
	t.Logf("the JVM runs as user %d, group %d; this test as %d, %d", j.uid, j.gid, os.Geteuid(), os.Getegid())
	threads := ask("jvm-threads", 0)
	if !bytes.Contains(threads, []byte(`"asservat-courier-2"`)) || !bytes.Contains(threads, []byte("Blocked.waitForParcel")) {
		t.Errorf("the thread dump names neither the program's threads nor their method")
	}
	t.Logf("thread dump, %d bytes:\n%s", len(threads), excerpt(threads, 3))
	histogram := ask("jvm-histogram", 0)
	if !bytes.Contains(histogram, []byte("Blocked$Parcel")) {
		t.Errorf("the histogram does not name the program's class")
	}
	t.Logf("class histogram, %d bytes:\n%s", len(histogram), excerpt(histogram, 5))
	heap := ask("jvm-heapdump", 0)
	if !bytes.HasPrefix(heap, []byte("JAVA PROFILE 1.0.")) {
		t.Errorf("the heap dump begins with %q", heap[:min(len(heap), 20)])
	}
	t.Logf("heap dump, %d bytes, begins with %q", len(heap), heap[:min(len(heap), 18)])
	if os.Getenv("ASSERVAT_TEST_JVM_NO_JFR") != "" {
		return
	}
	recording := ask("jvm-recording", 3)
	if !bytes.HasPrefix(recording, []byte("FLR\x00")) {
		t.Errorf("the flight recording begins with %q", recording[:min(len(recording), 8)])
	}
	t.Logf("flight recording, %d bytes", len(recording))
}
