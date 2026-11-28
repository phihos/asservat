package coredesc

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A synthetic program that is busy in a function of its own, so that its
// stack needs no library to be read.
const busyProgram = `#include <stdio.h>
#include <sys/prctl.h>
volatile int stop;
__attribute__((noinline)) int handle_order(int order) {
	while (!stop);
	return order;
}
int main(void) {
	prctl(0x59616d61, -1UL, 0, 0, 0); /* lets the test's gcore, a sibling, attach */
	puts("ready"); fflush(stdout);
	return handle_order(7);
}
`

// The core of a stripped program of a distribution without a debuginfod
// server is described with files and lines from the distribution's debug
// package: an RPM found by the program's build ID in the repository's
// list, or Alpine's debug package of the package that owns the program.
func TestDebugPackages(t *testing.T) {
	for _, tool := range []string{"gcc", "objcopy", "gcore", "gdb", "bsdtar", "bsdcat"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", name, err, out)
		}
	}
	// The program as a distribution ships it: stripped, with a build ID
	// and the name of its debug file, which is in another package.
	os.WriteFile(filepath.Join(dir, "main.c"), []byte(busyProgram), 0o644)
	program := filepath.Join(dir, "app", "server")
	os.Mkdir(filepath.Dir(program), 0o755)
	run("gcc", "-g", "-O0", "-Wl,--build-id=0x00112233445566778899aabbccddeeff00112233", "-o", "server.full", "main.c")
	run("objcopy", "--only-keep-debug", "server.full", "server.debug")
	// The debug file carries a script for gdb, as debug files may
	// (.debug_gdb_scripts, here as Python text): it comes from a server,
	// and gdb runs as root on a node, so it is not run.
	ran := filepath.Join(dir, "the-debug-file's-script-ran")
	os.WriteFile(filepath.Join(dir, "script"), []byte("\x04from-the-debug-file\nopen("+strconv.Quote(ran)+", 'w').close()\n\x00"), 0o644)
	run("objcopy", "--add-section", ".debug_gdb_scripts=script", "--set-section-flags", ".debug_gdb_scripts=readonly", "server.debug")
	run("objcopy", "--strip-debug", "--add-gnu-debuglink=server.debug", "server.full", program)

	cmd := exec.Command(program)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("program said %q: %v", line, err)
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	if out, err := exec.Command("gcore", "-o", filepath.Join(dir, "core"), pid).CombinedOutput(); err != nil {
		t.Skipf("gcore cannot attach here: %v: %s", err, tail(out))
	}
	core := filepath.Join(dir, "core."+pid)
	if !slices.Contains(coreFiles(core), program) {
		t.Fatal("the program is not among the files that the core names:", coreFiles(core))
	}

	// The two packages: the debug file by its build ID in an RPM, by the
	// program's path in Alpine's package.
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	pack := func(name, format string) []byte {
		t.Helper()
		in := filepath.Join(dir, "in-"+format, filepath.Dir(name))
		os.MkdirAll(in, 0o755)
		run("cp", "server.debug", filepath.Join(in, filepath.Base(name)))
		out, err := exec.Command("bsdtar", "-c", "--format", format, "-f", "-", "-C", filepath.Join(dir, "in-"+format), "usr").Output()
		if err != nil {
			t.Fatal(err)
		}
		var packed bytes.Buffer
		w := gzip.NewWriter(&packed)
		w.Write(out)
		w.Close()
		return packed.Bytes()
	}
	// An RPM: its lead, a signature and a header, here both without
	// entries, then the files as a compressed cpio archive.
	lead := append([]byte{0xed, 0xab, 0xee, 0xdb, 3, 0}, make([]byte, 90)...)
	header := []byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	rpm := slices.Concat(lead, header, header, pack("usr/lib/debug/.build-id/00/112233445566778899aabbccddeeff00112233.debug", "newc"))
	apk := pack("usr/lib/debug"+program+".debug", "ustar")
	var list bytes.Buffer
	w := gzip.NewWriter(&list)
	fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="2">
<package type="rpm"><name>other-debuginfo</name><location href="Packages/other-debuginfo-1-1.rpm"/>
  <format><rpm:provides><rpm:entry name="debuginfo(build-id)" flags="EQ" epoch="0" ver="ffffffffffffffffffffffffffffffffffffffff"/></rpm:provides></format></package>
<package type="rpm"><name>server-debuginfo</name><location href="Packages/server-debuginfo-1-1.rpm"/>
  <format><rpm:provides><rpm:entry name="server-debuginfo" flags="EQ" epoch="0" ver="1" rel="1"/>
  <rpm:entry name="debuginfo(build-id)" flags="EQ" epoch="0" ver="00112233445566778899aabbccddeeff00112233"/></rpm:provides></format></package>
</metadata>`)
	w.Close()
	published := map[string][]byte{
		"/rpm/9.4/" + arch + "/repodata/repomd.xml": []byte(`<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision>
<data type="primary"><checksum type="sha256">abc</checksum><location href="repodata/abc-primary.xml.gz"/></data></repomd>`),
		"/rpm/9.4/" + arch + "/repodata/abc-primary.xml.gz":          list.Bytes(),
		"/rpm/9.4/" + arch + "/Packages/server-debuginfo-1-1.rpm":    rpm,
		"/alpine/v3.22/community/" + arch + "/orders-dbg-1.0-r2.apk": apk,
	}
	var asked []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		if content, ok := published[r.URL.Path]; ok {
			w.Write(content)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/broken/") {
			http.Error(w, "the mirror is out of order", http.StatusBadGateway)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	sources := &debugSources{
		// The first repository does not exist for the release.
		RPM:    map[string][]string{"rocky": {server.URL + "/none/{version}/{arch}/", server.URL + "/rpm/{version}/{arch}/"}},
		Alpine: server.URL + "/alpine",
	}

	// The container's root as the hub unpacks it: the program at its
	// path, and the files that name the distribution.
	root := func(t *testing.T, files map[string]string) string {
		root := t.TempDir()
		files[program] = ""
		for name, content := range files {
			os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o755)
			if name == program {
				run("cp", program, filepath.Join(root, name))
			} else if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}
	rocky := map[string]string{"/etc/os-release": "NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"9.4\"\n"}
	installed := "P:musl\nV:1.2.5-r10\nA:" + arch + "\no:musl\nF:lib\nR:ld-musl.so.1\n\n" +
		"P:orders-server\nV:1.0-r2\nA:" + arch + "\no:orders\nF:" + strings.TrimPrefix(filepath.Dir(program), "/") + "\nR:other\nR:server\n\n"
	alpine := map[string]string{"/etc/os-release": "ID=alpine\nVERSION_ID=3.22.1\n", "/lib/apk/db/installed": installed}
	// Where the frame of the program's function is, as the description says.
	describe := func(t *testing.T, d Describer, root string) (file string, report []byte) {
		t.Helper()
		report, err := d.Describe(context.Background(), core, root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(ran); err == nil {
			t.Fatal("gdb ran the script that the debug file carries")
		}
		var described struct {
			Threads []struct {
				Frames []struct {
					Function, File string
					Line           int
				}
			}
		}
		if err := json.Unmarshal(report, &described); err != nil {
			t.Fatal(err)
		}
		for _, thread := range described.Threads {
			for _, frame := range thread.Frames {
				if frame.Function == "handle_order" {
					return fmt.Sprint(frame.File, ":", frame.Line > 0), report
				}
			}
		}
		t.Fatalf("no frame of the program's function: %s", report)
		return "", nil
	}
	requests := func() []string {
		mu.Lock()
		defer mu.Unlock()
		defer func() { asked = nil }()
		// Not gdb's own, to the debuginfod server.
		return slices.DeleteFunc(asked, func(path string) bool { return strings.HasPrefix(path, "/buildid/") })
	}

	t.Run("RPM", func(t *testing.T) {
		d := Describer{Scratch: scratchDir(t), DebuginfodURLs: server.URL, sources: sources}
		root := root(t, rocky)
		at, report := describe(t, d, root)
		if !strings.HasSuffix(at, "main.c:true") {
			t.Fatalf("the function is at %q, asked %v", at, requests())
		}
		if asked := requests(); len(asked) != 4 {
			t.Fatal("asked", asked)
		}
		// The release is kept with the program's files, for the hub.
		if files := Files(report, root); !slices.Contains(files, "/etc/os-release") || !slices.Contains(files, program) {
			t.Fatal("kept", files)
		}
		// The next core finds the package and the repositories' lists in the cache.
		if at, _ := describe(t, d, root); !strings.HasSuffix(at, "main.c:true") {
			t.Fatalf("the function is at %q", at)
		}
		if asked := requests(); len(asked) != 0 {
			t.Fatal("asked again", asked)
		}
	})
	// A repository that fails does not take away what the one before it found.
	t.Run("RPM, with a later repository that fails", func(t *testing.T) {
		failing := &debugSources{RPM: map[string][]string{"rocky": {server.URL + "/rpm/{version}/{arch}/", server.URL + "/broken/{version}/{arch}/"}}, Alpine: sources.Alpine}
		d := Describer{Scratch: scratchDir(t), DebuginfodURLs: server.URL, sources: failing}
		if at, _ := describe(t, d, root(t, rocky)); !strings.HasSuffix(at, "main.c:true") {
			t.Fatalf("the function is at %q, asked %v", at, requests())
		}
		requests()
	})
	t.Run("Alpine", func(t *testing.T) {
		d := Describer{Scratch: scratchDir(t), DebuginfodURLs: server.URL, sources: sources}
		elsewhere := root(t, alpine)
		root := root(t, alpine)
		at, report := describe(t, d, root)
		if !strings.HasSuffix(at, "main.c:true") {
			t.Fatalf("the function is at %q, asked %v", at, requests())
		}
		// Not for musl, which the core does not map.
		if asked := requests(); !slices.Equal(asked, []string{"/alpine/v3.22/main/" + arch + "/orders-dbg-1.0-r2.apk", "/alpine/v3.22/community/" + arch + "/orders-dbg-1.0-r2.apk"}) {
			t.Fatal("asked", asked)
		}
		if files := Files(report, root); !slices.Contains(files, "/lib/apk/db/installed") {
			t.Fatal("kept", files)
		}
		// gdb looks for a debug file by the path of the program's file
		// after following its links. On a node that leads elsewhere than
		// in the container: the root is /proc/<pid>/root, and gdb follows
		// links such as /lib on the node. The debug file is found all
		// the same, by its build ID.
		dir := filepath.Join(elsewhere, filepath.Dir(program))
		if err := os.Rename(dir, filepath.Join(elsewhere, "moved")); err != nil {
			t.Fatal(err)
		}
		to, _ := filepath.Rel(filepath.Dir(dir), filepath.Join(elsewhere, "moved"))
		if err := os.Symlink(to, dir); err != nil {
			t.Fatal(err)
		}
		if at, _ := describe(t, Describer{Scratch: scratchDir(t), DebuginfodURLs: server.URL, sources: sources}, elsewhere); !strings.HasSuffix(at, "main.c:true") {
			t.Fatalf("with the program's directory a link, the function is at %q", at)
		}
		requests()
	})
	t.Run("a package that is not published", func(t *testing.T) {
		d := Describer{Scratch: scratchDir(t), DebuginfodURLs: server.URL, sources: sources}
		// An earlier revision than the mirror has, and the edge branch.
		older := map[string]string{"/etc/os-release": "ID=alpine\nVERSION_ID=3.23.0_alpha20250612\n", "/lib/apk/db/installed": strings.ReplaceAll(installed, "1.0-r2", "1.0-r1")}
		root := root(t, older)
		if at, _ := describe(t, d, root); at != ":false" {
			t.Fatalf("the function is at %q", at)
		}
		if asked := requests(); !slices.Equal(asked, []string{"/alpine/edge/main/" + arch + "/orders-dbg-1.0-r1.apk", "/alpine/edge/community/" + arch + "/orders-dbg-1.0-r1.apk"}) {
			t.Fatal("asked", asked)
		}
		// It is not asked for with every core.
		describe(t, d, root)
		if asked := requests(); len(asked) != 0 {
			t.Fatal("asked again", asked)
		}
		// Nor is a build ID that no repository lists.
		unknown := root
		os.WriteFile(filepath.Join(unknown, "etc/os-release"), []byte("ID=rocky\nVERSION_ID=8.10\n"), 0o644)
		if at, _ := describe(t, d, unknown); at != ":false" {
			t.Fatalf("the function is at %q", at)
		}
		if asked := requests(); len(asked) != 2 {
			t.Fatal("asked", asked)
		}
	})
	// A debuginfod server has the debug file by the build ID alone, whatever
	// the distribution. One that neither answers nor closes, as Ubuntu's
	// was seen to for minutes, is given up and holds nothing up for long.
	t.Run("debuginfod", func(t *testing.T) {
		debug, err := os.ReadFile(filepath.Join(dir, "server.debug"))
		if err != nil {
			t.Fatal(err)
		}
		release := make(chan struct{})
		silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		defer silent.Close()
		defer close(release)
		knows := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/buildid/00112233445566778899aabbccddeeff00112233/debuginfo" {
				w.Write(debug)
				return
			}
			http.NotFound(w, r)
		}))
		defer knows.Close()
		d := Describer{Scratch: scratchDir(t), DebuginfodURLs: silent.URL + " " + knows.URL + "/", sources: sources, wait: 300 * time.Millisecond}
		began := time.Now()
		if at, _ := describe(t, d, root(t, map[string]string{})); !strings.HasSuffix(at, "main.c:true") {
			t.Fatalf("the function is at %q", at)
		}
		if took := time.Since(began); took > 10*time.Second {
			t.Fatal("a silent server held the description up for", took)
		}
		// What a server did not answer for is not taken as unknown: asked
		// again, with only the silent server, it is asked for again.
		lone := Describer{Scratch: scratchDir(t), DebuginfodURLs: silent.URL, sources: sources, wait: 300 * time.Millisecond}
		describe(t, lone, root(t, map[string]string{}))
		if _, err := os.Stat(filepath.Join(lone.Scratch, "debuginfo/.build-id/00/112233445566778899aabbccddeeff00112233.debug")); err == nil {
			t.Fatal("a file that the server did not answer for is remembered as unknown")
		}
		requests()
	})
	t.Run("nothing is fetched without debuginfod servers", func(t *testing.T) {
		for _, files := range []map[string]string{rocky, alpine} {
			if at, _ := describe(t, Describer{Scratch: scratchDir(t), sources: sources}, root(t, files)); at != ":false" {
				t.Fatalf("the function is at %q", at)
			}
		}
		if asked := requests(); len(asked) != 0 {
			t.Fatal("asked", asked)
		}
	})
}

// The release of a distribution is read as a shell reads it.
func TestOSRelease(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755)
	os.Mkdir(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "usr/lib/os-release"), []byte("NAME=\"Red Hat Enterprise Linux\"\n# a comment\nID=\"rhel\"\nVERSION_ID='9.5'\nPLATFORM_ID=platform:el9\n"), 0o644)
	// As most distributions have it: a link.
	os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc/os-release"))
	if release := osRelease(root); release["ID"] != "rhel" || release["VERSION_ID"] != "9.5" || release["PLATFORM_ID"] != "platform:el9" {
		t.Fatal(release)
	}
	if release := osRelease(t.TempDir()); len(release) != 0 {
		t.Fatal(release)
	}
}

// What a container says of itself reaches addresses and the cache's
// names only where it reads as a name or a version.
func TestOnlyPlainNamesFromTheContainer(t *testing.T) {
	for value, plain := range map[string]bool{
		"9.4": true, "2023": true, "rocky": true, "1.2.5-r4": true, "3.24.4": true, "x86_64": true, "openssl": true, "2.34-100.el9_4.2": true, "1:2.0+git~rc1": false,
		"": false, "../../etc": false, "9/../../x": false, ".hidden": false, "a b": false, "evil.example/x": false, "v?x=1": false,
	} {
		if plainName.MatchString(value) != plain {
			t.Errorf("%q plain: %v", value, !plain)
		}
	}
}

// A server on the internet at times resets a connection, does not answer
// one, or says that it cannot serve right now: the file is asked for a
// second time before the download counts as failed, and a server that
// fails twice is not asked a third time.
func TestADownloadIsAskedForAgainAfterAFailedConnection(t *testing.T) {
	for _, test := range []struct {
		name   string
		fails  int32
		served bool
		status int // what the server says while it fails; 0 for no answer at all
	}{{"once", 1, true, 0}, {"twice", 2, false, 0}, {"unavailable once", 1, true, http.StatusServiceUnavailable}, {"unavailable twice", 2, false, http.StatusServiceUnavailable}, {"too many requests once", 1, true, http.StatusTooManyRequests}} {
		t.Run(test.name, func(t *testing.T) {
			var asked atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if asked.Add(1) <= test.fails && test.status != 0 {
					w.WriteHeader(test.status) // as Microsoft's symbol server said on a bad day
					return
				}
				if asked.Load() <= test.fails {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					connection.Close() // no answer at all
					return
				}
				io.WriteString(w, "the file")
			}))
			defer server.Close()
			body, err := Describer{Scratch: t.TempDir()}.fetcher(context.Background(), "test").get(server.URL + "/file")
			if !test.served {
				if err == nil {
					body.Close()
					t.Fatal("a server that failed twice was asked again")
				}
				if asked.Load() != 2 {
					t.Fatalf("the server was asked %d times, want 2", asked.Load())
				}
				return
			}
			if err != nil {
				t.Fatalf("the file was not asked for again: %v", err)
			}
			defer body.Close()
			if got, _ := io.ReadAll(body); string(got) != "the file" {
				t.Fatalf("got %q", got)
			}
		})
	}
}

// An agent describes the cores of a capture at the same time, and the
// cores of one workload are of the same program: a debuginfod server is
// asked once for a build ID, not once by every core, and by all the cores
// together no more at a time than by one. A hundred cores at once made a
// public server refuse and reset connections.
func TestCoresDescribedTogetherAskADebuginfodServerOnce(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]int{}
	asking, most := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.Path]++
		asking++
		most = max(most, asking)
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		asking--
		mu.Unlock()
		if strings.Contains(r.URL.Path, "/aa0") {
			io.WriteString(w, "debug information")
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	files := map[string]string{}
	for i := range 12 {
		files[fmt.Sprintf("/lib/lib%d.so", i)] = fmt.Sprintf("aa%d%037d", i%2, i)
	}
	d := Describer{Scratch: t.TempDir()}
	var cores sync.WaitGroup
	for range 20 {
		cores.Go(func() {
			if _, found := debuginfo(d.fetcher(context.Background(), "debuginfo"), []string{server.URL}, files); len(found) != 12 {
				t.Error("found", found)
			}
		})
	}
	cores.Wait()
	if len(asked) != 12 {
		t.Fatalf("%d build IDs were asked for, want 12", len(asked))
	}
	for path, times := range asked {
		if times != 1 {
			t.Errorf("%s was asked for %d times", path, times)
		}
	}
	if most > 6 {
		t.Errorf("%d requests at a time", most)
	}
	// What was found is there for every core.
	_, found := debuginfo(d.fetcher(context.Background(), "debuginfo"), []string{server.URL}, files)
	have := 0
	for _, has := range found {
		if has {
			have++
		}
	}
	if have != 6 {
		t.Errorf("%d of the files have debug information, want 6", have)
	}
}

// A debuginfod server that fails is left alone by all the cores that are
// described together, not asked by each of them in its turn: a hundred
// cores would otherwise wait for it one after another.
func TestCoresDescribedTogetherLeaveAFailingDebuginfodServerAlone(t *testing.T) {
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	files := map[string]string{}
	for i := range 12 {
		files[fmt.Sprintf("/lib/lib%d.so", i)] = fmt.Sprintf("bb%038d", i)
	}
	d := Describer{Scratch: t.TempDir()}
	var cores sync.WaitGroup
	for range 20 {
		cores.Go(func() { debuginfo(d.fetcher(context.Background(), "debuginfo"), []string{server.URL}, files) })
	}
	cores.Wait()
	// Those that were asking when it first failed, and no one after them.
	if asked.Load() > debuginfodAskers {
		t.Fatalf("a failing server was asked %d times", asked.Load())
	}
}
