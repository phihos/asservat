package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"

	"asservat.local/asservat/internal/api"

	"asservat.local/asservat/internal/coredesc"
)

// Cores of crashed processes. The kernel pipes the core of every process
// that dies of a fatal signal on the node to one program, named by the
// sysctl kernel.core_pattern. With the core handler enabled, the agent
// points it at a copy of this binary in the spool directory, which exists at
// the same path on the node and in the agent's container. The handler keeps
// the core only if the process belongs to a pod that an approved core dump
// watch marked; the agent uploads it with the capture of that crash. Every
// other core it passes on to the program that the node's pattern named
// before, such as apport or systemd-coredump (passOn).

// CoreSpool is the spool directory.
type CoreSpool string

func (s CoreSpool) handler() string { return filepath.Join(string(s), "asservat") }

// previous names the file that holds the node's core pattern from before
// the agent's.
func (s CoreSpool) previous() string { return filepath.Join(string(s), "previous-core-pattern") }

// corePatternMost is the longest core pattern that the kernel takes
// (Documentation/admin-guide/sysctl/kernel.rst).
const corePatternMost = 127

// A value that a core pattern asks the kernel for: %p, %E. %% is a
// percent sign.
var coreSpecifier = regexp.MustCompile(`%.`)

// asked lists the values that the pattern of a handler asks the kernel
// for, in their order; nil for a pattern that names a file.
func asked(pattern string) []string {
	if !strings.HasPrefix(pattern, "|") {
		return nil
	}
	var specifiers []string
	for _, s := range coreSpecifier.FindAllString(pattern, -1) {
		if s != "%%" {
			specifiers = append(specifiers, s)
		}
	}
	return specifiers
}

// marker names the file that makes the handler keep the cores of a pod, for
// one watch.
func (s CoreSpool) marker(podUID, watch string) string {
	return filepath.Join(string(s), "watched", podUID+"."+watch)
}

func (s CoreSpool) cores(podUID string) string { return filepath.Join(string(s), "cores", podUID) }

// taken holds the cores of one crash report until its capture uploads them.
func (s CoreSpool) taken(trigger string) string { return filepath.Join(string(s), "taken", trigger) }

// Install copies the running binary into the spool and makes it the node's
// core handler. The returned function restores the previous settings. The
// pattern also asks the kernel for the values that the node's handler from
// before takes, which the agent's handler passes on with the cores that it
// does not keep. Where the node wrote cores to files, processes outside of
// watched pods leave no core while the agent's handler is installed.
func (s CoreSpool) Install(patternFile string) (restore func(), err error) {
	for _, dir := range []string{"watched", "cores", "taken"} {
		// Markers and cores of an earlier run are stale.
		if err := os.RemoveAll(filepath.Join(string(s), dir)); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Join(string(s), dir), 0o700); err != nil {
			return nil, err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// Rename over the old copy: the kernel may be running it.
	if err := copyFile(self, s.handler()+".new", 0o700); err != nil {
		return nil, err
	}
	if err := os.Rename(s.handler()+".new", s.handler()); err != nil {
		return nil, err
	}
	// %P is the process ID on the node, %t the time of the dump.
	pattern := "|" + s.handler() + " core-handler %P %t"
	saved := s.previous()
	current, err := os.ReadFile(patternFile)
	if err != nil {
		return nil, err
	}
	previous := strings.TrimSpace(string(current))
	if strings.HasPrefix(previous, pattern) {
		// An agent that ended without restoring: the pattern before it is saved.
		b, err := os.ReadFile(saved)
		if err != nil {
			return nil, err
		}
		previous = string(b)
	} else if err := os.WriteFile(saved, []byte(previous), 0o600); err != nil {
		return nil, err
	}
	// The kernel puts each value in an argument of its own, also an empty
	// one and one with spaces, since Linux 5.3.
	if passing := strings.Join(append([]string{pattern}, asked(previous)...), " "); len(passing) <= corePatternMost {
		pattern = passing
	} else if strings.HasPrefix(previous, "|") {
		slog.Warn("the node's core handler takes more than fits behind the agent's in a core pattern: it gets no cores while the agent runs", "pattern", previous)
	}
	if err := os.WriteFile(patternFile, []byte(pattern), 0o644); err != nil {
		return nil, fmt.Errorf("set the core pattern: %w", err)
	}
	// With a limit of 0 the kernel does not wait for the handler, and the
	// crashed process may be gone from /proc before the handler has read
	// which pod it belongs to. 16 is systemd's setting.
	limitFile := filepath.Join(filepath.Dir(patternFile), "core_pipe_limit")
	limit, err := os.ReadFile(limitFile)
	if err != nil {
		return nil, err
	}
	unlimited := strings.TrimSpace(string(limit)) == "0"
	if unlimited {
		if err := os.WriteFile(limitFile, []byte("16"), 0o644); err != nil {
			return nil, fmt.Errorf("set the core pipe limit: %w", err)
		}
	}
	return func() {
		os.WriteFile(patternFile, []byte(previous), 0o644)
		if unlimited {
			os.WriteFile(limitFile, []byte("0"), 0o644)
		}
	}, nil
}

var (
	podCgroup       = regexp.MustCompile(`pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)
	containerCgroup = regexp.MustCompile(`[0-9a-f]{64}`)
)

// cgroupPod returns the pod UID and container ID in a process's cgroup
// file, or empty strings for a process outside of pods.
func cgroupPod(cgroup string) (podUID, container string) {
	m := podCgroup.FindStringSubmatch(cgroup)
	ids := containerCgroup.FindAllString(cgroup, -1)
	if m == nil || len(ids) == 0 {
		return "", ""
	}
	// The systemd cgroup driver writes the UID with underscores.
	return strings.ReplaceAll(m[1], "_", "-"), ids[len(ids)-1]
}

// minFreePercent is the free space below which the handler stops writing a
// core. It is the kubelet's default threshold for evicting pods from a node
// (nodefs.available<10%), which a core must not trigger.
const minFreePercent = 10

// Handle is the core handler: the kernel runs it on the node with the core
// of process pid on standard input. It keeps the core if the process
// belongs to a watched pod, replacing an earlier core of the same
// container, and says what it did. values are what the kernel put for the
// values that the node's previous handler takes, which gets the other
// cores.
func (s CoreSpool) Handle(proc, pid, at string, core io.Reader, values ...string) (outcome string, err error) {
	cgroup, err := os.ReadFile(filepath.Join(proc, pid, "cgroup"))
	if err != nil {
		return s.passOn("the process was gone before its pod was read ("+err.Error()+")", core, values), nil
	}
	podUID, container := cgroupPod(string(cgroup))
	if podUID == "" {
		return s.passOn("not a process of a pod", core, values), nil
	}
	if watched, _ := filepath.Glob(s.marker(podUID, "*")); len(watched) == 0 {
		return s.passOn("no core dump watch for pod "+podUID, core, values), nil
	}
	dir := s.cores(podUID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// Only finished ones: another process of the container may be dumping.
	earlier, _ := filepath.Glob(filepath.Join(dir, container+".*.core"))
	for _, name := range earlier {
		os.Remove(name)
	}
	// And the program's files of earlier cores, also of one that was
	// never finished.
	kept, _ := filepath.Glob(filepath.Join(dir, container+".*"+programFiles))
	for _, name := range kept {
		os.Remove(name)
	}
	name := filepath.Join(dir, container+"."+pid+"."+at)
	f, err := os.OpenFile(name+".part", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	defer os.Remove(name + ".part")
	defer f.Close()
	for {
		var fs syscall.Statfs_t
		if err := syscall.Statfs(dir, &fs); err != nil {
			return "", err
		}
		if fs.Bavail*100 < fs.Blocks*minFreePercent {
			return "dropped, the node's disk is nearly full", nil
		}
		if _, err := io.CopyN(f, core, 64<<20); err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	// The crashed process is still there while its core is handed over,
	// and with it its container's files; when the agent comes to describe
	// the core, both are gone, and the container's next instance may not
	// run yet. The program's files that the core maps are kept now, for
	// the description and with the core. Without them the core stands.
	if err := keepProgramFiles(name+".part", filepath.Join(proc, pid, "root"), name+programFiles); err != nil {
		outcome = ", without the program's files: " + err.Error()
	}
	return "kept for pod " + podUID + outcome, os.Rename(name+".part", name+".core")
}

// passOn runs the node's handler from before the agent's with a core that
// the agent does not keep, as the kernel would have: the handler's pattern
// with the kernel's values in it, the core on standard input. Where there
// was none, or this handler was not given the values, the core is dropped.
// It says what became of the core, which was not kept for the reason.
func (s CoreSpool) passOn(reason string, core io.Reader, values []string) string {
	pattern, _ := os.ReadFile(s.previous())
	previous := strings.TrimSpace(string(pattern))
	if !strings.HasPrefix(previous, "|") || len(values) != len(asked(previous)) {
		return "dropped, " + reason
	}
	// The kernel splits a pattern into arguments before it puts the values in.
	command := strings.Fields(previous[1:])
	if len(command) == 0 {
		return "dropped, " + reason
	}
	// A process as a file (%F) is open in this handler under the number
	// that the kernel names, and stays so in the node's handler.
	var files []*os.File
	for i := range command {
		command[i] = coreSpecifier.ReplaceAllStringFunc(command[i], func(specifier string) string {
			if specifier == "%%" {
				return "%"
			}
			value := values[0]
			values = values[1:]
			if n, err := strconv.Atoi(value); specifier == "%F" && err == nil && n > 2 {
				for len(files) < n-2 {
					files = append(files, nil)
				}
				files[n-3] = os.NewFile(uintptr(n), "process")
			}
			return value
		})
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin, cmd.ExtraFiles = core, files
	if err := cmd.Run(); err != nil {
		return "passed on to " + command[0] + ", which failed (" + err.Error() + "), " + reason
	}
	return "passed on to " + command[0] + ", " + reason
}

// unmark stops keeping the pod's cores for a watch and removes those kept
// so far, unless another watch still wants them.
func (s CoreSpool) unmark(podUID, watch string) {
	os.Remove(s.marker(podUID, watch))
	if others, _ := filepath.Glob(s.marker(podUID, "*")); len(others) == 0 {
		os.RemoveAll(s.cores(podUID))
	}
}

// take sets the pod's cores aside for the capture of one crash report.
// The handler may not have finished, or even begun, the core when the
// kubelet reports the container as terminated. So this waits while the
// handler writes, and for a few seconds for a core to appear at all: a
// process that the kernel killed for its memory limit leaves none. The
// kernel tells when the handler begins a file, finishes it by renaming it,
// or gives it up. The wait ends after a minute at most, because the crash's
// report waits for it and the capture's other recordings for the report;
// a core that is finished later goes with the pod's next crash or watch.
func (s CoreSpool) take(podUID, trigger string) {
	dir := s.cores(podUID)
	// The handler makes the directory for the pod's first core. It is made
	// here to be watched from before that.
	os.MkdirAll(dir, 0o700)
	// Without a watch for the pod's cores the handler writes none: the
	// watch ended meanwhile, and the directory goes with it once it is
	// empty.
	defer func() {
		if watched, _ := filepath.Glob(s.marker(podUID, "*")); len(watched) == 0 {
			os.Remove(dir)
		}
	}()
	var changed <-chan struct{}
	if changes, err := watchDir(dir, syscall.IN_CREATE|syscall.IN_MOVED_TO|syscall.IN_DELETE); err == nil {
		defer changes.Close()
		changed = changes.happened
	} else {
		// The two times alone then say when to look again.
		slog.Warn("the core handler's directory is not watched", "error", err)
	}
	appear, most := time.After(5*time.Second), time.After(time.Minute)
	for waiting, late := true, false; waiting; {
		parts, _ := filepath.Glob(filepath.Join(dir, "*.part"))
		cores, _ := filepath.Glob(filepath.Join(dir, "*.core"))
		if len(parts) == 0 {
			// Another report may be quicker, as that of a second watch for
			// the pod. If the hub does not take that one, the cores come
			// back: so this goes on waiting for them, for the few seconds
			// that it waits for a core to appear at all.
			if len(s.setAside(cores, trigger)) > 0 || late {
				return
			}
		}
		select {
		case _, reports := <-changed:
			if !reports {
				changed = nil
			}
		case <-appear:
			late = true // no core will come if none is being written by now
		case <-most:
			waiting = false
		}
	}
	// The time is up: what is finished by now is taken.
	cores, _ := filepath.Glob(filepath.Join(dir, "*.core"))
	s.setAside(cores, trigger)
}

// setAside moves finished cores, each with the program's files that the
// handler kept with it, to where the capture of one report finds them, and
// returns those it moved: a core that another report took first is not
// among them.
func (s CoreSpool) setAside(cores []string, trigger string) (moved []string) {
	if len(cores) == 0 {
		return nil
	}
	os.MkdirAll(s.taken(trigger), 0o700)
	for _, file := range cores {
		if os.Rename(file, filepath.Join(s.taken(trigger), filepath.Base(file))) != nil {
			continue
		}
		moved = append(moved, file)
		kept := strings.TrimSuffix(file, ".core") + programFiles
		os.Rename(kept, filepath.Join(s.taken(trigger), filepath.Base(kept)))
	}
	if len(moved) == 0 {
		os.Remove(s.taken(trigger))
	}
	return moved
}

// giveBack returns the cores that were set aside for a report that the hub
// did not take to the pod's cores, where another watch for the pod finds
// them.
func (s CoreSpool) giveBack(podUID, trigger string) {
	dir := s.taken(trigger)
	defer os.RemoveAll(dir)
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(files) == 0 {
		return
	}
	// Only while a watch still wants the pod's cores: without one they go.
	if watched, _ := filepath.Glob(s.marker(podUID, "*")); len(watched) == 0 {
		return
	}
	os.MkdirAll(s.cores(podUID), 0o700)
	// The program's files first: a core is looked for by its own name, and
	// is found with them.
	slices.SortFunc(files, func(a, b string) int {
		return strings.Compare(strings.TrimSuffix(b, ".core"), strings.TrimSuffix(a, ".core"))
	})
	// A core that comes back waits its time anew before a watch records it
	// by itself: the report of a crash, which looks for it now, goes first.
	now := time.Now()
	for _, file := range files {
		os.Chtimes(file, now, now)
		os.Rename(file, filepath.Join(s.cores(podUID), filepath.Base(file)))
	}
}

// coreWaitsForCrash is how long a core that the handler kept waits for the
// kubelet to report its container as crashed, before the watch records it
// by itself. A container that ends with its process is reported within a
// second or two, and that report takes the core with the crash's other
// recordings. Nothing tells that a container will go on, so this is a time:
// long enough for the kubelet's report, short against what a core is for.
const coreWaitsForCrash = 10 * time.Second

// dumped has a core dump watch record a core that came without a crash: a
// process of the pod died and left one while its container goes on, as a
// worker that its parent starts again. The kubelet reports nothing then,
// and the core that the watch was approved for would rest on the node
// unread. The kernel tells when the handler has finished a core; if no
// crash's report has taken it after coreWaitsForCrash, the watch records
// with it. It ends with ctx.
func (a *Agent) dumped(agent, ctx context.Context, w api.Watch, pod *atomic.Pointer[corev1.Pod]) {
	dir := a.Cores.cores(string(pod.Load().UID))
	// The handler makes the directory for the pod's first core. It is made
	// here to be watched from before that.
	os.MkdirAll(dir, 0o700)
	changes, err := watchDir(dir, syscall.IN_MOVED_TO)
	if err != nil {
		slog.Warn("cores that come without a crash are not recorded for this pod", "pod", pod.Load().Name, "error", err)
		return
	}
	defer changes.Close()
	wait := a.coreWait
	if wait == 0 {
		wait = coreWaitsForCrash
	}
	// due is when the next of the cores that still wait has waited its time.
	var due <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case _, reports := <-changes.happened:
			if !reports {
				return
			}
		case <-due:
		}
		// Each core waits its own time: one that came a moment ago is not
		// taken with one that has waited, as its container may yet end.
		due = nil
		var waited []string
		var soonest time.Duration
		cores, _ := filepath.Glob(filepath.Join(dir, "*.core"))
		for _, file := range cores {
			info, err := os.Stat(file)
			if err != nil {
				continue // a crash's report took it
			}
			if left := wait - time.Since(info.ModTime()); left <= 0 {
				waited = append(waited, file)
			} else if soonest == 0 || left < soonest {
				soonest = left
			}
		}
		if soonest > 0 {
			due = time.After(soonest)
		}
		// Set aside before it is reported: of several watches for the pod,
		// the one that gets the core records, and the others say nothing.
		id := uuid.NewString()
		taken := a.Cores.setAside(waited, id)
		if len(taken) == 0 {
			continue
		}
		now := pod.Load()
		names := containerNames(now)
		var of []string
		for _, file := range taken {
			// "<container ID>.<pid>.<time>.core"
			if parts := strings.Split(filepath.Base(file), "."); len(parts) > 1 {
				name := names[parts[0]]
				if name == "" {
					name = fmt.Sprintf("%.12s", parts[0])
				}
				of = append(of, fmt.Sprintf("process %s of container %s", parts[1], name))
			}
		}
		if !a.tell(agent, w, now, id, strings.Join(of, ", ")+" left a core dump; its container goes on") {
			// The hub does not record for this watch: it has ended, and the
			// agent observes it a while longer. It looks at no more cores,
			// which are another watch's to record.
			return
		}
	}
}

// containerNames returns the names of a pod's containers by the IDs of
// their instances, the running and the last ended ones.
func containerNames(pod *corev1.Pod) map[string]string {
	names := map[string]string{}
	for _, status := range append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
		for _, id := range []string{status.ContainerID, terminatedID(status.State), terminatedID(status.LastTerminationState)} {
			_, id, _ = strings.Cut(id, "://")
			names[id] = status.Name
		}
	}
	return names
}

// crashCores uploads the cores that were set aside for a crash report and
// removes them from the node, also if the upload fails.
func (a *Agent) crashCores(ctx context.Context, pod *corev1.Pod, trigger string, known *processes, up func(string, io.Reader) error) error {
	if a.Cores == "" {
		return errors.New("this node's agent runs without the core handler (agent.coreHandler.enabled)")
	}
	dir := a.Cores.taken(trigger)
	defer os.RemoveAll(dir)
	names := containerNames(pod)
	files, _ := filepath.Glob(filepath.Join(dir, "*.core"))
	if len(files) == 0 {
		return errors.New("the crashed process left no core: it did not die of a signal that dumps core (a memory limit kills without one), or the node's disk is nearly full")
	}
	for _, file := range files {
		// "<container ID>.<pid>.<time>.core"
		parts := strings.Split(filepath.Base(file), ".")
		container := names[parts[0]]
		if container == "" {
			container = parts[0][:12]
		}
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		name := "core." + container + "." + parts[1]
		err = up(name, f)
		f.Close()
		if err != nil {
			return err
		}
		// The crashed process is gone. The handler kept the program's
		// files that its core maps; without them the container's next
		// instance, if it runs already, has the same image's files.
		root := ""
		if unpacked, err := a.keptProgramFiles(strings.TrimSuffix(file, ".core") + programFiles); err == nil {
			root = unpacked
			defer os.RemoveAll(unpacked)
		} else if pids, _, err := a.targets(pod, container, "", known); err == nil && len(pids) > 0 {
			root = "/proc/" + strconv.Itoa(pids[0]) + "/root"
		}
		a.describe(ctx, file, root, name, 0, up)
	}
	return nil
}

func terminatedID(s corev1.ContainerState) string {
	if s.Terminated == nil {
		return ""
	}
	return s.Terminated.ContainerID
}

// copyFile copies a file from one path to another without reading it into
// memory: the agent's program is some 90 MiB, which would stay as heap.
func copyFile(from, to string, mode os.FileMode) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}

// programFiles ends the name of the archive of a crash core's program
// files in the spool, next to the core.
const programFiles = ".files"

// keepProgramFiles writes the program files that a core maps, found under
// root, as an archive.
func keepProgramFiles(core, root, archive string) error {
	files := coredesc.Files(coredesc.Mapped(core), root)
	if len(files) == 0 {
		return errors.New("the core names none")
	}
	// Named as a part until it is whole: the agent waits for parts.
	f, err := os.OpenFile(archive+".part", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(archive + ".part")
	err = coredesc.WriteFiles(f, root, files)
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(archive+".part", archive)
}

// keptProgramFiles unpacks the archive that the handler kept with a crash
// core into a directory of the scratch space, which then stands for the
// crashed container's root.
func (a *Agent) keptProgramFiles(archive string) (string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(a.Scratch, "crashed-*")
	if err != nil {
		return "", err
	}
	if err := coredesc.ExtractFiles(f, dir, info.Size()); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}
