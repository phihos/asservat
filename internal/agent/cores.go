package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// Cores of crashed processes. The kernel pipes the core of every process
// that dies of a fatal signal on the node to one program, named by the
// sysctl kernel.core_pattern. With the core handler enabled, the agent
// points it at a copy of this binary in the spool directory, which exists at
// the same path on the node and in the agent's container. The handler keeps
// the core only if the process belongs to a pod that an approved core dump
// watch marked; the agent uploads it with the capture of that crash.

// CoreSpool is the spool directory.
type CoreSpool string

func (s CoreSpool) handler() string { return filepath.Join(string(s), "asservat") }

// marker names the file that makes the handler keep the cores of a pod, for
// one watch.
func (s CoreSpool) marker(podUID, watch string) string {
	return filepath.Join(string(s), "watched", podUID+"."+watch)
}

func (s CoreSpool) cores(podUID string) string { return filepath.Join(string(s), "cores", podUID) }

// taken holds the cores of one crash report until its capture uploads them.
func (s CoreSpool) taken(trigger string) string { return filepath.Join(string(s), "taken", trigger) }

// Install copies the running binary into the spool and makes it the node's
// core handler. The returned function restores the previous settings. While the
// agent's handler is installed, processes outside of watched pods leave no
// core.
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
	binary, err := os.ReadFile(self)
	if err != nil {
		return nil, err
	}
	// Rename over the old copy: the kernel may be running it.
	if err := os.WriteFile(s.handler()+".new", binary, 0o700); err != nil {
		return nil, err
	}
	if err := os.Rename(s.handler()+".new", s.handler()); err != nil {
		return nil, err
	}
	// %P is the process ID on the node, %t the time of the dump.
	pattern := "|" + s.handler() + " core-handler %P %t"
	saved := filepath.Join(string(s), "previous-core-pattern")
	current, err := os.ReadFile(patternFile)
	if err != nil {
		return nil, err
	}
	previous := strings.TrimSpace(string(current))
	if previous == pattern {
		// An agent that ended without restoring: the pattern before it is saved.
		b, err := os.ReadFile(saved)
		if err != nil {
			return nil, err
		}
		previous = string(b)
	} else if err := os.WriteFile(saved, []byte(previous), 0o600); err != nil {
		return nil, err
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
// belongs to a watched pod, replacing an earlier core of the same container.
func (s CoreSpool) Handle(proc, pid, at string, core io.Reader) error {
	cgroup, err := os.ReadFile(filepath.Join(proc, pid, "cgroup"))
	if err != nil {
		return err
	}
	podUID, container := cgroupPod(string(cgroup))
	if watched, _ := filepath.Glob(s.marker(podUID, "*")); podUID == "" || len(watched) == 0 {
		return nil
	}
	dir := s.cores(podUID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	earlier, _ := filepath.Glob(filepath.Join(dir, container+".*"))
	for _, name := range earlier {
		os.Remove(name)
	}
	name := filepath.Join(dir, container+"."+pid+"."+at)
	f, err := os.OpenFile(name+".part", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(name + ".part")
	defer f.Close()
	for {
		var fs syscall.Statfs_t
		if err := syscall.Statfs(dir, &fs); err != nil {
			return err
		}
		if fs.Bavail*100 < fs.Blocks*minFreePercent {
			return errors.New("core dropped: the node's disk is nearly full")
		}
		if _, err := io.CopyN(f, core, 64<<20); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name+".part", name+".core")
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
// kubelet reports the container as terminated, and no event tells when it
// has. So this looks again while the handler writes, and for a few seconds
// for a core to appear at all.
func (s CoreSpool) take(podUID, trigger string) {
	dir := s.cores(podUID)
	for started := time.Now(); ; time.Sleep(200 * time.Millisecond) {
		parts, _ := filepath.Glob(filepath.Join(dir, "*.part"))
		cores, _ := filepath.Glob(filepath.Join(dir, "*.core"))
		waited := time.Since(started)
		if len(parts) == 0 && (len(cores) > 0 || waited > 5*time.Second) || waited > time.Minute {
			break
		}
	}
	cores, _ := filepath.Glob(filepath.Join(dir, "*.core"))
	if len(cores) == 0 {
		return
	}
	os.MkdirAll(s.taken(trigger), 0o700)
	for _, file := range cores {
		os.Rename(file, filepath.Join(s.taken(trigger), filepath.Base(file)))
	}
}

// crashCores uploads the cores that were set aside for a crash report and
// removes them from the node, also if the upload fails.
func (a *Agent) crashCores(pod *corev1.Pod, trigger string, up func(string, io.Reader) error) error {
	if a.Cores == "" {
		return errors.New("this node's agent runs without the core handler (agent.coreHandler.enabled)")
	}
	dir := a.Cores.taken(trigger)
	defer os.RemoveAll(dir)
	names := map[string]string{}
	for _, status := range append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
		for _, id := range []string{status.ContainerID, terminatedID(status.State), terminatedID(status.LastTerminationState)} {
			_, id, _ = strings.Cut(id, "://")
			names[id] = status.Name
		}
	}
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
		err = up("core."+container+"."+parts[1], f)
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func terminatedID(s corev1.ContainerState) string {
	if s.Terminated == nil {
		return ""
	}
	return s.Terminated.ContainerID
}
