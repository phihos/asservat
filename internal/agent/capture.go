package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"asservat.local/asservat/internal/api"
)

// capture records one pod and uploads the resulting files.
func (a *Agent) capture(ctx context.Context, id string, t api.TaskAssignment) error {
	r := t.Request
	pod, err := a.Kube.CoreV1().Pods(r.Namespace).Get(ctx, t.Pod, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if pod.Spec.NodeName != a.Node {
		return fmt.Errorf("pod %s runs on node %s", t.Pod, pod.Spec.NodeName)
	}
	duration := time.Duration(r.DurationSeconds) * time.Second
	up := func(name string, body io.Reader) error { return a.upload(ctx, id, t.Pod, name, body) }
	switch r.Kind {
	case api.KindPodState:
		events, err := a.Kube.CoreV1().Events(r.Namespace).List(ctx, metav1.ListOptions{FieldSelector: "involvedObject.name=" + t.Pod})
		if err != nil {
			return err
		}
		pod.ManagedFields = nil
		for name, v := range map[string]any{"pod.json": pod, "events.json": events.Items} {
			b, _ := json.MarshalIndent(v, "", "  ")
			if err := up(name, bytes.NewReader(b)); err != nil {
				return err
			}
		}
		return nil
	case api.KindLogs:
		return a.logs(ctx, pod, r, duration, up)
	case api.KindPcap:
		pid, _, err := a.containerPID(pod, "")
		if err != nil {
			return err
		}
		// Headers only unless payload was requested (and approved).
		snap := "128"
		if r.Params["payload"] == "true" {
			snap = "0"
		}
		args := []string{"-t", strconv.Itoa(pid), "-n", "tcpdump", "-i", "any", "-U", "-s", snap, "-w", "-"}
		if f := r.Params["filter"]; f != "" {
			args = append(args, f)
		}
		return a.record(ctx, duration, "capture.pcap", up, "nsenter", args...)
	case api.KindStrace:
		pid, container, err := a.containerPID(pod, r.Params["container"])
		if err != nil {
			return err
		}
		// Buffer contents are omitted unless strings was requested (and approved).
		size := "0"
		if r.Params["strings"] == "true" {
			size = "256"
		}
		return a.record(ctx, duration, container+".strace", up, "strace", "-f", "-tt", "-T", "-s", size, "-p", strconv.Itoa(pid), "-o", "/dev/stdout")
	case api.KindPprof:
		pid, _, err := a.containerPID(pod, "")
		if err != nil {
			return err
		}
		path := r.Params["path"]
		if path == "" {
			path = "/debug/pprof/profile?seconds=" + strconv.Itoa(r.DurationSeconds)
		}
		// The request runs inside the pod's network namespace, so endpoints
		// bound to localhost work and no NetworkPolicy applies.
		ctx, cancel := context.WithTimeout(ctx, duration+30*time.Second)
		defer cancel()
		return a.record(ctx, 0, "profile.pprof", up, "nsenter", "-t", strconv.Itoa(pid), "-n", "curl", "-sS", "--fail", "http://127.0.0.1:"+r.Params["port"]+path)
	case api.KindCoredump:
		pid, container, err := a.containerPID(pod, r.Params["container"])
		if err != nil {
			return err
		}
		// gcore cannot write to a pipe: the core rests in the scratch
		// directory until it is uploaded.
		prefix := filepath.Join(a.Scratch, id+"-"+t.Pod)
		file := prefix + "." + strconv.Itoa(pid)
		defer os.Remove(file)
		if out, err := exec.CommandContext(ctx, "gcore", "-o", prefix, strconv.Itoa(pid)).CombinedOutput(); err != nil {
			return fmt.Errorf("gcore: %w: %s", err, tail(out))
		}
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		return up("core."+container, f)
	}
	return fmt.Errorf("unknown kind %q", r.Kind)
}

func (a *Agent) logs(ctx context.Context, pod *corev1.Pod, r api.CaptureRequest, duration time.Duration, up func(string, io.Reader) error) error {
	opts := corev1.PodLogOptions{Previous: r.Params["previous"] == "true", Follow: duration > 0, Timestamps: true}
	if v := r.Params["tailLines"]; v != "" {
		n, _ := strconv.ParseInt(v, 10, 64)
		opts.TailLines = &n
	}
	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}
	uploaded := 0
	for _, c := range pod.Spec.Containers {
		if want := r.Params["container"]; want != "" && want != c.Name {
			continue
		}
		o := opts
		o.Container = c.Name
		stream, err := a.Kube.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &o).Stream(ctx)
		if err != nil {
			if opts.Previous {
				continue // this container has not restarted
			}
			return err
		}
		// A followed stream ends with the duration; what arrived until then
		// is the result.
		err = up(c.Name+".log", untilDeadline{stream, ctx})
		stream.Close()
		if err != nil {
			return err
		}
		uploaded++
	}
	if uploaded == 0 {
		return errors.New("no container has such logs")
	}
	return nil
}

// untilDeadline turns the end of a bounded recording into a clean end of the
// stream.
type untilDeadline struct {
	r   io.Reader
	ctx context.Context
}

func (u untilDeadline) Read(p []byte) (int, error) {
	n, err := u.r.Read(p)
	if err != nil && errors.Is(u.ctx.Err(), context.DeadlineExceeded) {
		err = io.EOF
	}
	return n, err
}

// record runs a tool and uploads its standard output while it runs. With a
// duration, the tool is interrupted after it and its output up to then is
// the result.
func (a *Agent) record(ctx context.Context, duration time.Duration, name string, up func(string, io.Reader) error, tool string, args ...string) error {
	run := ctx
	if duration > 0 {
		var cancel context.CancelFunc
		run, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}
	cmd := exec.CommandContext(run, tool, args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGINT) } // lets the tool flush
	cmd.WaitDelay = 10 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	uploadErr := up(name, out)
	io.Copy(io.Discard, out)
	err = cmd.Wait()
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case uploadErr != nil:
		return uploadErr
	case err != nil && run.Err() == nil:
		return fmt.Errorf("%s: %w: %s", tool, err, tail(stderr.Bytes()))
	}
	return nil
}

func tail(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > 400 {
		b = b[len(b)-400:]
	}
	return string(b)
}

// containerPID returns the node PID of a container's main process. An empty
// name selects the pod's first container.
func (a *Agent) containerPID(pod *corev1.Pod, name string) (int, string, error) {
	if name == "" {
		name = pod.Spec.Containers[0].Name
	}
	for _, s := range pod.Status.ContainerStatuses {
		if s.Name != name {
			continue
		}
		_, id, ok := strings.Cut(s.ContainerID, "://")
		if !ok || s.State.Running == nil {
			return 0, name, fmt.Errorf("container %s is not running", name)
		}
		pid, err := mainPID(a.Proc, id)
		return pid, name, err
	}
	return 0, name, fmt.Errorf("pod %s has no container %s", pod.Name, name)
}

// mainPID finds a container's main process in the node's /proc: the oldest
// process in the container's cgroup whose parent is outside of it (an exec
// session also has such a parent, but started later).
func mainPID(proc, containerID string) (int, error) {
	inside := func(pid int) bool {
		b, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "cgroup"))
		return err == nil && bytes.Contains(b, []byte(containerID))
	}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return 0, err
	}
	found, oldest := 0, uint64(0)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !inside(pid) {
			continue
		}
		stat, err := os.ReadFile(filepath.Join(proc, e.Name(), "stat"))
		if err != nil {
			continue
		}
		// "pid (comm) state ppid ... starttime ..."; comm may contain spaces
		// and parentheses. After it, ppid is field 2 and starttime field 20.
		fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
		if len(fields) < 20 {
			continue
		}
		ppid, err1 := strconv.Atoi(fields[1])
		started, err2 := strconv.ParseUint(fields[19], 10, 64)
		if err1 == nil && err2 == nil && !inside(ppid) && (found == 0 || started < oldest) {
			found, oldest = pid, started
		}
	}
	if found == 0 {
		return 0, fmt.Errorf("no process of container %s found on this node", containerID)
	}
	return found, nil
}
