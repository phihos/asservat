package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"

	"golang.org/x/sys/unix"

	"asservat.local/asservat/internal/api"
)

// A HotSpot JVM answers diagnostic commands over a socket in its /tmp, the
// attach mechanism that jcmd and jstack use. It opens the socket when it
// finds a marker file there and receives SIGQUIT. Asservat asks over it
// for the diagnostics of the catalog (api.JVMDiagnostics) and for nothing
// else: the socket would also load agent libraries into the JVM and change
// its flags, and no request of this file can name those.
//
// The JVM takes requests only from a process with its own user and group
// (JDK 8; later ones also from root), and the marker file must be that
// user's. So the agent starts itself again as that user ("asservat
// jvm-attach"), which Go cannot become in one goroutine. As another user
// than the agent's that child has no capabilities. It is handed the
// container's /tmp and the JVM as open files, and works in the first and
// signals the second only.

// jvmRequests is every request that Asservat makes of a JVM, as the words
// of the attach protocol's command and its first argument. "{file}" is
// the file that the JVM writes in its /tmp, "{name}" names a flight
// recording and "{seconds}" bounds one.
var jvmRequests = map[string][2]string{
	"jvm-threads":   {"jcmd", "Thread.print -l"},
	"jvm-histogram": {"jcmd", "GC.class_histogram"},
	"jvm-heapdump":  {"jcmd", "GC.heap_dump /tmp/{file}"},
	// The JVM ends a recording by itself a minute after the time frame,
	// should nobody come to stop it.
	"jvm-recording":      {"jcmd", "JFR.start name={name} duration={seconds}s filename=/tmp/{file}"},
	"jvm-recording-stop": {"jcmd", "JFR.stop name={name} filename=/tmp/{file}"},
}

// attachWait is how long a JVM is given to open its socket after the
// signal: as long as the JDK's own client waits (10 seconds,
// sun.tools.attach.attachTimeout). It signals a second time after half of
// it, as that client does, for a JVM that was not ready for the first.
const attachWait = 10 * time.Second

// errNoJVM tells that a process is no HotSpot JVM.
var errNoJVM = errors.New("no HotSpot JVM")

// notAskable is why a JVM cannot be asked.
type notAskable struct{ error }

// jvm is a HotSpot JVM that can be asked.
type jvm struct {
	pid   int // on the node
	inner int // inside its own PID namespace, by which it names its socket
	// The user and group that it runs as, which it demands of who asks.
	uid, gid uint32
}

// findJVM tells whether a process of the node is a HotSpot JVM that can be
// asked, from its files in /proc: errNoJVM if it is none, another error
// if it is a JVM that cannot be asked.
//
// This check is the safety of the whole feature. SIGQUIT ends a process
// that does not handle it, so it goes only to a process that has
// HotSpot's libjvm.so mapped as code, has none of OpenJ9's libraries
// (OpenJ9 ships a libjvm.so too and attaches differently) and, as the
// JDK's own client demands, handles SIGQUIT: what handles the signal is
// not ended by it, whatever else the process is.
func findJVM(proc string, pid int) (jvm, error) {
	dir := filepath.Join(proc, strconv.Itoa(pid))
	maps, err := os.ReadFile(filepath.Join(dir, "maps"))
	if err != nil {
		return jvm{}, errNoJVM // it ended, or is a kernel thread
	}
	hotspot, openj9 := false, false
	for _, line := range strings.Split(string(maps), "\n") {
		// "address perms offset dev inode path"
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		library := filepath.Base(fields[5])
		hotspot = hotspot || library == "libjvm.so" && strings.Contains(fields[1], "x")
		openj9 = openj9 || strings.HasPrefix(library, "libj9")
	}
	switch {
	case openj9:
		return jvm{}, notAskable{errors.New("it runs an OpenJ9 JVM, which Asservat cannot ask: only HotSpot")}
	case !hotspot:
		return jvm{}, errNoJVM
	}
	j := jvm{pid: pid}
	handlesQuit := false
	status, _ := os.ReadFile(filepath.Join(dir, "status"))
	for _, line := range strings.Split(string(status), "\n") {
		key, value, _ := strings.Cut(line, ":")
		fields := strings.Fields(value)
		switch {
		case key == "NSpid" && len(fields) > 0: // the last one is the ID in the innermost namespace
			j.inner, _ = strconv.Atoi(fields[len(fields)-1])
		case (key == "Uid" || key == "Gid") && len(fields) > 1: // real, effective, saved, file system
			id, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return jvm{}, errNoJVM
			}
			if key == "Uid" {
				j.uid = uint32(id)
			} else {
				j.gid = uint32(id)
			}
		case key == "SigCgt" && len(fields) > 0: // a bit per signal, the lowest for signal 1
			caught, _ := strconv.ParseUint(fields[0], 16, 64)
			handlesQuit = caught&(1<<(syscall.SIGQUIT-1)) != 0
		}
	}
	if j.inner == 0 {
		return jvm{}, errNoJVM // it ended meanwhile
	}
	if !handlesQuit {
		return jvm{}, notAskable{errors.New("its JVM does not handle SIGQUIT (started with -Xrs), so it is not signalled")}
	}
	// A JVM that was told not to answer is not signalled either. Its
	// options are on its command line or in these variables.
	const disabled = "-XX:+DisableAttachMechanism"
	command, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
	environment, _ := os.ReadFile(filepath.Join(dir, "environ"))
	told := bytes.Contains(command, []byte(disabled))
	for _, variable := range bytes.Split(environment, []byte{0}) {
		name, value, _ := bytes.Cut(variable, []byte("="))
		told = told || slices.Contains([]string{"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"}, string(name)) && bytes.Contains(value, []byte(disabled))
	}
	if told {
		return jvm{}, notAskable{errors.New("its JVM was started with " + disabled)}
	}
	return j, nil
}

// containerJVM finds the JVM of a container: its main process, or else the
// first of its processes that is one.
func (a *Agent) containerJVM(pod *corev1.Pod, container string, known *processes) (jvm, error) {
	id, _, err := runningID(pod, container)
	if err != nil {
		return jvm{}, err
	}
	all, main, err := known.of(a, pod, id)
	if err != nil {
		return jvm{}, err
	}
	slices.Sort(all)
	for _, pid := range append([]int{main}, all...) {
		if j, err := findJVM(a.Proc, pid); err != errNoJVM {
			return j, err
		}
	}
	return jvm{}, errNoJVM
}

// jvmDiagnostics returns the diagnostics of the JVMs in the pod's
// containers, and what is to say about JVMs that cannot be asked. It
// reads the node's /proc: nothing is written or signalled.
func (a *Agent) jvmDiagnostics(pod *corev1.Pod) (found []api.ProfileTarget, notes []string) {
	for _, c := range pod.Spec.Containers {
		_, err := a.containerJVM(pod, c.Name, nil)
		if err == nil {
			for _, e := range api.JVMDiagnostics {
				found = append(found, api.ProfileTarget{Container: c.Name, ProfileEndpoint: e})
			}
		} else if errors.As(err, &notAskable{}) {
			notes = append(notes, "Container "+c.Name+": "+err.Error()+".")
		}
	}
	return found, notes
}

// openInside opens a directory of a container, named as the container
// names it, under the container's root as the node sees it. The kernel
// follows the path within that root (openat2 with RESOLVE_IN_ROOT, Linux
// 5.6): a link to an absolute path leads to the container's file of that
// name, not to the node's.
func openInside(root, dir string) (*os.File, error) {
	at, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(at)
	fd, err := unix.Openat2(at, strings.TrimLeft(dir, "/"), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT})
	if err != nil {
		return nil, fmt.Errorf("%s of the container: %w", dir, err)
	}
	return os.NewFile(uintptr(fd), dir), nil
}

// askJVM has the JVM of a container run a diagnostic and uploads what it
// gives. A flight recording runs for the time frame, or until frame ends,
// and keeps what it has until then.
func (a *Agent) askJVM(ctx, frame context.Context, pod *corev1.Pod, target api.ProfileTarget, seconds int, known *processes, up func(string, io.Reader) error) error {
	j, held, err := a.holdJVM(pod, target.Container, known)
	if err != nil {
		return err
	}
	defer held.Close()
	return attachAs(ctx, frame, a.Proc, j, held, target, seconds, up)
}

// attachAs asks a JVM that is held, as a child with the JVM's user and
// group.
func attachAs(ctx, frame context.Context, proc string, j jvm, held *os.File, target api.ProfileTarget, seconds int, up func(string, io.Reader) error) error {
	tmp, err := openInside(filepath.Join(proc, strconv.Itoa(j.pid), "root"), "/tmp")
	if err != nil {
		return err
	}
	defer tmp.Close()
	// The agent's own program, by the link that needs no path to it which
	// the JVM's user could follow.
	cmd := exec.Command("/proc/self/exe", "jvm-attach", target.ID, strconv.Itoa(j.inner), strconv.Itoa(seconds))
	cmd.ExtraFiles = []*os.File{tmp, held} // the child's files 3 and 4
	if j.uid != uint32(os.Geteuid()) || j.gid != uint32(os.Getegid()) {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: j.uid, Gid: j.gid}}
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// The agent may not signal a child of another user. The child is told
	// to end a recording by the end of its standard input, and is never
	// ended itself: it removes what it wrote into the container.
	stop, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("the JVM could not be asked as its user %d: %w", j.uid, err)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-frame.Done():
		case <-ctx.Done():
		case <-done:
		}
		stop.Close()
		// A capture that is cancelled does not wait for the JVM.
		select {
		case <-ctx.Done():
			out.Close()
		case <-done:
		}
	}()
	// A diagnostic that failed gives nothing: no empty file is stored.
	content := bufio.NewReader(out)
	uploadErr := errors.New("the JVM gave nothing")
	if _, err := content.Peek(1); err == nil {
		uploadErr = up(target.File, content)
	}
	if ctx.Err() != nil {
		// The JVM cannot be interrupted in a heap dump: the child waits
		// for it and removes the file, and nobody waits for the child.
		go cmd.Wait()
		return ctx.Err()
	}
	io.Copy(io.Discard, content)
	if err := cmd.Wait(); err != nil {
		return errors.New(tail(stderr.Bytes()))
	}
	return uploadErr
}

// holdJVM finds the JVM of a container and holds its process (a pidfd):
// a signal through that goes to this process or to none, also if its ID
// is given to another process meanwhile.
func (a *Agent) holdJVM(pod *corev1.Pod, container string, known *processes) (jvm, *os.File, error) {
	j, err := a.containerJVM(pod, container, known)
	if err == errNoJVM {
		err = fmt.Errorf("no process in container %s of pod %s is a HotSpot JVM", container, pod.Name)
	}
	if err != nil {
		return jvm{}, nil, err
	}
	fd, err := unix.PidfdOpen(j.pid, 0)
	if err != nil {
		return jvm{}, nil, err
	}
	held := os.NewFile(uintptr(fd), "pidfd")
	// Looked at again now that it is held: what was found is this process
	// if it still lives, which the held file tells (it is readable once
	// the process has ended).
	again, err := findJVM(a.Proc, j.pid)
	ended := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, pollErr := unix.Poll(ended, 0); err != nil || again != j || pollErr != nil || n != 0 {
		held.Close()
		return jvm{}, nil, fmt.Errorf("the JVM in container %s of pod %s ended meanwhile", container, pod.Name)
	}
	return j, held, nil
}

// AttachJVM is the agent started again as a JVM's user ("jvm-attach
// <diagnostic> <the JVM's process ID in its namespace> <seconds>"), with
// the JVM's /tmp as file 3 and the JVM's process as file 4. It writes
// what the diagnostic gives to out, and ends a flight recording early
// when stop ends.
func AttachJVM(args []string, stop io.Reader, out io.Writer) error {
	if len(args) != 3 {
		return errors.New("usage: jvm-attach <diagnostic> <pid> <seconds>, run by the agent")
	}
	pid, err1 := strconv.Atoi(args[1])
	seconds, err2 := strconv.Atoi(args[2])
	if err1 != nil || err2 != nil {
		return errors.New("jvm-attach: the process ID and the seconds are numbers")
	}
	// What the diagnostic gives goes to a pipe. If the agent closes it,
	// writing fails and what was written into the container is removed;
	// the signal that would end this process instead is ignored.
	signal.Ignore(syscall.SIGPIPE)
	c := attacher{dir: "/proc/self/fd/3", pid: pid, wait: attachWait, quit: func() error {
		return unix.PidfdSendSignal(4, unix.SIGQUIT, nil, 0)
	}}
	return c.run(args[0], time.Duration(seconds)*time.Second, stop, out)
}

// attacher asks one JVM, as a process with the JVM's user and group.
type attacher struct {
	dir  string // the JVM's /tmp
	pid  int    // the JVM's process ID in its own namespace
	wait time.Duration
	// quit sends the JVM SIGQUIT.
	quit func() error
}

// run has the JVM run a diagnostic and writes what it gives to out. What
// the JVM wrote into its /tmp for it is removed in every outcome.
func (c attacher) run(diagnostic string, frame time.Duration, stop io.Reader, out io.Writer) error {
	if e, _ := api.FindProfileEndpoint(diagnostic); !e.Attach {
		return c.refuse(diagnostic)
	}
	if err := c.open(); err != nil {
		return err
	}
	// The JVM writes a heap dump and a recording to a file of its own. The
	// name cannot be guessed, so nothing in the container can have put
	// something else there, and the JVM overwrites no file.
	random := make([]byte, 16)
	rand.Read(random)
	name := fmt.Sprintf("asservat-%x", random)
	file := name
	words := strings.NewReplacer("{file}", file, "{name}", name, "{seconds}", strconv.Itoa(int(frame/time.Second)+60))
	ask := func(diagnostic string) (string, error) {
		answer, err := c.ask(diagnostic, words)
		if err != nil {
			return "", err
		}
		defer answer.Close()
		text, err := io.ReadAll(answer)
		return string(text), err
	}
	switch diagnostic {
	case "jvm-heapdump":
		defer os.Remove(filepath.Join(c.dir, file))
		said, err := ask(diagnostic)
		if err != nil {
			return err
		}
		return c.send(file, said, out)
	case "jvm-recording":
		defer os.Remove(filepath.Join(c.dir, file))
		if said, err := ask(diagnostic); err != nil || !strings.Contains(said, "Started recording") {
			return fmt.Errorf("the JVM started no flight recording: %s %v", tail([]byte(said)), err)
		}
		stopped := make(chan struct{})
		go func() {
			io.Copy(io.Discard, stop)
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(frame):
		}
		said, err := ask("jvm-recording-stop")
		if err != nil {
			return err
		}
		return c.send(file, said, out)
	}
	answer, err := c.ask(diagnostic, words)
	if err != nil {
		return err
	}
	defer answer.Close()
	_, err = io.Copy(out, answer)
	return err
}

func (c attacher) refuse(request string) error {
	return fmt.Errorf("%q is nothing that Asservat asks a JVM for", request)
}

// send writes a file that the JVM wrote into its /tmp to out. said is what
// the JVM answered, which tells why if there is no file.
func (c attacher) send(file, said string, out io.Writer) error {
	f, err := os.OpenFile(filepath.Join(c.dir, file), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("the JVM wrote no file: %s", tail([]byte(said)))
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return errors.New("what the JVM wrote is no file")
	}
	_, err = io.Copy(out, f)
	return err
}

// socket opens the JVM's attach socket as a path (not a connection), or
// fails if it is not there. A link in its place is not followed.
func (c attacher) socket() (*os.File, error) {
	fd, err := unix.Open(filepath.Join(c.dir, ".java_pid"+strconv.Itoa(c.pid)), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "socket")
	if info, err := f.Stat(); err != nil || info.Mode()&os.ModeSocket == 0 {
		f.Close()
		return nil, errors.New("the JVM's attach socket is no socket")
	}
	return f, nil
}

// open makes the JVM open its attach socket, if it has not yet: a marker
// file in its /tmp tells the JVM that the SIGQUIT which follows asks for
// the socket and not for a thread dump on its standard output. The marker
// is removed afterwards.
func (c attacher) open() error {
	if s, err := c.socket(); err == nil {
		return s.Close()
	}
	// The JVM makes its socket under another name and renames it.
	changes, err := watchDir(c.dir, syscall.IN_CREATE|syscall.IN_MOVED_TO)
	if err != nil {
		return err
	}
	defer changes.Close()
	marker := filepath.Join(c.dir, ".attach_pid"+strconv.Itoa(c.pid))
	f, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("no marker file could be written into the container's /tmp, which the JVM needs to open its attach socket: %w", err)
	}
	f.Close()
	defer os.Remove(marker)
	for range 2 {
		if err := c.quit(); err != nil {
			return fmt.Errorf("the JVM could not be signalled: %w", err)
		}
		timeout := time.After(c.wait / 2)
		for waiting := true; waiting; {
			if s, err := c.socket(); err == nil {
				return s.Close()
			}
			select {
			case <-changes.happened:
			case <-timeout:
				waiting = false
			}
		}
	}
	return fmt.Errorf("the JVM did not open its attach socket within %s: it cannot write its /tmp, or was started with -XX:+DisableAttachMechanism", c.wait)
}

// ask sends one of jvmRequests, and no other request can be sent. It
// speaks the attach protocol's first version, which every HotSpot since
// JDK 6 speaks: the version, the command and three arguments, each ended
// by a zero byte. The answer is a line with a status, zero for success,
// and then the command's output.
func (c attacher) ask(request string, words *strings.Replacer) (io.ReadCloser, error) {
	known, is := jvmRequests[request]
	if !is {
		return nil, c.refuse(request)
	}
	command, argument := known[0], words.Replace(known[1])
	s, err := c.socket()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	// Through the open path: the address of a socket holds 108 bytes, and
	// what is connected to is what was looked at.
	conn, err := net.Dial("unix", "/proc/self/fd/"+strconv.Itoa(int(s.Fd())))
	if err != nil {
		return nil, fmt.Errorf("the JVM's attach socket: %w", err)
	}
	if _, err := conn.Write([]byte("1\x00" + command + "\x00" + argument + "\x00\x00\x00")); err != nil {
		conn.Close()
		return nil, err
	}
	answer := bufio.NewReader(conn)
	status, err := answer.ReadString('\n')
	if err == nil && strings.TrimSpace(status) != "0" {
		said, _ := io.ReadAll(answer)
		err = fmt.Errorf("the JVM failed at %s (status %s): %s", strings.Fields(argument)[0], strings.TrimSpace(status), tail(said))
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{answer, conn}, nil
}
