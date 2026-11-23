package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// The kubelet has the container runtime write what a container prints to
// files on the node: /var/log/pods/<namespace>_<pod>_<UID>/<container>/<n>.log,
// where n counts the container's restarts. Every line is
// "<time> <stream> <P or F> <text>"; P marks a part of a line that the
// following lines continue. The kubelet rotates a file by renaming it, and
// the runtime then opens a new one of the same name.

// podLogDir is where the log files of a pod's container are on the node,
// whose root the agent reaches through the node's first process.
func (a *Agent) podLogDir(namespace, pod, uid, container string) string {
	return filepath.Join(a.Proc, "1", "root", "var", "log", "pods", namespace+"_"+pod+"_"+uid, container)
}

// longestLine is the most that is held of one log line: it is in the agent's
// memory. The runtimes cut lines into parts of 16 KiB by default.
const longestLine = 64 << 10

// podLog reads what a container writes from the log files on its node.
type podLog struct {
	dir     string
	changes *dirChanges
	// files are the files being read: the one that the runtime writes, and
	// before it for one more look the one it wrote before.
	files []*logFile
	// parts are the parts so far of a line that the runtime wrote in parts.
	parts []byte
	read  []byte
}

type logFile struct {
	f *os.File
	// begun is the beginning of a line whose end is not written yet.
	begun []byte
}

// openPodLog opens a container's log directory at the end of its current
// file. It fails where the files cannot be read: the caller then asks the
// API server.
func openPodLog(dir string) (*podLog, error) {
	// The directory is watched before the file is looked for, so that no
	// file made in between is missed.
	changes, err := watchDir(dir, syscall.IN_MODIFY|syscall.IN_CREATE)
	if err != nil {
		return nil, err
	}
	current, err := currentLog(dir)
	if err == nil {
		_, err = current.Seek(0, io.SeekEnd)
	}
	if err != nil {
		changes.Close()
		return nil, err
	}
	return &podLog{dir: dir, changes: changes, files: []*logFile{{f: current}}, read: make([]byte, 64<<10)}, nil
}

// currentLog opens the log file of the container's latest instance.
func currentLog(dir string) (*os.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	latest := -1
	for _, e := range entries {
		if number, ok := strings.CutSuffix(e.Name(), ".log"); ok {
			if n, err := strconv.Atoi(number); err == nil {
				latest = max(latest, n)
			}
		}
	}
	if latest < 0 {
		return nil, fmt.Errorf("no log file in %s", dir)
	}
	return os.Open(filepath.Join(dir, strconv.Itoa(latest)+".log"))
}

// follow calls found with every line that the container writes, without the
// runtime's prefix, until ctx ends. It returns an error when the files can
// no longer be read.
func (l *podLog) follow(ctx context.Context, found func(line []byte)) error {
	defer func() {
		l.changes.Close()
		for _, file := range l.files {
			file.f.Close()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-l.changes.happened:
			if !ok {
				return errors.New("the kernel stopped reporting changes of " + l.dir)
			}
		}
		made := l.changes.seen()&syscall.IN_CREATE != 0
		for _, file := range l.files {
			if err := l.take(file, found); err != nil {
				return err
			}
		}
		// The file from before has had its last look.
		for ; len(l.files) > 1; l.files = l.files[1:] {
			l.files[0].f.Close()
		}
		if !made {
			continue
		}
		// A file was made: after a rotation, or for the container's next
		// instance, it is the one to read on, from its beginning. The runtime
		// may write a last line to the old file while it changes over, so
		// that one is looked at once more with the next change.
		next, err := currentLog(l.dir)
		if err != nil {
			return err
		}
		was, _ := l.files[0].f.Stat()
		if is, err := next.Stat(); err != nil || os.SameFile(was, is) {
			next.Close()
			continue
		}
		file := &logFile{f: next}
		l.files = append(l.files, file)
		if err := l.take(file, found); err != nil {
			return err
		}
	}
}

// take reads what was written to a file since the last time.
func (l *podLog) take(file *logFile, found func(line []byte)) error {
	for {
		n, err := file.f.Read(l.read)
		for written := l.read[:n]; len(written) > 0; {
			end := bytes.IndexByte(written, '\n')
			if end < 0 {
				file.begun = append(file.begun, written...)
				break
			}
			line := written[:end]
			if len(file.begun) > 0 {
				file.begun = append(file.begun, line...)
				line = file.begun
			}
			l.line(line, found)
			file.begun, written = file.begun[:0], written[end+1:]
		}
		if len(file.begun) > longestLine {
			return fmt.Errorf("a line in %s is longer than %d bytes", file.f.Name(), longestLine)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// line takes a line as the runtime wrote it. The parts of a line that came
// in parts are joined; one that grows longer than longestLine is handed on
// in pieces.
func (l *podLog) line(written []byte, found func(line []byte)) {
	text, whole := written, true
	field, rest, prefixed := []byte(nil), written, true
	for range 3 { // the time, the stream, and whether it is a part
		if field, rest, prefixed = bytes.Cut(rest, []byte(" ")); !prefixed {
			break
		}
	}
	if prefixed {
		text, whole = rest, !bytes.HasPrefix(field, []byte("P"))
	}
	if !whole || len(l.parts) > 0 {
		l.parts = append(l.parts, text...)
		text = l.parts
	}
	if whole || len(text) > longestLine {
		found(text)
		l.parts = l.parts[:0]
	}
}
