package agent

import (
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// dirChanges tells when something changes in a directory, as the kernel
// reports it through inotify.
type dirChanges struct {
	f *os.File
	// happened holds a token while changes wait to be looked at. It is
	// closed when the kernel's reports end.
	happened chan struct{}
	kinds    atomic.Uint32
}

// watchDir reports the changes in a directory that the mask names
// (syscall.IN_CREATE and the like) until it is closed.
func watchDir(dir string, mask uint32) (*dirChanges, error) {
	// Not blocking, so that the runtime waits for the reports with its
	// poller and Close ends the read.
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify: %w", err)
	}
	f := os.NewFile(uintptr(fd), "inotify")
	if _, err := syscall.InotifyAddWatch(fd, dir, mask); err != nil {
		f.Close()
		return nil, fmt.Errorf("inotify of %s: %w", dir, err)
	}
	c := &dirChanges{f: f, happened: make(chan struct{}, 1)}
	go func() {
		defer close(c.happened)
		// Room for several reports: one is its header and a file name.
		reports := make([]byte, 4096)
		for {
			n, err := f.Read(reports)
			if err != nil {
				return
			}
			for at := 0; at+syscall.SizeofInotifyEvent <= n; {
				report := (*syscall.InotifyEvent)(unsafe.Pointer(&reports[at]))
				c.kinds.Or(report.Mask)
				at += syscall.SizeofInotifyEvent + int(report.Len)
			}
			select {
			case c.happened <- struct{}{}:
			default: // the last changes have not been looked at yet
			}
		}
	}()
	return c, nil
}

// seen returns the kinds of changes (syscall.IN_CREATE and the like) since
// the last call.
func (c *dirChanges) seen() uint32 { return c.kinds.Swap(0) }

func (c *dirChanges) Close() { c.f.Close() }
