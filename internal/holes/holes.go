// Package holes packs a file that is mostly holes into its data and the
// places they belong at, and unpacks it again.
//
// A core dump of a process is as large as the memory the process has
// mapped, and of what it never touched gdb writes nothing: the file has
// holes there, which take no room on the node's disk. Read as it is, such
// a file is zeros for every hole, and a process that maps a terabyte it
// never uses would have the hub store a terabyte. The agent sends such a
// core packed, the hub stores it packed and unpacks it for whoever reads
// it: the bytes that are downloaded are those of the file.
package holes

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// A packed file: the magic, then for every stretch of data its place and
// its length, as two 64-bit numbers, and the data; at the end the file's
// size with a length of zero.
const magic = "ASVHOLE1"

// largest is the size of the largest file that is unpacked: 256 TiB, the
// address space of a process on the processors Asservat runs on (48
// bits), which no core of one exceeds. A size beyond it is no core's, and
// unpacking it to count or to hash it would not end.
const largest = 1 << 48

// Sparse tells whether a file has holes worth packing: at least a
// megabyte less on the disk than its size.
func Sparse(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Blocks*512+1<<20 < info.Size()
}

// Pack returns the file packed, read from its start.
func Pack(f *os.File) io.Reader {
	r, w := io.Pipe()
	go func() { w.CloseWithError(pack(w, f)) }()
	return r
}

func pack(w io.Writer, f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, magic); err != nil {
		return err
	}
	fd, size := int(f.Fd()), info.Size()
	for at := int64(0); at < size; {
		// The next data, and where it ends.
		from, err := unix.Seek(fd, at, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break // only a hole is left
		}
		if err != nil {
			return err
		}
		to, err := unix.Seek(fd, from, unix.SEEK_HOLE)
		if err != nil {
			return err
		}
		if err := head(w, from, to-from); err != nil {
			return err
		}
		if _, err := io.Copy(w, io.NewSectionReader(f, from, to-from)); err != nil {
			return err
		}
		at = to
	}
	return head(w, size, 0)
}

func head(w io.Writer, at, length int64) error {
	b := binary.BigEndian.AppendUint64(make([]byte, 0, 16), uint64(at))
	_, err := w.Write(binary.BigEndian.AppendUint64(b, uint64(length)))
	return err
}

// Unpack writes the file that r holds packed to w and returns its size.
// Into a file it leaves the holes as holes; into anything else it writes
// zeros for them.
func Unpack(w io.Writer, r io.Reader) (int64, error) {
	start := make([]byte, len(magic))
	if _, err := io.ReadFull(r, start); err != nil || string(start) != magic {
		return 0, errors.New("the file is not packed as one with holes")
	}
	file, _ := w.(*os.File)
	written := int64(0)
	for {
		var record [16]byte
		if _, err := io.ReadFull(r, record[:]); err != nil {
			return written, errors.New("the packed file ends before its end is told")
		}
		at, length := binary.BigEndian.Uint64(record[:8]), binary.BigEndian.Uint64(record[8:])
		if at > largest || length > largest || int64(at) < written {
			return written, fmt.Errorf("the packed file places data at %d after %d, or beyond what a process maps", at, written)
		}
		// The hole before the data, or before the end.
		if gap := int64(at) - written; gap > 0 {
			if file != nil {
				if _, err := file.Seek(gap, io.SeekCurrent); err != nil {
					return written, err
				}
			} else if _, err := io.CopyN(w, zeros{}, gap); err != nil {
				return written, err
			}
			written = int64(at)
		}
		if length == 0 {
			if file != nil {
				if err := file.Truncate(written); err != nil {
					return written, err
				}
			}
			var more [1]byte
			if n, _ := r.Read(more[:]); n != 0 {
				return written, errors.New("the packed file goes on after its end")
			}
			return written, nil
		}
		n, err := io.CopyN(w, r, int64(length))
		written += n
		if err != nil {
			return written, errors.New("the packed file ends in the middle of its data")
		}
	}
}

// zeros reads as zeros without end.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
