package coredesc

import (
	"debug/elf"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// A core that the agent takes of a running process numbers its threads as
// the node does: the agent is in the node's process ID namespace. A
// language runtime knows its threads by their numbers inside the
// container. So that a runtime's threads can be told to be the core's, a
// description holds both numbers of each thread (threadIds), and the hub
// keeps them when it describes a core again. A core that the kernel wrote
// of a crashed process numbers its threads as the container does: it needs
// none.

// NamespaceThreadIDs returns, for the threads of a process of the node,
// their numbers inside the process's own namespace, by their numbers on
// the node: nil if they are the same, or the process is gone.
func NamespaceThreadIDs(proc string, pid int) map[int]int {
	tasks, _ := filepath.Glob(filepath.Join(proc, strconv.Itoa(pid), "task", "*", "status"))
	ids := map[int]int{}
	differ := false
	for _, task := range tasks {
		status, _ := os.ReadFile(task)
		for _, line := range strings.Split(string(status), "\n") {
			// "NSpid: <on the node> … <innermost>"
			if numbers, is := strings.CutPrefix(line, "NSpid:"); is {
				fields := strings.Fields(numbers)
				if len(fields) == 0 {
					continue
				}
				outer, _ := strconv.Atoi(fields[0])
				inner, _ := strconv.Atoi(fields[len(fields)-1])
				ids[outer], differ = inner, differ || outer != inner
			}
		}
	}
	if !differ {
		return nil
	}
	return ids
}

// ThreadIDs reads the thread numbers that a description holds.
func ThreadIDs(report []byte) map[int]int {
	var fields struct {
		ThreadIDs map[string]int `json:"threadIds"`
	}
	if json.Unmarshal(report, &fields) != nil || len(fields.ThreadIDs) == 0 {
		return nil
	}
	ids := map[int]int{}
	for outer, inner := range fields.ThreadIDs {
		if n, err := strconv.Atoi(outer); err == nil {
			ids[n] = inner
		}
	}
	return ids
}

// onNode returns the number on the node of a thread that a runtime knows
// by its number inside the container.
func (d Describer) onNode(inner int) int {
	for outer, n := range d.ThreadIDs {
		if n == inner {
			return outer
		}
	}
	return inner
}

// renumberThreads writes the threads' numbers inside the container into
// the notes of a core, in place of their numbers on the node: into each
// thread's status (NT_PRSTATUS) and the process's information
// (NT_PRPSINFO), where a 64-bit kernel has them at these offsets.
func renumberThreads(core *os.File, file *elf.File, ids map[int]int) error {
	const prstatus, prpsinfo = 1, 3
	at := map[uint32]int{prstatus: 32, prpsinfo: 24}
	info, err := core.Stat()
	if err != nil {
		return err
	}
	for _, segment := range file.Progs {
		// Notes that say they are larger than the file are not notes.
		if segment.Type != elf.PT_NOTE || segment.Filesz > uint64(info.Size()) {
			continue
		}
		notes := make([]byte, segment.Filesz)
		if _, err := segment.ReadAt(notes, 0); err != nil {
			return err
		}
		for offset := 0; len(notes)-offset >= 12; {
			name, size, kind := int(file.ByteOrder.Uint32(notes[offset:])), int(file.ByteOrder.Uint32(notes[offset+4:])), file.ByteOrder.Uint32(notes[offset+8:])
			start := offset + 12 + (name+3)&^3
			if name < 0 || size < 0 || start+size > len(notes) {
				break
			}
			if field, known := at[kind]; known && size >= field+4 && strings.TrimRight(string(notes[offset+12:offset+12+name]), "\x00") == "CORE" {
				if inner, is := ids[int(file.ByteOrder.Uint32(notes[start+field:]))]; is {
					number := make([]byte, 4)
					file.ByteOrder.PutUint32(number, uint32(inner))
					if _, err := core.WriteAt(number, int64(segment.Off)+int64(start+field)); err != nil {
						return err
					}
				}
			}
			offset = start + (size+3)&^3
		}
	}
	return nil
}
