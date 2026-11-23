package coredesc

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/go-delve/delve/pkg/goversion"
	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/service/api"
)

// Most Go programs in containers are built without debug information
// (-ldflags="-s -w"). Delve then finds no goroutines: it looks up the
// runtime's variables and the layout of its types in that information. A Go
// program always carries its line table, though, which names the function,
// file and line of every address, and the runtime keeps frame pointers. So
// the goroutines of such a core are found from what the runtime's memory
// looks like, and their stacks are walked along the frame pointers. What
// they cannot have is variables.
//
// The layout of the runtime's g, as far as it is used here, has been the
// same since Go 1.11 except for the two places that are found by looking:
//
//	stack.lo, stack.hi   words 0 and 1
//	sched.sp, .pc, .g    words 7, 8 and 9; sched.g points to the g itself
//	sched.bp             word 12 or 13 (gobuf lost a field)
//	atomicstatus         uint32, 8 bytes before goid
//	goid                 somewhere after sched: the word that is a different
//	                     small number in every g
//	waitreason           uint8, 24 bytes after goid
const (
	gSchedPC  = 8 * 8
	gSchedG   = 9 * 8
	gRead     = 512             // bytes read of each g: goid lies within in every version
	gStatuses = 0b1101011111    // the states a g can be in, as bits: 0 to 4, 6, 8, 9
	gScan     = 0x1000          // set in a status while the collector scans the stack
	gIDMost   = uint64(1) << 48 // goroutine IDs count up from 1
	gDead     = 6
)

// lineTableGoroutines reads the goroutines of a core whose program has no
// debug information.
// It also returns the stacks of the threads, by their system IDs: gdb
// cannot walk them without debug information either.
func lineTableGoroutines(ctx context.Context, target *proc.Target, exe string, runtime goversion.GoVersion) (out []goroutine, threads map[int]goStack, cut bool, err error) {
	bi, mem := target.BinInfo(), target.Memory()
	if bi.Arch.PtrSize() != 8 || len(bi.Images) == 0 {
		return nil, nil, false, errors.New("no 64-bit program")
	}
	// word reads from what was read of memory; where that failed, it is 0.
	word := func(b []byte, at int) uint64 {
		if at+8 > len(b) {
			return 0
		}
		return binary.LittleEndian.Uint64(b[at:])
	}
	read := func(addr uint64, n int) []byte {
		b := make([]byte, n)
		if got, err := mem.ReadMemory(b, addr); err != nil || got != n {
			return nil
		}
		return b
	}
	// A g, by what never changes: sched.g and its stack's bounds, which a
	// goroutine that has ended may have given back.
	isG := func(addr uint64) []byte {
		if addr == 0 || addr%8 != 0 {
			return nil
		}
		g := read(addr, gRead)
		if g == nil || word(g, gSchedG) != addr || word(g, 0) >= word(g, 8) && word(g, 0)|word(g, 8) != 0 {
			return nil
		}
		return g
	}

	// The runtime's allgs is a slice of all goroutines among its variables:
	// the longest slice there whose every element is a g.
	file, err := elf.Open(exe)
	if err != nil {
		return nil, nil, false, err
	}
	defer file.Close()
	var addrs []uint64
	for _, name := range []string{".bss", ".data"} {
		section := file.Section(name)
		if section == nil {
			continue
		}
		vars := read(section.Addr+bi.Images[0].StaticBase, int(section.Size)&^7)
		for at := 0; at+24 <= len(vars); at += 8 {
			array, length, capacity := word(vars, at), word(vars, at+8), word(vars, at+16)
			if length <= uint64(len(addrs)) || length > capacity || isG(word(read(array, 8), 0)) == nil {
				continue
			}
			// The elements are read a page at a time and only for as long
			// as they are gs: what merely looks like a long slice costs
			// one page.
			var found []uint64
			for whole := true; whole && uint64(len(found)) < length; {
				page := read(array+uint64(len(found))*8, int(min(length-uint64(len(found)), 512))*8)
				whole = page != nil
				for i := 0; i < len(page) && whole; i += 8 {
					if whole = isG(word(page, i)) != nil; whole {
						found = append(found, word(page, i))
					}
				}
			}
			if uint64(len(found)) == length {
				addrs = found
			}
		}
	}
	if len(addrs) == 0 {
		return nil, nil, false, errors.New("the runtime's list of goroutines was not found")
	}
	// Where the fields of a g are is told by some of them: a program can
	// have a million goroutines, and each is read again when it is needed.
	gs := make([][]byte, min(len(addrs), 4096))
	for i := range gs {
		gs[i] = isG(addrs[i])
	}

	// goid: the first word after sched that is a different ID in every g,
	// behind a status that is one.
	goid := 0
	for at := 14 * 8; at+32 <= gRead && goid == 0; at += 8 {
		ids := make(map[uint64]bool, len(gs))
		for _, g := range gs {
			id, status := word(g, at), binary.LittleEndian.Uint32(g[at-8:])&^gScan
			if id == 0 || id >= gIDMost || ids[id] || status > 9 || gStatuses&(1<<status) == 0 {
				break
			}
			ids[id] = true
		}
		if len(ids) == len(gs) {
			goid = at
		}
	}
	if goid == 0 {
		return nil, nil, false, errors.New("the goroutines' IDs were not found")
	}
	// sched.bp: of the two places, the one that more often points into the
	// goroutine's own stack.
	inStack := func(g []byte, addr uint64) bool { return addr >= word(g, 0) && addr+16 <= word(g, 8) }
	schedBP, votes := 12*8, 0
	for _, g := range gs {
		for _, at := range []int{12 * 8, 13 * 8} {
			if inStack(g, word(g, at)) {
				votes += at - 100 // one down for word 12, one up for word 13
			}
		}
	}
	if votes > 0 {
		schedBP = 13 * 8
	}

	// A goroutine that runs has its registers in its thread: the thread
	// whose stack pointer is in the goroutine's stack.
	type registers struct {
		pc, bp uint64
		thread int
	}
	running := map[uint64]registers{}
	var all []registers
	var sps []uint64 // their stack pointers
	for _, thread := range target.ThreadList() {
		regs, err := thread.Registers()
		if err != nil {
			continue
		}
		all = append(all, registers{regs.PC(), regs.BP(), thread.ThreadID()})
		sps = append(sps, regs.SP())
	}
	type found struct {
		addr, id uint64
	}
	var live []found
	for _, addr := range addrs {
		g := isG(addr)
		if g == nil {
			continue
		}
		for i, sp := range sps {
			if sp >= word(g, 0) && sp < word(g, 8) {
				running[addr] = all[i]
			}
		}
		if status := binary.LittleEndian.Uint32(g[goid-8:]) &^ gScan; status != 0 && status != gDead {
			live = append(live, found{addr, word(g, goid)})
		}
	}
	// Without the table of inlined calls a frame is its function with the
	// line of what was inlined there.
	var inlined *inlineTable
	// Some of the functions that Delve read from the same file, the
	// lowest first, tell where the table's addresses count from.
	entries := []uint64{}
	for i := 0; i < len(bi.Functions); i += max(1, len(bi.Functions)/64) {
		entries = append(entries, bi.Functions[i].Entry-bi.Images[0].StaticBase)
	}
	slices.Sort(entries)
	if inlined, err = openInlineTable(file, entries); err != nil {
		slog.Info("inlined calls are not told apart", "program", exe, "error", err)
	}

	// walk follows a stack from its innermost frame. Each frame keeps the
	// caller's frame pointer and, above it, the address it returns to.
	walk := func(pc, bp uint64, within func(addr uint64) bool) (frames []goFrame, cut bool) {
		frames = []goFrame{}
		for at := pc; at != 0; {
			if len(frames) >= maxFrames {
				return frames, true
			}
			// A return address is behind its call: the line is the call's.
			line := at
			if len(frames) > 0 {
				line--
			}
			_, _, fn := bi.PCToLine(line)
			if fn == nil && len(frames) > 0 {
				break // no address of the program: the stack ends here
			}
			// The calls that were inlined here come first, each with the
			// line it had reached; then the function whose frame it is.
			names := []string{}
			lines := []uint64{line}
			if fn != nil && inlined != nil {
				base := bi.Images[0].StaticBase
				for _, call := range inlined.at(fn.Entry-base, line-base) {
					names, lines = append(names, call.function), append(lines, call.caller+base)
				}
			}
			if fn != nil {
				names = append(names, fn.Name)
			} else {
				names = append(names, "")
			}
			for i, name := range names {
				frame := goFrame{Level: len(frames), PC: fmt.Sprintf("0x%016x", at), Function: name, Arguments: []goVariable{}, Locals: []goVariable{}}
				frame.File, frame.Line, _ = bi.PCToLine(lines[i])
				frames = append(frames, frame)
			}
			if !within(bp) {
				break
			}
			saved := read(bp, 16)
			if saved == nil || word(saved, 0) != 0 && word(saved, 0) <= bp {
				break
			}
			at, bp = word(saved, 8), word(saved, 0)
		}
		return frames, false
	}
	// A thread's stack, whose bounds are not known, is followed for as long
	// as it leads upwards to addresses of the program.
	threads = map[int]goStack{}
	for _, thread := range all {
		frames, cut := walk(thread.pc, thread.bp, func(addr uint64) bool { return addr != 0 })
		threads[thread.thread] = goStack{frames, cut}
	}

	if len(live) > maxGoroutines {
		sort.SliceStable(live, func(i, j int) bool {
			_, a := running[live[i].addr]
			_, b := running[live[j].addr]
			return a && !b
		})
		live, cut = live[:maxGoroutines], true
	}
	sort.Slice(live, func(i, j int) bool { return live[i].id < live[j].id })
	selected, _ := target.CurrentThread().Registers()
	for _, l := range live {
		if err := ctx.Err(); err != nil {
			return nil, nil, false, err
		}
		g := isG(l.addr)
		if g == nil {
			continue
		}
		d := goroutine{ID: int64(l.id)}
		// What the goroutine was doing when it last left its thread is in
		// sched; one on a thread is where the thread's registers say.
		pc, bp := word(g, gSchedPC), word(g, schedBP)
		if on, ok := running[l.addr]; ok {
			pc, bp, d.ThreadSystemID = on.pc, on.bp, on.thread
			d.Current = selected != nil && selected.PC() == on.pc && selected.BP() == on.bp
		}
		switch status := binary.LittleEndian.Uint32(g[goid-8:]) &^ gScan; status {
		case 1:
			d.Status = "runnable"
		case 2:
			d.Status = "running"
		case 3:
			d.Status = "syscall"
		case 4:
			d.Status = api.WaitReasonString(&runtime, int64(g[goid+24]))
		case 8:
			d.Status = "copystack"
		default:
			d.Status = fmt.Sprintf("status %d", status)
		}
		d.Frames, d.Cut = walk(pc, bp, func(addr uint64) bool { return inStack(g, addr) })
		for _, frame := range d.Frames {
			if name := frame.Function; name != "" && !standard(name) {
				d.Function = name
				break
			}
		}
		if d.Function == "" && len(d.Frames) > 0 {
			d.Function = d.Frames[0].Function
		}
		out = append(out, d)
	}
	return out, threads, cut, nil
}

// goStack is a stack that was walked without debug information; cut tells
// that it goes deeper than maxFrames.
type goStack struct {
	frames []goFrame
	cut    bool
}

// standard tells whether a function is of the runtime or of the standard
// library's waiting: not where a goroutine's own work is.
func standard(function string) bool {
	for _, prefix := range []string{"runtime.", "internal/", "sync.", "syscall."} {
		if strings.HasPrefix(function, prefix) {
			return true
		}
	}
	return false
}
