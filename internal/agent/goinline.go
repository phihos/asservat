package agent

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
)

// The compiler puts small functions into their callers. A stack then has
// fewer frames than the source has calls, and the line of an address is in
// another function than the one whose frame it is. Go's line table records
// for every address which calls were inlined around it, as the runtime
// needs it for its own stack traces. inlineTable reads that from the
// program file, in the format of Go 1.20 and later (runtime/symtab.go,
// internal/abi/symtab.go).
type inlineTable struct {
	quantum   uint64 // the size of the smallest instruction
	text      uint64 // where the functions' offsets count from
	names     []byte // function names, each ended by a zero
	pctab     []byte // tables of values by address
	functab   []byte // the functions by address, and their records
	functions int
	funcdata  []byte // from where the records' data offsets count
}

const (
	lineTableMagic  = 0xfffffff1 // Go 1.20 and later
	pcdataInlTree   = 2          // PCDATA_InlTreeIndex
	funcdataInlTree = 3          // FUNCDATA_InlTree
	inlinedCallSize = 16         // funcID, 3 unused bytes, nameOff, parentPc, startLine
	funcRecordFixed = 44         // the fixed part of a function's record, before its pcdata offsets
)

// openInlineTable reads the line table of a Go program. entries are the
// addresses of some of its functions, the lowest first, as known otherwise
// from the same file.
func openInlineTable(file *elf.File, entries []uint64) (*inlineTable, error) {
	var table *elf.Section
	for _, s := range file.Sections {
		if s.Name == ".gopclntab" || s.Name == ".data.rel.ro.gopclntab" {
			table = s
		}
	}
	if table == nil {
		return nil, errors.New("no Go line table")
	}
	data, err := table.Data()
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	if len(data) < 8+8*8 || le.Uint32(data) != lineTableMagic || data[7] != 8 {
		return nil, errors.New("a line table of another format")
	}
	// The header: magic, two unused bytes, quantum, pointer size; then the
	// counts of functions and files, the text's start, and five offsets.
	field := func(i int) uint64 { return le.Uint64(data[8+8*i:]) }
	t := &inlineTable{quantum: uint64(data[6]), functions: int(field(0))}
	part := func(i int) []byte {
		if field(i) > uint64(len(data)) {
			return nil
		}
		return data[field(i):]
	}
	t.names, t.pctab, t.functab = part(3), part(6), part(7)
	if t.names == nil || t.pctab == nil || len(t.functab) < 8*(t.functions+1) {
		return nil, errors.New("a damaged line table")
	}
	// The table counts the functions' addresses from the start of the Go
	// code, which it does not name in every version: mostly the start of
	// the text, and otherwise near enough that the lowest known function
	// is among its first. The right start is where the known ones are;
	// not all of them, as the list may name more than functions.
	starts := []uint64{}
	if text := file.Section(".text"); text != nil {
		starts = append(starts, text.Addr)
	}
	for i := 0; i < min(t.functions, 256) && len(entries) > 0; i++ {
		starts = append(starts, entries[0]-uint64(le.Uint32(t.functab[8*i:])))
	}
	best, most := uint64(0), 0
	for _, start := range starts {
		t.text = start
		found := 0
		for _, entry := range entries {
			if t.index(entry) >= 0 {
				found++
			}
		}
		if found > most {
			best, most = start, found
		}
	}
	if 2*most <= len(entries) {
		return nil, errors.New("the line table's functions are not the program's")
	}
	t.text = best

	// The inlining of a function is among its data, at an offset from an
	// address that only the runtime's module record holds. That record
	// starts with the line table's address; where it lies and what follows
	// in it changes between Go versions, so the address is recognized by
	// what it must lead to.
	var loaded []*elf.Section
	contents := map[*elf.Section][]byte{}
	for _, s := range file.Sections {
		if s.Type == elf.SHT_PROGBITS && s.Flags&elf.SHF_ALLOC != 0 && s.Flags&elf.SHF_EXECINSTR == 0 {
			if contents[s], err = s.Data(); err != nil {
				return nil, err
			}
			loaded = append(loaded, s)
		}
	}
	// A module record is no longer than this many words in any Go version.
	const moduleWords = 80
	for _, s := range loaded {
		module := contents[s]
		for at := 0; at+8 <= len(module) && t.funcdata == nil; at += 8 {
			if le.Uint64(module[at:]) != table.Addr {
				continue
			}
			for field := at + 8; field+8 <= len(module) && field < at+moduleWords*8 && t.funcdata == nil; field += 8 {
				addr := le.Uint64(module[field:])
				for _, in := range loaded {
					if addr >= in.Addr && addr < in.Addr+in.Size {
						if t.funcdata = contents[in][addr-in.Addr:]; !t.plausible() {
							t.funcdata = nil
						}
					}
				}
			}
		}
	}
	if t.funcdata == nil {
		return nil, errors.New("the functions' data was not found")
	}
	return t, nil
}

// record returns the record of the function that starts at entry, and the
// offsets of its table pcdata and its data funcdata, or ok false.
func (t *inlineTable) record(entry uint64, pcdata, funcdata int) (tableAt, dataAt uint32, ok bool) {
	le := binary.LittleEndian
	i := t.index(entry)
	if i < 0 {
		return 0, 0, false
	}
	at := int(le.Uint32(t.functab[8*i+4:]))
	if at+funcRecordFixed > len(t.functab) {
		return 0, 0, false
	}
	f := t.functab[at:]
	tables, datas := int(le.Uint32(f[28:])), int(f[43])
	if pcdata >= tables || funcdata >= datas || funcRecordFixed+4*(tables+datas) > len(f) {
		return 0, 0, false
	}
	tableAt = le.Uint32(f[funcRecordFixed+4*pcdata:])
	dataAt = le.Uint32(f[funcRecordFixed+4*(tables+funcdata):])
	// No table is offset 0, no data is offset -1.
	return tableAt, dataAt, tableAt != 0 && dataAt != ^uint32(0)
}

// index returns which of the table's functions starts at entry, or -1.
func (t *inlineTable) index(entry uint64) int {
	le := binary.LittleEndian
	lo, hi := 0, t.functions
	for lo < hi {
		if mid := (lo + hi) / 2; t.text+uint64(le.Uint32(t.functab[8*mid:])) < entry {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == t.functions || t.text+uint64(le.Uint32(t.functab[8*lo:])) != entry {
		return -1
	}
	return lo
}

// value looks an address up in a table of values by address: pairs of a
// value's change and the length it holds for, as variable-length numbers.
func (t *inlineTable) value(table uint32, entry, pc uint64) int {
	if uint64(table) >= uint64(len(t.pctab)) {
		return -1
	}
	p, at, value := t.pctab[table:], entry, -1
	for first := true; ; first = false {
		change, n := binary.Uvarint(p)
		if n <= 0 || change == 0 && !first {
			return -1
		}
		p = p[n:]
		if change&1 != 0 {
			value += int(^(change >> 1))
		} else {
			value += int(change >> 1)
		}
		length, n := binary.Uvarint(p)
		if n <= 0 {
			return -1
		}
		p = p[n:]
		if at += length * t.quantum; pc < at {
			return value
		}
	}
}

// call reads one record of a function's inlining: the name of the function
// that was inlined and the offset of its call in the function it is in.
func (t *inlineTable) call(data uint32, index int) (name string, parent uint64, ok bool) {
	at := int(data) + inlinedCallSize*index
	if index < 0 || at+inlinedCallSize > len(t.funcdata) {
		return "", 0, false
	}
	c := t.funcdata[at:]
	nameAt := int(binary.LittleEndian.Uint32(c[4:]))
	// A name starts the names or follows the end of another.
	if c[1]|c[2]|c[3] != 0 || nameAt < 0 || nameAt >= len(t.names) || nameAt > 0 && t.names[nameAt-1] != 0 {
		return "", 0, false
	}
	end := bytes.IndexByte(t.names[nameAt:], 0)
	if end <= 0 {
		return "", 0, false
	}
	return string(t.names[nameAt : nameAt+end]), uint64(binary.LittleEndian.Uint32(c[8:])), true
}

// plausible tells whether the functions' data is where the table assumes:
// the inlining of the first functions that have one reads as such.
func (t *inlineTable) plausible() bool {
	checked := 0
	for i := 0; i < t.functions && checked < 32; i++ {
		entry := t.text + uint64(binary.LittleEndian.Uint32(t.functab[8*i:]))
		if _, data, ok := t.record(entry, pcdataInlTree, funcdataInlTree); ok {
			if _, _, ok := t.call(data, 0); !ok {
				return false
			}
			checked++
		}
	}
	return checked > 0
}

// inlinedCall is a call that the compiler put into its caller.
type inlinedCall struct {
	function string // the function that was inlined
	caller   uint64 // the address of its call
}

// at returns the calls that were inlined around an address of the function
// that starts at entry, innermost first. The function itself is not among
// them; its line is that of the last call's address.
func (t *inlineTable) at(entry, pc uint64) []inlinedCall {
	table, data, ok := t.record(entry, pcdataInlTree, funcdataInlTree)
	if !ok {
		return nil
	}
	var calls []inlinedCall
	// A call is inlined into a call: no more deep than a function is long.
	for range 64 {
		name, parent, ok := t.call(data, t.value(table, entry, pc))
		if !ok {
			break
		}
		pc = entry + parent
		calls = append(calls, inlinedCall{name, pc})
	}
	return calls
}
