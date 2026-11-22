package hub

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf16"

	"github.com/google/pprof/profile"
)

// A .NET trace (*.nettrace, written by dotnet-trace and dotnet-monitor) is
// shown as a profile: the hub turns the runtime's samples of the threads'
// stacks into pprof's format, which pprof's viewer shows like any other
// profile. This is the view that PerfView and "dotnet-trace report" give of
// such a trace. Its other events (garbage collections, exceptions and so
// on) are not shown; the file downloads for PerfView.
//
// The format is "Nettrace" version 4, which .NET 5 to 10 write: a list of
// objects, of which the blocks of events, of event descriptions
// ("metadata") and of stacks matter here.

const (
	// The runtime's sample of a thread's stack.
	nettraceSampler, nettraceSample = "Microsoft-DotNETCore-SampleProfiler", 0
	// A compiled method with its address: reported when it is compiled
	// during the trace, and for all methods when the trace ends.
	nettraceRuntime, nettraceMethodLoad   = "Microsoft-Windows-DotNETRuntime", 143
	nettraceRundown, nettraceMethodDCEnd  = "Microsoft-Windows-DotNETRuntimeRundown", 144
	nettraceNative                        = "[native code]"
	nettraceSamplingWhenTheTraceTellsNone = time.Millisecond
)

// nettraceReader reads a trace that is held in memory: blocks are aligned
// to the file, so the position matters.
type nettraceReader struct {
	b  []byte
	at int
}

var errNettraceShort = errors.New("the trace ends in the middle of an object")

func (r *nettraceReader) take(n int) ([]byte, error) {
	if n < 0 || r.at+n > len(r.b) {
		return nil, errNettraceShort
	}
	r.at += n
	return r.b[r.at-n : r.at], nil
}
func (r *nettraceReader) u8() (byte, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}
func (r *nettraceReader) i32() (int32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(b)), nil
}
func (r *nettraceReader) u64() (uint64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// varint reads a number of 7 bits per byte, the lowest first.
func (r *nettraceReader) varint() (uint64, error) {
	var n uint64
	for shift := 0; shift < 70; shift += 7 {
		b, err := r.u8()
		if err != nil {
			return 0, err
		}
		n |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return n, nil
		}
	}
	return 0, errors.New("a number in the trace is longer than a number can be")
}

// wide reads a string of UTF-16 units that a zero ends.
func (r *nettraceReader) wide() (string, error) {
	var units []uint16
	for {
		b, err := r.take(2)
		if err != nil {
			return "", err
		}
		u := binary.LittleEndian.Uint16(b)
		if u == 0 {
			return string(utf16.Decode(units)), nil
		}
		units = append(units, u)
	}
}

// str reads a string with its length in bytes before it.
func (r *nettraceReader) str() (string, error) {
	n, err := r.i32()
	if err != nil {
		return "", err
	}
	b, err := r.take(int(n))
	return string(b), err
}

// nettraceMethod is a compiled method: where its code is and its name.
type nettraceMethod struct {
	start, size uint64
	name        string
}

// nettraceProfile turns the stack samples of a .NET trace into a profile.
func nettraceProfile(trace []byte) (*profile.Profile, error) {
	r := &nettraceReader{b: trace}
	if magic, err := r.take(8); err != nil || string(magic) != "Nettrace" {
		return nil, errors.New("the file does not begin as a .NET trace (nettrace)")
	}
	if serialization, err := r.str(); err != nil || serialization != "!FastSerialization.1" {
		return nil, errors.New("the file does not begin as a .NET trace (nettrace)")
	}
	type described struct {
		provider string
		event    int32
	}
	type sampled struct {
		thread uint64
		stack  string // the addresses, as the trace holds them
	}
	var (
		meta     = map[uint32]described{}
		methods  []nettraceMethod
		counts   = map[sampled]int64{}
		pointer  = 8
		interval = nettraceSamplingWhenTheTraceTellsNone
		// Events name their stacks by a number that holds until the next
		// sequence point, and a stack can follow its events.
		stacks  = map[uint32]string{}
		pending []struct {
			thread uint64
			stack  uint32
		}
	)
	settle := func() {
		for _, p := range pending {
			counts[sampled{p.thread, stacks[p.stack]}]++
		}
		pending, stacks = nil, map[uint32]string{}
	}
	// event takes one event: a description of events, a sample or a method.
	event := func(metadata bool, id uint32, thread uint64, stack uint32, payload []byte) error {
		p := &nettraceReader{b: payload}
		if metadata {
			defined, err := p.i32()
			if err != nil {
				return err
			}
			provider, err := p.wide()
			if err != nil {
				return err
			}
			number, err := p.i32()
			if err != nil {
				return err
			}
			meta[uint32(defined)] = described{provider, number}
			return nil
		}
		switch meta[id] {
		case described{nettraceSampler, nettraceSample}:
			pending = append(pending, struct {
				thread uint64
				stack  uint32
			}{thread, stack})
		case described{nettraceRuntime, nettraceMethodLoad}, described{nettraceRundown, nettraceMethodDCEnd}:
			// The method's and its module's IDs, the address and size of its code, its token and flags, then its names.
			if _, err := p.take(16); err != nil {
				return err
			}
			start, err := p.u64()
			if err != nil {
				return err
			}
			size, err := p.i32()
			if err != nil {
				return err
			}
			if _, err := p.take(8); err != nil {
				return err
			}
			namespace, err := p.wide()
			if err != nil {
				return err
			}
			name, err := p.wide()
			if err != nil {
				return err
			}
			if namespace != "" {
				name = namespace + "." + name
			}
			methods = append(methods, nettraceMethod{start, uint64(uint32(size)), name})
		}
		return nil
	}
	// block reads the events of a block of events or of metadata.
	events := func(b []byte, metadata bool) error {
		p := &nettraceReader{b: b}
		head, err := p.take(4)
		if err != nil {
			return err
		}
		headerSize, flags := int(binary.LittleEndian.Uint16(head)), binary.LittleEndian.Uint16(head[2:])
		if _, err := p.take(headerSize - 4); err != nil {
			return err
		}
		if flags&1 == 0 {
			// Every event with its whole header, padded to four bytes.
			for p.at < len(p.b) {
				size, err := p.i32()
				if err != nil {
					return err
				}
				whole, err := p.take(int(size))
				if err != nil {
					return err
				}
				e := &nettraceReader{b: whole}
				id, _ := e.i32()
				e.take(4) // the sequence number
				thread, _ := e.u64()
				e.take(12) // the capturing thread and its processor
				stack, _ := e.i32()
				e.take(8 + 16 + 16) // the time and two activity IDs
				length, err := e.i32()
				if err != nil {
					return err
				}
				payload, err := e.take(int(length))
				if err != nil {
					return err
				}
				if err := event(metadata, uint32(id)&0x7fffffff, thread, uint32(stack), payload); err != nil {
					return err
				}
				if pad := (4 - p.at%4) % 4; pad > 0 && p.at < len(p.b) {
					p.take(pad)
				}
			}
			return nil
		}
		// Compressed headers: a field that the flags leave out is that of the event before.
		var id, stack, length uint32
		var thread uint64
		for p.at < len(p.b) {
			flags, err := p.u8()
			if err != nil {
				return err
			}
			number := func(present byte, into func(uint64)) {
				if err == nil && flags&present != 0 {
					var n uint64
					if n, err = p.varint(); err == nil {
						into(n)
					}
				}
			}
			number(1, func(n uint64) { id = uint32(n) })
			number(2, func(uint64) {}) // the sequence number,
			number(2, func(uint64) {}) // the capturing thread
			number(2, func(uint64) {}) // and its processor
			number(4, func(n uint64) { thread = n })
			number(8, func(n uint64) { stack = uint32(n) })
			if err == nil {
				_, err = p.varint() // the time, which every event has
			}
			for _, activity := range []byte{16, 32} {
				if err == nil && flags&activity != 0 {
					_, err = p.take(16)
				}
			}
			number(128, func(n uint64) { length = uint32(n) })
			if err != nil {
				return err
			}
			payload, err := p.take(int(length))
			if err != nil {
				return err
			}
			if err := event(metadata, id&0x7fffffff, thread, stack, payload); err != nil {
				return err
			}
		}
		return nil
	}

	for {
		tag, err := r.u8()
		if err != nil {
			return nil, err
		}
		if tag == 1 { // the end of the objects
			break
		}
		// An object: its type (a nested object of versions and a name), its content, and a closing tag.
		head, err := r.take(2)
		if err != nil || tag != 5 || head[0] != 5 || head[1] != 1 {
			return nil, errors.New("the trace holds something that is no object")
		}
		version, _ := r.i32()
		r.i32() // the oldest reader that understands it
		name, err := r.str()
		if end, _ := r.u8(); err != nil || end != 6 {
			return nil, errNettraceShort
		}
		if name == "Trace" {
			if version != 4 {
				return nil, fmt.Errorf("the trace is of format version %d; version 4, which .NET 5 to 10 write, is shown here", version)
			}
			// The time of the trace as a date and as a counter, the counter's frequency, then four numbers.
			if _, err := r.take(16 + 8 + 8); err != nil {
				return nil, err
			}
			size, _ := r.i32()
			r.take(8) // the process and the number of processors
			rate, err := r.i32()
			if err != nil {
				return nil, err
			}
			if size == 4 {
				pointer = 4
			}
			if rate > 0 {
				interval = time.Duration(rate) // in nanoseconds
			}
		} else {
			// A block: its size, padding to four bytes of the file, its content.
			size, err := r.i32()
			if err != nil {
				return nil, err
			}
			r.at += (4 - r.at%4) % 4
			block, err := r.take(int(size))
			if err != nil {
				return nil, err
			}
			switch name {
			case "EventBlock":
				err = events(block, false)
			case "MetadataBlock":
				err = events(block, true)
			case "StackBlock":
				b := &nettraceReader{b: block}
				first, _ := b.i32()
				count, err := b.i32()
				for i := int32(0); err == nil && i < count; i++ {
					var n int32
					var addresses []byte
					if n, err = b.i32(); err == nil {
						if addresses, err = b.take(int(n)); err == nil {
							stacks[uint32(first+i)] = string(addresses)
						}
					}
				}
			case "SPBlock": // a sequence point
				settle()
			}
			if err != nil {
				return nil, fmt.Errorf("a %s of the trace cannot be read: %w", name, err)
			}
		}
		if end, err := r.u8(); err != nil || end != 6 {
			return nil, errNettraceShort
		}
	}
	settle()
	if len(counts) == 0 {
		return nil, errors.New("the trace holds no samples of the threads' stacks; it was recorded without the sample profiler")
	}

	// The profile: every sampled stack with the methods that its addresses lie in.
	sort.Slice(methods, func(i, j int) bool { return methods[i].start < methods[j].start })
	named := func(address uint64) string {
		i := sort.Search(len(methods), func(i int) bool { return methods[i].start > address }) - 1
		if i < 0 || address >= methods[i].start+methods[i].size {
			return nettraceNative
		}
		return methods[i].name
	}
	period := interval.Nanoseconds()
	prof := &profile.Profile{
		SampleType: []*profile.ValueType{{Type: "samples", Unit: "count"}, {Type: "thread_time", Unit: "nanoseconds"}},
		PeriodType: &profile.ValueType{Type: "thread_time", Unit: "nanoseconds"},
		Period:     period,
		Comments: []string{"Converted by Asservat from a .NET trace: the runtime's samples of every managed thread's stack, taken every " +
			interval.String() + " whether the thread ran or waited. Addresses outside of compiled .NET methods are shown as " + nettraceNative + "."},
	}
	functions := map[string]*profile.Function{}
	locations := map[string]*profile.Location{}
	location := func(name string) *profile.Location {
		l := locations[name]
		if l == nil {
			f := &profile.Function{ID: uint64(len(prof.Function) + 1), Name: name, SystemName: name}
			functions[name] = f
			prof.Function = append(prof.Function, f)
			l = &profile.Location{ID: uint64(len(prof.Location) + 1), Line: []profile.Line{{Function: f}}}
			locations[name] = l
			prof.Location = append(prof.Location, l)
		}
		return l
	}
	keys := make([]sampled, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { // in a fixed order
		if keys[i].thread != keys[j].thread {
			return keys[i].thread < keys[j].thread
		}
		return keys[i].stack < keys[j].stack
	})
	for _, key := range keys {
		sample := &profile.Sample{
			Value:    []int64{counts[key], counts[key] * period},
			NumLabel: map[string][]int64{"thread": {int64(key.thread)}},
		}
		// The addresses run from the innermost frame outwards. Frames that
		// follow each other outside of .NET methods are shown as one.
		last := ""
		for at := 0; at+pointer <= len(key.stack); at += pointer {
			address := uint64(binary.LittleEndian.Uint32([]byte(key.stack[at : at+4])))
			if pointer == 8 {
				address = binary.LittleEndian.Uint64([]byte(key.stack[at : at+8]))
			}
			name := named(address)
			if name == nettraceNative && last == nettraceNative {
				continue
			}
			last = name
			sample.Location = append(sample.Location, location(name))
		}
		if len(sample.Location) == 0 {
			sample.Location = []*profile.Location{location("[no stack]")}
		}
		prof.Sample = append(prof.Sample, sample)
	}
	return prof, prof.CheckValid()
}
