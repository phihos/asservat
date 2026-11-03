package syscalls

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

// ArgumentDecoderVersion identifies the argument-only160-byte record ABI.
// Metadata continues to use its unchanged published object and DecodeEvent.
const ArgumentDecoderVersion = "traceloop-x86_64-arguments-v1"
const ArgumentExitMask uint64 = 0xf000000000000000
const ArgumentReturnLength uint64 = 0x0ffffffffffffffe
const ArgumentStringLength uint64 = 0x0fffffffffffffff
const ArgumentIndexLength uint64 = 0x0ffffffffffffff0

var ErrArgumentUnsupported = errors.New("syscalls: unsupported argument definition or bound")
var ErrArgumentRecord = errors.New("syscalls: invalid argument record")

// ArgumentDefinition is the closed reviewed x86_64 table. Values returned by
// ArgumentDefinitions are detached; loaders regenerate them from selection.
type ArgumentDefinition struct {
	Number      uint16
	Name        string
	Lengths     [6]uint64
	ScalarMask  uint8 // scalar register arguments only; never pointer values
	ScalarNames [6]string
	SignedMask  uint8
	MemoryIndex uint8
	MemoryName  string
}

func ArgumentDefinitions(names []string, captureBuffers bool, maxBytesPerEvent int) ([]ArgumentDefinition, error) {
	if len(names) < 1 || len(names) > 6 || maxBytesPerEvent < 1 || maxBytesPerEvent > 4096 {
		return nil, ErrArgumentUnsupported
	}
	seen := map[string]bool{}
	out := make([]ArgumentDefinition, 0, len(names))
	for _, name := range names {
		if seen[name] {
			return nil, ErrArgumentUnsupported
		}
		seen[name] = true
		d := ArgumentDefinition{Name: name, MemoryIndex: 1, MemoryName: "buffer"}
		switch name {
		case "read", "pread64":
			d.Number = 0
			d.ScalarMask = 1<<0 | 1<<2
			d.ScalarNames[0], d.ScalarNames[2] = "fd", "count"
			d.SignedMask = 1
			if name == "pread64" {
				d.Number = 17
				d.ScalarMask |= 1 << 3
				d.ScalarNames[3] = "offset"
				d.SignedMask |= 1 << 3
			}
			if captureBuffers {
				d.Lengths[1] = ArgumentExitMask | ArgumentReturnLength
			}
		case "write", "pwrite64":
			d.Number = 1
			d.ScalarMask = 1<<0 | 1<<2
			d.ScalarNames[0], d.ScalarNames[2] = "fd", "count"
			d.SignedMask = 1
			if name == "pwrite64" {
				d.Number = 18
				d.ScalarMask |= 1 << 3
				d.ScalarNames[3] = "offset"
				d.SignedMask |= 1 << 3
			}
			if captureBuffers {
				d.Lengths[1] = ArgumentIndexLength | 2
			}
		case "openat":
			d.Number = 257
			d.ScalarMask = 1<<0 | 1<<2 | 1<<3
			d.ScalarNames[0], d.ScalarNames[2], d.ScalarNames[3] = "dirfd", "flags", "mode"
			d.SignedMask = 1
			d.MemoryName = "path"
			d.Lengths[1] = ArgumentStringLength
		case "close":
			d.Number = 3
			d.ScalarMask = 1
			d.ScalarNames[0] = "fd"
			d.SignedMask = 1
			d.MemoryName = ""
		default:
			return nil, ErrArgumentUnsupported
		}
		// One helper reads at most128 bytes. Observation credit reserves256
		// separately; it must not impose an unnecessary256-byte acquisition floor.
		if d.Lengths[1] != 0 && maxBytesPerEvent < 128 {
			return nil, ErrArgumentUnsupported
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out, nil
}

func ArgumentDefinitionDigest(defs []ArgumentDefinition) [32]byte {
	b := []byte(ArgumentDecoderVersion)
	for _, d := range defs {
		b = binary.LittleEndian.AppendUint16(b, d.Number)
		for _, n := range d.Lengths {
			b = binary.LittleEndian.AppendUint64(b, n)
		}
		b = append(b, d.ScalarMask, d.SignedMask)
		for _, name := range d.ScalarNames {
			b = append(b, byte(len(name)))
			b = append(b, name...)
		}
	}
	return sha256.Sum256(b)
}

func ArgumentMaxProbeBytes(defs []ArgumentDefinition) uint64 {
	maximum := uint64(256)
	for _, d := range defs {
		var entry, exit uint64
		for _, n := range d.Lengths {
			if n != 0 {
				if n&ArgumentExitMask != 0 {
					exit++
				} else {
					entry++
				}
			}
		}
		maximum = max(maximum, 256+256*max(entry, exit))
	}
	return maximum
}

// ArgumentRecord never retains comm, unselected registers, unused parameter
// bytes or perf alignment padding. Continuations are joined only with their
// exact TID+entry timestamp+phase base; base carries both start incarnations.
type ArgumentRecord struct {
	Type                                     uint32
	Phase                                    uint8
	Number                                   uint16
	PID, TID                                 uint32
	Monotonic, Boot, TaskStart, ProcessStart uint64
	Scalar                                   [6]uint64
	ScalarMask                               uint8
	Ret                                      int64
	Continuations                            uint8
	Index                                    uint8
	Failed, Truncated                        bool
	Data                                     []byte
}

func DecodeArgumentRecord(raw []byte, defs []ArgumentDefinition) (ArgumentRecord, error) {
	var r ArgumentRecord
	if len(raw) < 160 || len(raw) > 167 {
		return r, ErrArgumentRecord
	}
	le := binary.LittleEndian
	r.Type = le.Uint32(raw)
	if r.Type == EventCont {
		r.Monotonic = le.Uint64(raw[136:])
		r.TID = le.Uint32(raw[156:])
		r.Index = raw[152]
		r.Phase = raw[154]
		if r.Monotonic == 0 || r.TID == 0 || r.Index != 1 || r.Phase > 1 || raw[153] > 1 || raw[155] != 0 {
			return ArgumentRecord{}, ErrArgumentRecord
		}
		r.Failed = raw[153] == 1
		length := le.Uint64(raw[144:])
		if length != ArgumentStringLength && length > 128 {
			return ArgumentRecord{}, ErrArgumentRecord
		}
		if r.Failed {
			return r, nil
		}
		if length == ArgumentStringLength {
			length = 128
			for i, b := range raw[4:132] {
				if b == 0 {
					length = uint64(i)
					break
				}
			}
			// At the maximum the helper may have inserted its final NUL after truncation.
			r.Truncated = length >= 127
		} else {
			r.Truncated = length == 128
		}
		r.Data = append([]byte(nil), raw[4:4+length]...)
		return r, nil
	}
	if r.Type != EventEnter && r.Type != EventExit {
		return r, ErrArgumentRecord
	}
	r.PID = le.Uint32(raw[72:])
	r.TID = le.Uint32(raw[104:])
	r.Monotonic = le.Uint64(raw[56:])
	r.Boot = le.Uint64(raw[64:])
	r.Number = le.Uint16(raw[78:])
	r.TaskStart = le.Uint64(raw[112:])
	r.ProcessStart = le.Uint64(raw[120:])
	r.Continuations = raw[96]
	if r.PID == 0 || r.TID == 0 || r.Monotonic == 0 || r.Boot == 0 || r.TaskStart == 0 || r.ProcessStart == 0 || r.TaskStart > r.Boot || r.ProcessStart > r.Boot || le.Uint32(raw[108:]) != 1 || r.Continuations > 1 {
		return ArgumentRecord{}, ErrArgumentRecord
	}
	var definition *ArgumentDefinition
	for i := range defs {
		if defs[i].Number == r.Number {
			definition = &defs[i]
			break
		}
	}
	if definition == nil {
		return ArgumentRecord{}, ErrArgumentRecord
	}
	r.Phase = uint8(r.Type)
	expected := uint8(0)
	if n := definition.Lengths[1]; n != 0 && (n&ArgumentExitMask != 0) == (r.Type == EventExit) {
		expected = 1
	}
	if r.Continuations != expected {
		return ArgumentRecord{}, ErrArgumentRecord
	}
	if r.Type == EventExit {
		r.Ret = int64(le.Uint64(raw[8:]))
	} else {
		r.ScalarMask = definition.ScalarMask
		if definition.Name == "openat" && le.Uint64(raw[24:])&(0100|020000000) == 0 {
			r.ScalarMask &^= 1 << 3
		}
		for i := range r.Scalar {
			if r.ScalarMask&(1<<i) != 0 {
				r.Scalar[i] = le.Uint64(raw[8+8*i:])
			}
		}
	}
	return r, nil
}

// ArgumentProbe is one entry OR exit and its bounded continuation. Pairing
// across phases must additionally match TID, task/process starts and Monotonic.
// An incomplete/missing continuation is a gap, never an invented empty argument.
type ArgumentProbe struct {
	Event  ArgumentRecord
	Memory *ArgumentRecord
}
type argumentKey struct {
	tid   uint32
	phase uint8
}
type ArgumentDecoder struct {
	definitions []ArgumentDefinition
	pending     map[argumentKey]ArgumentRecord
	limit       int
	gaps        uint64
}

func NewArgumentDecoder(names []string, buffers bool, maxBytes, maxTracked int) (*ArgumentDecoder, error) {
	ds, err := ArgumentDefinitions(names, buffers, maxBytes)
	if err != nil || maxTracked < 1 || maxTracked > 16384 {
		return nil, ErrArgumentUnsupported
	}
	return &ArgumentDecoder{definitions: ds, pending: map[argumentKey]ArgumentRecord{}, limit: maxTracked * 2}, nil
}
func (d *ArgumentDecoder) Add(raw []byte) (*ArgumentProbe, error) {
	r, err := DecodeArgumentRecord(raw, d.definitions)
	if err != nil {
		d.gaps++
		return nil, err
	}
	key := argumentKey{r.TID, r.Phase}
	if r.Type == EventCont {
		base, ok := d.pending[key]
		if !ok || base.Monotonic != r.Monotonic {
			d.gaps++
			return nil, nil
		}
		delete(d.pending, key)
		if !r.Failed {
			for _, def := range d.definitions {
				if def.Number != base.Number || def.MemoryName != "buffer" {
					continue
				}
				if base.Type == EventEnter {
					r.Truncated = base.Scalar[2] > uint64(len(r.Data))
				} else {
					r.Truncated = base.Ret > int64(len(r.Data))
				}
			}
		}
		return &ArgumentProbe{Event: base, Memory: &r}, nil
	}
	if _, ok := d.pending[key]; ok {
		delete(d.pending, key)
		d.gaps++
	}
	if r.Continuations == 0 {
		return &ArgumentProbe{Event: r}, nil
	}
	if len(d.pending) >= d.limit {
		d.gaps++
		return nil, nil
	}
	d.pending[key] = r
	return nil, nil
}

// Flush joins no missing records. Call after perf loss and on detach so a
// later continuation cannot repair an uncertain stream.
func (d *ArgumentDecoder) Flush() uint64 {
	d.gaps += uint64(len(d.pending))
	clear(d.pending)
	n := d.gaps
	d.gaps = 0
	return n
}
