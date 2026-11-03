package syscalls

import (
	"asservat.local/asservat/internal/domain/artifact"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"
)

// ArgumentPairer belongs to exactly one immutable boot/source capture. Neither
// another engine nor a replacement source may reuse its pending halves.
type ArgumentPairer struct {
	limit   int
	pending map[argumentCallKey]ArgumentProbe
	order   []argumentCallKey
}
type argumentCallKey struct {
	tid                 uint32
	task, process, mono uint64
	number              uint16
}
type ArgumentCall struct{ Entry, Exit *ArgumentProbe }

func NewArgumentPairer(limit int) (*ArgumentPairer, error) {
	if limit < 1 || limit > 16384 {
		return nil, ErrArgumentUnsupported
	}
	return &ArgumentPairer{limit: limit, pending: make(map[argumentCallKey]ArgumentProbe)}, nil
}
func argumentHalf(p ArgumentProbe) ArgumentCall {
	if p.Event.Type == EventEnter {
		return ArgumentCall{Entry: &p}
	}
	return ArgumentCall{Exit: &p}
}

// Add tolerates exit-before-entry delivery across CPU rings. A mismatch never
// borrows the arguments of another incarnation or syscall.
func (p *ArgumentPairer) Add(v ArgumentProbe) []ArgumentCall {
	e := v.Event
	k := argumentCallKey{e.TID, e.TaskStart, e.ProcessStart, e.Monotonic, e.Number}
	var out []ArgumentCall
	if old, ok := p.pending[k]; ok {
		delete(p.pending, k)
		if old.Event.Type != e.Type {
			c := ArgumentCall{Entry: &old, Exit: &v}
			if e.Type == EventEnter {
				c = ArgumentCall{Entry: &v, Exit: &old}
			}
			if c.Exit.Event.Boot >= c.Entry.Event.Boot {
				return []ArgumentCall{c}
			}
			return []ArgumentCall{argumentHalf(old), argumentHalf(v)}
		}
		out = append(out, argumentHalf(old))
	}
	for len(p.pending) >= p.limit {
		key := p.order[0]
		p.order = p.order[1:]
		if old, ok := p.pending[key]; ok {
			delete(p.pending, key)
			out = append(out, argumentHalf(old))
		}
	}
	p.pending[k] = v
	p.order = append(p.order, k)
	if len(p.order) > 2*p.limit {
		compact := make([]argumentCallKey, 0, len(p.pending))
		seen := make(map[argumentCallKey]bool, len(p.pending))
		for _, key := range p.order {
			if _, ok := p.pending[key]; ok && !seen[key] {
				seen[key] = true
				compact = append(compact, key)
			}
		}
		p.order = compact
	}
	return out
}
func (p *ArgumentPairer) Flush(emit func(ArgumentCall)) {
	for _, key := range p.order {
		if v, ok := p.pending[key]; ok {
			delete(p.pending, key)
			emit(argumentHalf(v))
		}
	}
	clear(p.order)
	p.order = nil
}
func (c ArgumentCall) Clear() {
	for _, p := range []*ArgumentProbe{c.Entry, c.Exit} {
		if p != nil && p.Memory != nil {
			clear(p.Memory.Data)
		}
	}
}

type ArgumentValue = artifact.ArgumentValue
type RawArgumentEvent = artifact.RawArgumentEvent

// ArgumentEvent uses reversible encodings; a failed read is distinct from a
// successful zero-byte read. It never formats a pointer or executes a string.
func ArgumentEvent(c ArgumentCall, m ArgumentHeader, bootWall time.Time, defs []ArgumentDefinition) (RawArgumentEvent, error) {
	var out RawArgumentEvent
	p := c.Entry
	if p == nil {
		p = c.Exit
	}
	if p == nil || bootWall.IsZero() {
		return out, ErrArgumentRecord
	}
	e := p.Event
	var d *ArgumentDefinition
	for i := range defs {
		if defs[i].Number == e.Number {
			d = &defs[i]
			break
		}
	}
	if d == nil {
		return out, ErrArgumentUnsupported
	}
	ref := func(kind string, id uint32, start uint64) string {
		return kind + ":" + strconv.FormatUint(uint64(id), 10) + ":" + strconv.FormatUint(start, 10) + "@" + m.BootID + "@" + m.SourceEpoch
	}
	out = RawArgumentEvent{Identity: artifact.ArgumentIdentity{ProcessRef: ref("p", e.PID, e.ProcessStart), ThreadRef: ref("t", e.TID, e.TaskStart), PodUID: m.PodUID}, Syscall: d.Name, ABI: ABI, Timestamp: bootWall.Add(time.Duration(e.Boot)).UTC().Format(time.RFC3339Nano), Outcome: "unfinished", Arguments: []ArgumentValue{}}
	if c.Entry == nil {
		out.Outcome = "unmatched"
	} else {
		for i, name := range d.ScalarNames {
			if e.ScalarMask&(1<<i) != 0 {
				value := strconv.FormatUint(e.Scalar[i], 10)
				if d.SignedMask&(1<<i) != 0 {
					value = strconv.FormatInt(int64(e.Scalar[i]), 10)
				}
				out.Arguments = append(out.Arguments, ArgumentValue{Name: name, Value: "decimal:" + value})
			}
		}
	}
	if c.Entry != nil && c.Exit != nil {
		out.Outcome = "success"
		if errno, failed := Errno(c.Exit.Event.Ret); failed {
			out.Outcome = "error"
			out.Errno = errno
		}
		elapsed := c.Exit.Event.Boot - c.Entry.Event.Boot
		if elapsed <= maxDuration {
			out.DurationNS = &elapsed
		}
	}
	for _, probe := range []*ArgumentProbe{c.Entry, c.Exit} {
		if probe == nil || probe.Memory == nil {
			continue
		}
		memory := probe.Memory
		value := "base64:" + base64.StdEncoding.EncodeToString(memory.Data)
		if memory.Failed {
			value = "unavailable:fault"
		}
		out.Arguments = append(out.Arguments, ArgumentValue{Name: d.MemoryName, Value: value, Truncated: memory.Truncated})
	}
	return out, nil
}

const ArgumentNativeFormat = "asservat-syscall-arguments/v1"
const MaxArgumentLine = 8192

// Header contains acquisition provenance only. Argument bytes occur exclusively
// in event records; these header/footer types are not control authority.
type ArgumentHeader = artifact.ArgumentHeader
type ArgumentEventLine = artifact.ArgumentEventLine
type ArgumentFooter = artifact.ArgumentFooter

func AppendArgumentLine(dst []byte, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxArgumentLine {
		return nil, ErrArgumentRecord
	}
	return append(append(dst, b...), '\n'), nil
}
