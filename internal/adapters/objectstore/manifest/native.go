package manifest

import (
	"bytes"
	"encoding/binary"
	"encoding/json/jsontext"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// NativeCheck validates one native stream incrementally while it is encoded or
// read back. It retains at most one bounded record (a PCAPNG block or a JSON
// line) or, for single-document types, the bounded document; never a whole
// recording. A failed check is terminal. It grants no disclosure.
type NativeCheck interface {
	Write(p []byte) error
	Close() error // final check at the exact end of the native stream
}

// Bounds for streaming checks. PCAPNG blocks of the metadata profile hold
// headers only; the bound also covers a full 64 KiB snapshot length.
const (
	MaxPCAPNGBlock  = 256 << 10
	MaxSyscallEvent = 16 << 10
)

// NativeCheck returns the type's validator. The manifest supplies the
// acquisition interval that record times must fall within.
func (v *Validator) NativeCheck(e artifact.ContextExpectation, m ContextManifest) (NativeCheck, error) {
	if v == nil || e.Validate() != nil {
		return nil, artifact.ErrInvalid
	}
	switch e.NativeType {
	case artifact.PodStatusArtifact:
		return &documentCheck{limit: artifact.MaxContextBytes, final: func(b []byte) error { return v.ValidateNative(b, e, m) }}, nil
	case artifact.HTTPHeadersArtifact:
		return &documentCheck{limit: artifact.HTTPHeadersNativeLimit, final: jsonObject}, nil
	case artifact.PCAPNGArtifact:
		return &pcapngCheck{}, nil
	case artifact.SyscallRecordsArtifact:
		return &syscallCheck{v: v, pod: e.PodUID, from: m.StartedAt, until: m.CompletedAt}, nil
	}
	return nil, artifact.ErrInvalid
}

type failure struct{ err error }

func (f *failure) fail(err error) error {
	if f.err == nil {
		f.err = err
	}
	return f.err
}

type documentCheck struct {
	failure
	limit int64
	buf   bytes.Buffer
	final func([]byte) error
}

func (c *documentCheck) Write(p []byte) error {
	if c.err != nil {
		return c.err
	}
	if int64(len(p)) > c.limit-int64(c.buf.Len()) {
		return c.fail(artifact.ErrLimit)
	}
	c.buf.Write(p)
	return nil
}
func (c *documentCheck) Close() error {
	defer clear(c.buf.Bytes())
	if c.err != nil {
		return c.err
	}
	return c.fail(c.final(c.buf.Bytes()))
}

// jsonObject accepts exactly one strict JSON object (no duplicate names,
// valid UTF-8, nothing trailing), as for the HTTP header projection.
func jsonObject(b []byte) error {
	v := jsontext.Value(b)
	if !v.IsValid() || v.Kind() != '{' {
		return artifact.ErrIntegrity
	}
	return nil
}

// pcapngCheck walks the block structure (pcapng draft-ietf-opsawg-pcapng):
// every section starts with a Section Header Block whose byte-order magic
// fixes its endianness; lengths are bounded, 32-bit aligned and repeated in
// the trailer; packets reference a described interface and fit its snapshot
// length. Only section header, interface description, enhanced packet and
// interface statistics blocks are accepted: the metadata profile carries no
// name resolution, decryption secrets or custom blocks.
type pcapngCheck struct {
	failure
	pending  []byte
	order    binary.ByteOrder
	snaplens []uint32
	blocks   int64
}

const (
	pcapngSHB = 0x0A0D0D0A
	pcapngIDB = 1
	pcapngISB = 5
	pcapngEPB = 6
)

func (c *pcapngCheck) Write(p []byte) error {
	if c.err != nil {
		return c.err
	}
	c.pending = append(c.pending, p...)
	off := 0
	defer func() {
		// Compact once per write; only an incomplete trailing block remains.
		rest := copy(c.pending, c.pending[off:])
		clear(c.pending[rest:])
		c.pending = c.pending[:rest]
	}()
	for {
		head := c.pending[off:]
		if len(head) < 12 {
			return nil
		}
		typ := binary.LittleEndian.Uint32(head) // SHB type is byte-order independent
		if typ == pcapngSHB {
			switch {
			case bytes.Equal(head[8:12], []byte{0x4d, 0x3c, 0x2b, 0x1a}):
				c.order = binary.LittleEndian
			case bytes.Equal(head[8:12], []byte{0x1a, 0x2b, 0x3c, 0x4d}):
				c.order = binary.BigEndian
			default:
				return c.fail(artifact.ErrIntegrity)
			}
			c.snaplens = c.snaplens[:0]
		} else if c.order == nil {
			return c.fail(artifact.ErrIntegrity) // the stream must start with a section header
		} else {
			typ = c.order.Uint32(head)
		}
		n := c.order.Uint32(head[4:])
		if n < 12 || n%4 != 0 || n > MaxPCAPNGBlock {
			return c.fail(artifact.ErrIntegrity)
		}
		if uint32(len(head)) < n {
			return nil
		}
		if c.order.Uint32(head[n-4:]) != n || c.block(typ, head[8:n-4]) != nil {
			return c.fail(artifact.ErrIntegrity)
		}
		c.blocks++
		off += int(n)
	}
}

func (c *pcapngCheck) block(typ uint32, body []byte) error {
	switch typ {
	case pcapngSHB:
		if len(body) < 16 || c.order.Uint16(body[4:]) != 1 {
			return artifact.ErrIntegrity
		}
	case pcapngIDB:
		if len(body) < 8 {
			return artifact.ErrIntegrity
		}
		c.snaplens = append(c.snaplens, c.order.Uint32(body[4:]))
		if len(c.snaplens) > 4096 {
			return artifact.ErrLimit
		}
	case pcapngEPB:
		if len(body) < 20 {
			return artifact.ErrIntegrity
		}
		iface, captured, original := c.order.Uint32(body), c.order.Uint32(body[12:]), c.order.Uint32(body[16:])
		if iface >= uint32(len(c.snaplens)) || captured > original || (int64(captured)+3)/4*4 > int64(len(body)-20) || c.snaplens[iface] != 0 && captured > c.snaplens[iface] {
			return artifact.ErrIntegrity
		}
	case pcapngISB:
		if len(body) < 12 || c.order.Uint32(body) >= uint32(len(c.snaplens)) {
			return artifact.ErrIntegrity
		}
	default:
		return artifact.ErrIntegrity
	}
	return nil
}

func (c *pcapngCheck) Close() error {
	defer clear(c.pending)
	if c.err != nil {
		return c.err
	}
	if len(c.pending) != 0 || c.blocks == 0 {
		return c.fail(artifact.ErrIntegrity)
	}
	return nil
}

// syscallCheck validates JSON Lines: every line is one strict event of
// syscall-results.schema.json#/$defs/event for the expected pod, recorded
// within the acquisition interval. An empty file is a quiet interval.
type syscallCheck struct {
	failure
	v           *Validator
	pod         string
	from, until time.Time
	line        []byte
}

func (c *syscallCheck) Write(p []byte) error {
	if c.err != nil {
		return c.err
	}
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		take := p
		if i >= 0 {
			take = p[:i]
		}
		if len(c.line)+len(take) > MaxSyscallEvent {
			return c.fail(artifact.ErrLimit)
		}
		c.line = append(c.line, take...)
		if i < 0 {
			return nil
		}
		if err := c.event(c.line); err != nil {
			return c.fail(err)
		}
		clear(c.line)
		c.line = c.line[:0]
		p = p[i+1:]
	}
	return nil
}

func (c *syscallCheck) event(b []byte) error {
	v, err := strict(b, MaxSyscallEvent)
	if err != nil {
		return err
	}
	if c.v.syscallEvent.Validate(v) != nil {
		return artifact.ErrInvalid
	}
	m := v.(map[string]any)
	at, err := time.Parse(time.RFC3339Nano, m["timestamp"].(string))
	if err != nil || m["identity"].(map[string]any)["pod_uid"] != c.pod || at.Before(c.from) || at.After(c.until) {
		return artifact.ErrIntegrity
	}
	return nil
}

func (c *syscallCheck) Close() error {
	defer clear(c.line)
	if c.err != nil {
		return c.err
	}
	if len(c.line) != 0 {
		return c.fail(artifact.ErrIntegrity) // every event ends with a newline
	}
	return nil
}
