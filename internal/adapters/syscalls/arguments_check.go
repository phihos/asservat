package syscalls

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

type argumentsCheck struct {
	err         error
	source      artifact.ArgumentSourceProvenance
	e           artifact.ContextExpectation
	from, until time.Time
	line        []byte
	header      *ArgumentHeader
	footer      bool
	events      uint64
	total       int64
	definitions []ArgumentDefinition
}

// NewArgumentCheck consumes independently resolved immutable source facts. The
// publisher composes it alongside the canonical structural schema check.
func NewArgumentCheck(e artifact.ContextExpectation, source artifact.ArgumentSourceProvenance) (*argumentsCheck, error) {
	if !source.Valid() || source.PodUID != e.PodUID || e.Recording == nil || e.Recording.Arguments == nil || e.Recording.Syscalls == nil {
		return nil, artifact.ErrInvalid
	}
	a := e.Recording.Arguments
	definitions, err := ArgumentDefinitions(e.Recording.Syscalls.Names, a.CaptureBuffers, int(a.MaxBytesPerEvent))
	if err != nil || artifact.Digest(ArgumentDefinitionDigest(definitions)) != a.DefinitionDigest || int64(ArgumentMaxProbeBytes(definitions)) != a.MaxProbeBytes {
		return nil, artifact.ErrInvalid
	}
	return &argumentsCheck{e: e, source: source, definitions: definitions}, nil
}
func (c *argumentsCheck) fail(err error) error {
	if c.err == nil {
		c.err = err
	}
	return c.err
}
func argumentDecode(b []byte, v any) error {
	if _, err := jsontext.NewDecoder(bytes.NewReader(b)).ReadValue(); err != nil {
		return artifact.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(v) != nil {
		return artifact.ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return artifact.ErrInvalid
	}
	return nil
}
func (c *argumentsCheck) Write(p []byte) error {
	if c.err != nil {
		return c.err
	}
	c.total += int64(len(p))
	if c.total > c.e.Recording.MaxBytes {
		return c.fail(artifact.ErrLimit)
	}
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		take := p
		if i >= 0 {
			take = p[:i]
		}
		if len(c.line)+len(take) > MaxArgumentLine {
			return c.fail(artifact.ErrLimit)
		}
		c.line = append(c.line, take...)
		if i < 0 {
			return nil
		}
		if err := c.record(c.line); err != nil {
			return c.fail(err)
		}
		clear(c.line)
		c.line = c.line[:0]
		p = p[i+1:]
	}
	return nil
}
func (c *argumentsCheck) record(b []byte) error {
	if c.footer {
		return artifact.ErrIntegrity
	}
	var tag struct {
		Record string `json:"record"`
	}
	if json.Unmarshal(b, &tag) != nil {
		return artifact.ErrInvalid
	}
	switch tag.Record {
	case "header":
		if c.header != nil {
			return artifact.ErrIntegrity
		}
		var h ArgumentHeader
		if argumentDecode(b, &h) != nil {
			return artifact.ErrInvalid
		}
		a := c.e.Recording.Arguments
		if h.PodUID != c.e.PodUID || h.EngineDigest != hex.EncodeToString(a.ProgramDigest[:]) || h.DefinitionDigest != hex.EncodeToString(a.DefinitionDigest[:]) || h.AccountingRule != hex.EncodeToString(a.AccountingRule[:]) || h.StartedAt.Before(c.source.StartedAt) || !h.StartedAt.Before(c.source.StartBy) || h.NodeUID != c.source.NodeUID || h.BootID != c.source.BootID || h.CollectorPodUID != c.source.CollectorPodUID || h.SourceEpoch != c.source.CollectorEpoch || h.SessionID != c.source.SessionID || h.Fence != c.source.Fence || h.Format != ArgumentNativeFormat || h.Decoder != ArgumentDecoderVersion || h.ABI != ABI {
			return artifact.ErrIntegrity
		}
		c.header = &h
		c.from = h.StartedAt
		c.until = c.source.Until
	case "event":
		if c.header == nil {
			return artifact.ErrIntegrity
		}
		var line ArgumentEventLine
		if argumentDecode(b, &line) != nil {
			return artifact.ErrInvalid
		}
		e := line.Event
		at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil || at.Before(c.from) || at.After(c.until) || e.Identity.PodUID != c.e.PodUID || e.ABI != ABI {
			return artifact.ErrIntegrity
		}
		suffix := "@" + c.header.BootID + "@" + c.header.SourceEpoch
		validRef := func(ref, kind string) bool {
			if !strings.HasSuffix(ref, suffix) {
				return false
			}
			parts := strings.Split(strings.TrimSuffix(ref, suffix), ":")
			if len(parts) != 3 || parts[0] != kind {
				return false
			}
			id, err := strconv.ParseUint(parts[1], 10, 32)
			if err != nil || id == 0 || strconv.FormatUint(id, 10) != parts[1] {
				return false
			}
			start, err := strconv.ParseUint(parts[2], 10, 64)
			return err == nil && start > 0 && strconv.FormatUint(start, 10) == parts[2]
		}
		if !validRef(e.Identity.ProcessRef, "p") || !validRef(e.Identity.ThreadRef, "t") || e.Arguments == nil {
			return artifact.ErrIntegrity
		}
		switch e.Outcome {
		case "success", "error":
			if e.DurationNS == nil || *e.DurationNS > uint64(time.Minute) || at.Add(time.Duration(*e.DurationNS)).After(c.until) || (e.Outcome == "error") != (e.Errno != "") {
				return artifact.ErrIntegrity
			}
		case "unfinished", "unmatched":
			if e.DurationNS != nil || e.Errno != "" {
				return artifact.ErrIntegrity
			}
		default:
			return artifact.ErrIntegrity
		}

		if !strings.HasSuffix(e.Identity.ProcessRef, suffix) || !strings.HasSuffix(e.Identity.ThreadRef, suffix) {
			return artifact.ErrIntegrity
		}
		var def *ArgumentDefinition
		for i := range c.definitions {
			if c.definitions[i].Name == e.Syscall {
				def = &c.definitions[i]
				break
			}
		}
		if def == nil {
			return artifact.ErrIntegrity
		}
		names := map[string]bool{}
		for _, a := range e.Arguments {
			if names[a.Name] {
				return artifact.ErrIntegrity
			}
			names[a.Name] = true
			scalar := -1
			for i, name := range def.ScalarNames {
				if name != "" && name == a.Name {
					scalar = i
					break
				}
			}
			if scalar >= 0 {
				if a.Truncated || !strings.HasPrefix(a.Value, "decimal:") {
					return artifact.ErrIntegrity
				}
				text := strings.TrimPrefix(a.Value, "decimal:")
				if def.SignedMask&(1<<scalar) != 0 {
					n, err := strconv.ParseInt(text, 10, 64)
					if err != nil || strconv.FormatInt(n, 10) != text || ((a.Name == "fd" || a.Name == "dirfd") && n != int64(int32(n))) {
						return artifact.ErrIntegrity
					}
				} else {
					n, err := strconv.ParseUint(text, 10, 64)
					if err != nil || strconv.FormatUint(n, 10) != text || ((a.Name == "flags" || a.Name == "mode") && n != uint64(uint32(n))) {
						return artifact.ErrIntegrity
					}
				}
			} else if a.Name == def.MemoryName && def.Lengths[1] != 0 {
				if a.Value == "unavailable:fault" {
					if a.Truncated {
						return artifact.ErrIntegrity
					}
					continue
				}
				if !strings.HasPrefix(a.Value, "base64:") {
					return artifact.ErrIntegrity
				}
				encoded := strings.TrimPrefix(a.Value, "base64:")
				raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
				if err != nil || len(raw) > 128 || base64.StdEncoding.EncodeToString(raw) != encoded {
					clear(raw)
					return artifact.ErrIntegrity
				}
				clear(raw)
			} else {
				return artifact.ErrIntegrity
			}
		}
		c.events++
		if c.events > uint64(c.e.Recording.Syscalls.MaxEvents) {
			return artifact.ErrLimit
		}
	case "footer":
		if c.header == nil {
			return artifact.ErrIntegrity
		}
		var f ArgumentFooter
		if argumentDecode(b, &f) != nil || f.EndedAt.Before(c.from) || f.EndedAt.After(c.until) || f.Retained != c.events || (f.ObservedEvents == nil) != (f.ObservedBytes == nil) || !f.CoverageUnknown {
			return artifact.ErrIntegrity
		}
		if f.Outcome != "completed" && f.Outcome != "cancelled" && f.Outcome != "outputLimit" && f.Outcome != "observationStopped" && f.Outcome != "failed" {
			return artifact.ErrInvalid
		}
		c.footer = true
	default:
		return artifact.ErrInvalid
	}
	return nil
}
func (c *argumentsCheck) Close() error {
	defer clear(c.line)
	if c.err != nil {
		return c.err
	}
	if len(c.line) > 0 || c.header == nil || !c.footer {
		return c.fail(artifact.ErrIntegrity)
	}
	return nil
}
