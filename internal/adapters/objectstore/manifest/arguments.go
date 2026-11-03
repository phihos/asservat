package manifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

const MaxArgumentNativeLine = 8192

type argumentsCheck struct {
	failure
	v           *Validator
	e           artifact.ContextExpectation
	from, until time.Time
	line        []byte
	header      *artifact.ArgumentHeader
	footer      bool
	events      uint64
	total       int64
}

func newArgumentsCheck(v *Validator, e artifact.ContextExpectation, m ContextManifest) (NativeCheck, error) {
	if e.Recording == nil || e.Recording.Arguments == nil || e.Recording.Syscalls == nil {
		return nil, artifact.ErrInvalid
	}
	return &argumentsCheck{v: v, e: e, from: m.StartedAt, until: m.CompletedAt}, nil
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
		if len(c.line)+len(take) > MaxArgumentNativeLine {
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
	value, err := strict(b, MaxArgumentNativeLine)
	if err != nil {
		return err
	}
	if c.v.syscallArguments.Validate(value) != nil {
		return artifact.ErrInvalid
	}
	m := value.(map[string]any)
	switch m["record"] {
	case "header":
		if c.header != nil {
			return artifact.ErrIntegrity
		}
		var h artifact.ArgumentHeader
		if json.Unmarshal(b, &h) != nil {
			return artifact.ErrInvalid
		}
		a := c.e.Recording.Arguments
		if h.PodUID != c.e.PodUID || h.EngineDigest != hex.EncodeToString(a.ProgramDigest[:]) || h.DefinitionDigest != hex.EncodeToString(a.DefinitionDigest[:]) || h.AccountingRule != hex.EncodeToString(a.AccountingRule[:]) || !h.StartedAt.Equal(c.from) {
			return artifact.ErrIntegrity
		}
		c.header = &h
	case "event":
		if c.header == nil {
			return artifact.ErrIntegrity
		}
		var line artifact.ArgumentEventLine
		if json.Unmarshal(b, &line) != nil {
			return artifact.ErrInvalid
		}
		e := line.Event
		at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil || at.Before(c.from) || at.After(c.until) || e.Identity.PodUID != c.e.PodUID || e.ABI != "x86_64" {
			return artifact.ErrIntegrity
		}
		allowed := false
		for _, name := range c.e.Recording.Syscalls.Names {
			if e.Syscall == name {
				allowed = true
				break
			}
		}
		if !allowed {
			return artifact.ErrIntegrity
		}
		c.events++
		if c.events > uint64(c.e.Recording.Syscalls.MaxEvents) {
			return artifact.ErrLimit
		}
	case "footer":
		if c.header == nil {
			return artifact.ErrIntegrity
		}
		var f artifact.ArgumentFooter
		if json.Unmarshal(b, &f) != nil || !f.EndedAt.Equal(c.until) || f.Retained != c.events || (f.ObservedEvents == nil) != (f.ObservedBytes == nil) || !f.CoverageUnknown {
			return artifact.ErrIntegrity
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
