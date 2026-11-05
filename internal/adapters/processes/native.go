package processes

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// DecodeProcesses validates the complete bounded JSON value, including strict
// EOF and duplicate-name/UTF-8 rejection, before returning any metadata.
func DecodeProcesses(raw []byte) (artifact.ProcessInventory, error) {
	var p artifact.ProcessInventory
	if len(raw) == 0 || int64(len(raw)) > artifact.ProcessNativeLimit {
		return p, artifact.ErrLimit
	}
	v := jsontext.Value(bytes.Clone(raw))
	if v.Canonicalize() != nil {
		return p, artifact.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return artifact.ProcessInventory{}, artifact.ErrInvalid
	}
	var tail any
	if d.Decode(&tail) != io.EOF || !p.Valid() {
		return artifact.ProcessInventory{}, artifact.ErrInvalid
	}
	return p, nil
}

type ProcessCheck struct {
	e           artifact.ContextExpectation
	from, until time.Time
	data        []byte
	err         error
	closed      bool
}

func NewProcessCheck(e artifact.ContextExpectation, from, until time.Time) (*ProcessCheck, error) {
	if e.NativeType != artifact.ProcessesArtifact || e.DataClass != "metadata" || !e.Processes.Valid() || e.Processes.ActionID != e.ActionID || e.Processes.MaxNativeBytes != e.Registration.NativeLimit || from.IsZero() || until.Before(from) || until.Sub(from) > 5*time.Second {
		return nil, artifact.ErrInvalid
	}
	e.Processes = e.Processes.Clone()
	return &ProcessCheck{e: e, from: from, until: until}, nil
}

func (c *ProcessCheck) Write(p []byte) error {
	if c == nil {
		return artifact.ErrInvalid
	}
	if c.err != nil {
		return c.err
	}
	if c.closed {
		return artifact.ErrInvalid
	}
	if int64(len(p)) > c.e.Registration.NativeLimit-int64(len(c.data)) {
		c.err = artifact.ErrLimit
		clear(c.data)
		c.data = nil
		return c.err
	}
	c.data = append(c.data, p...)
	return nil
}

func (c *ProcessCheck) Close() error {
	if c == nil {
		return artifact.ErrInvalid
	}
	if c.closed {
		return c.err
	}
	c.closed = true
	defer func() { clear(c.data); c.data = nil }()
	if c.err != nil {
		return c.err
	}
	p, e := DecodeProcesses(c.data)
	if e != nil || p.PodUID != c.e.PodUID || p.Mode != c.e.Processes.Mode || p.StartedAt.Before(c.from) || p.CompletedAt.After(c.until) || c.e.NodeUID != "" && c.e.NodeUID != p.NodeUID || c.e.NodeBootID != "" && c.e.NodeBootID != p.NodeBootID {
		c.err = artifact.ErrInvalid
	}
	return c.err
}
