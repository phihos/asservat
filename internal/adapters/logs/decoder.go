package logs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"io"

	"asservat.local/asservat/internal/domain/artifact"
)

// decode rejects unknown/missing/duplicate fields and scalar nulls. Nullable
// provenance and source/fetch times are explicit fields, never omitted guesses.
func decode(raw []byte, v any) error {
	if _, err := jsontext.NewDecoder(bytes.NewReader(raw)).ReadValue(); err != nil {
		return artifact.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return artifact.ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return artifact.ErrInvalid
	}
	normalized, err := json.Marshal(v)
	if err != nil {
		return artifact.ErrInvalid
	}
	var expected map[string]json.RawMessage
	_ = json.Unmarshal(normalized, &expected)
	if len(fields) != len(expected) {
		return artifact.ErrInvalid
	}
	for name, value := range fields {
		want, ok := expected[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !bytes.Equal(want, []byte("null")) {
			return artifact.ErrInvalid
		}
	}
	return nil
}

// Walk consumes and validates the complete canonical record sequence and EOF.
// Visitors see provisional records; callers must not publish a page until Walk
// succeeds AND their independently authenticated source has finalized and closed.
// Working storage is bounded by one 8KiB line and at most128 provenance keys.
func Walk(ctx context.Context, r io.Reader, maxBytes int64, v Visitor) (artifact.LogFooter, error) {
	var zero artifact.LogFooter
	if ctx == nil || r == nil || maxBytes < 1 || maxBytes > artifact.LogNativeLimit {
		return zero, artifact.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	limited := &io.LimitedReader{R: r, N: maxBytes + 1}
	reader := bufio.NewReaderSize(limited, artifact.LogMaxLine+1)
	var s state
	var footer artifact.LogFooter
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		line, err := reader.ReadSlice('\n')
		if cancel := ctx.Err(); cancel != nil {
			clear(line)
			return zero, cancel
		}
		if limited.N == 0 || len(line) > artifact.LogMaxLine {
			clear(line)
			return zero, artifact.ErrLimit
		}
		if err == io.EOF && len(line) == 0 {
			if !s.footer {
				return zero, artifact.ErrInvalid
			}
			return footer, nil
		}
		if err != nil {
			clear(line)
			return zero, err
		}
		record, err := parseRecord(line)
		clear(line)
		if err != nil {
			return zero, err
		}
		if err = s.consume(record); err != nil {
			return zero, err
		}
		if x, ok := record.(artifact.LogFooter); ok {
			footer = x
		}
		if err = visitRecord(v, record); err != nil {
			return zero, err
		}
	}
}

// parseRecord is shared by pull and incremental validators; neither path has a
// weaker JSON/order grammar.
func parseRecord(line []byte) (any, error) {
	var tag struct {
		Record string `json:"record"`
	}
	if json.Unmarshal(line, &tag) != nil {
		return nil, artifact.ErrInvalid
	}
	switch tag.Record {
	case "header":
		var x artifact.LogHeader
		err := decode(line, &x)
		return x, err
	case "origin":
		var x artifact.LogOrigin
		err := decode(line, &x)
		return x, err
	case "fragment":
		var x artifact.LogFragment
		err := decode(line, &x)
		return x, err
	case "coverage":
		var x artifact.LogCoverage
		err := decode(line, &x)
		return x, err
	case "footer":
		var x artifact.LogFooter
		err := decode(line, &x)
		return x, err
	}
	return nil, artifact.ErrInvalid
}
func visitRecord(v Visitor, r any) error {
	switch x := r.(type) {
	case artifact.LogHeader:
		if v.Header != nil {
			return v.Header(x)
		}
	case artifact.LogOrigin:
		if v.Origin != nil {
			return v.Origin(x)
		}
	case artifact.LogFragment:
		if v.Fragment != nil {
			return v.Fragment(x)
		}
	case artifact.LogCoverage:
		if v.Coverage != nil {
			return v.Coverage(x)
		}
	}
	return nil
}
