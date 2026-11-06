package live

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	v "asservat.local/asservat/internal/domain/live"
)

type ownerBatchValue v.Batch
type ownerBatch struct {
	ownerBatchValue
	Rows   []json.RawMessage `json:"rows"`
	Cursor string            `json:"cursor"`
}
type ownerResult struct {
	Watch *v.Watch    `json:"watch,omitempty"`
	Batch *ownerBatch `json:"batch,omitempty"`
}

// EncodeOwnerResult keeps the private cursor and the domain's minimized field
// union. Public Batch deliberately omits the cursor and has no row JSON decoder.
// DisclosureUntil travels separately in the authenticated conversation frame.
func EncodeOwnerResult(result CommandResult) ([]byte, error) {
	if (result.Watch == nil) == (result.Batch == nil) {
		return nil, v.ErrInvalid
	}
	wire := ownerResult{Watch: result.Watch}
	if result.Batch != nil {
		b := result.Batch
		wire.Batch = &ownerBatch{ownerBatchValue: ownerBatchValue(*b), Cursor: b.Cursor, Rows: make([]json.RawMessage, len(b.Rows))}
		for j, row := range b.Rows {
			raw, e := json.Marshal(row)
			if e != nil {
				return nil, e
			}
			wire.Batch.Rows[j] = raw
		}
	}
	return json.Marshal(wire)
}
func ownerDecode(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(out) != nil || dec.Decode(new(any)) != io.EOF {
		return v.ErrInvalid
	}
	return nil
}
func DecodeOwnerResult(raw []byte, now time.Time) (CommandResult, error) {
	var wire ownerResult
	if ownerDecode(raw, &wire) != nil || (wire.Watch == nil) == (wire.Batch == nil) {
		return CommandResult{}, v.ErrInvalid
	}
	out := CommandResult{Watch: wire.Watch}
	if b := wire.Batch; b != nil {
		if b.Rows == nil || len(b.Rows) > v.MaxRows {
			return CommandResult{}, v.ErrInvalid
		}
		batch := v.Batch(b.ownerBatchValue)
		batch.Cursor = b.Cursor
		batch.Rows = make([]v.Row, len(b.Rows))
		type rowValue v.Row
		for j, raw := range b.Rows {
			r := struct {
				*rowValue
				Fields json.RawMessage `json:"fields"`
			}{rowValue: &rowValue{}}
			if ownerDecode(raw, &r) != nil {
				return CommandResult{}, v.ErrInvalid
			}
			row := v.Row(*r.rowValue)
			var fields any
			switch row.Projection {
			case v.Packet:
				row.Packet = &v.PacketFields{}
				fields = row.Packet
			case v.HTTP:
				row.HTTP = &v.HTTPFields{}
				fields = row.HTTP
			case v.Syscall:
				row.Syscall = &v.SyscallFields{}
				fields = row.Syscall
			default:
				return CommandResult{}, v.ErrInvalid
			}
			if ownerDecode(r.Fields, fields) != nil || !row.Valid(now) {
				return CommandResult{}, v.ErrInvalid
			}
			batch.Rows[j] = row
		}
		out.Batch = &batch
	}
	return out, nil
}
