package node

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"net/http"
	"time"
)

func WireLiveReply(epoch string, r v.NodeReply) (contracts.NodeLiveResult, error) {
	out := contracts.NodeLiveResult{Format: contracts.NodeLiveFormat, Epoch: epoch, WorkID: r.WorkID, SourceID: r.SourceID, Fence: r.Fence, BootID: r.BootID, Clock: r.Clock, Sample: r.Sample, Sequence: r.Position.Sequence, Lost: r.Position.Lost, ClockLost: r.Position.ClockLost, Unsupported: r.Position.Unsupported, SensorLost: r.Position.SensorLost, Dropped: r.Dropped, Examined: r.Examined, Bytes: r.Bytes, Rows: make([]contracts.NodeLiveRow, len(r.Rows))}
	if r.Manual != nil && r.ObservedManual != nil {
		return contracts.NodeLiveResult{}, ErrRefused
	}
	if r.Manual != nil {
		m := WireManualObservation(collector.ManualObserved(*r.Manual))
		out.Manual = &m
	}
	if r.ObservedManual != nil {
		m := WireManualObservation(*r.ObservedManual)
		out.Manual = &m
	}
	for n, row := range r.Rows {
		encoded, e := json.Marshal(row.Row)
		if e != nil {
			return contracts.NodeLiveResult{}, ErrRefused
		}
		out.Rows[n] = contracts.NodeLiveRow{Row: encoded, Nanos: row.Nanos, Clock: row.Clock}
	}
	encoded, e := json.Marshal(out)
	defer clear(encoded)
	if e != nil || len(encoded) > 24<<10 {
		return contracts.NodeLiveResult{}, ErrRefused
	}
	return out, nil
}
func strictLiveValue(raw []byte, out any) error {
	canonical := jsontext.Value(append([]byte(nil), raw...))
	defer clear(canonical)
	if canonical.Canonicalize() != nil {
		return ErrRefused
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrRefused
	}
	return nil
}
func DomainLiveReply(w contracts.NodeLiveResult) (v.NodeReply, error) {
	out := v.NodeReply{WorkID: w.WorkID, SourceID: w.SourceID, Fence: w.Fence, BootID: w.BootID, Clock: w.Clock, Sample: w.Sample, Position: v.Position{Sequence: w.Sequence, Lost: w.Lost, ClockLost: w.ClockLost, Unsupported: w.Unsupported, SensorLost: w.SensorLost}, Dropped: w.Dropped, Examined: w.Examined, Bytes: w.Bytes, Rows: make([]v.StampedRow, len(w.Rows))}
	if w.Manual != nil {
		m, ok := DomainManualObservation(*w.Manual)
		if !ok {
			return v.NodeReply{}, ErrRefused
		}
		out.ObservedManual = &m
	}
	if w.Format != contracts.NodeLiveFormat || len(w.Rows) > v.MaxRows {
		return v.NodeReply{}, ErrRefused
	}
	type plain v.Row
	for n, r := range w.Rows {
		var doc struct {
			plain
			Fields json.RawMessage `json:"fields"`
		}
		if !liveKeys(r.Row, "row_id", "source_session_id", "source_sequence", "observed_at", "received_at", "expires_at", "clock_uncertainty_ms", "filter_generation", "projection", "pod_uid", "fields") {
			return v.NodeReply{}, ErrRefused
		}
		if e := strictLiveValue(r.Row, &doc); e != nil {
			return v.NodeReply{}, ErrRefused
		}
		row := v.Row(doc.plain)
		switch row.Projection {
		case v.Packet:
			row.Packet = &v.PacketFields{}
			if !liveKeys(doc.Fields, "protocol", "peer_uid", "remote_ip", "remote_port", "direction", "wire_bytes", "pid") || strictLiveValue(doc.Fields, row.Packet) != nil {
				return v.NodeReply{}, ErrRefused
			}
		case v.Syscall:
			row.Syscall = &v.SyscallFields{}
			if !liveKeys(doc.Fields, "pid", "syscall", "error", "errno", "duration_ns", "paired") || strictLiveValue(doc.Fields, row.Syscall) != nil {
				return v.NodeReply{}, ErrRefused
			}
		case v.HTTP:
			row.HTTP = &v.HTTPFields{}
			if !liveKeys(doc.Fields, "method", "status", "peer_uid", "headers", "pairing", "duration_ms") || strictLiveValue(doc.Fields, row.HTTP) != nil {
				return v.NodeReply{}, ErrRefused
			}
		default:
			return v.NodeReply{}, ErrRefused
		}
		if !row.Valid(row.ReceivedAt) {
			return v.NodeReply{}, ErrRefused
		}
		out.Rows[n] = v.StampedRow{Row: row, Nanos: r.Nanos, Clock: r.Clock}
	}
	return out, nil
}
func (c *Client) UploadLive(ctx context.Context, epoch string, r v.NodeReply) error {
	wire, e := WireLiveReply(epoch, r)
	if e != nil {
		return e
	}
	defer func() {
		for _, r := range wire.Rows {
			clear(r.Row)
		}
	}()
	raw, code, e := c.post(ctx, contracts.NodeLivePath, 5*time.Second, wire)
	clear(raw)
	if e != nil {
		return e
	}
	if code != http.StatusNoContent {
		return ErrUnavailable
	}
	return nil
}
func (h *Handler) live(w http.ResponseWriter, r *http.Request) {
	peer, e := h.peer(r)
	if e != nil {
		w.WriteHeader(status(e))
		return
	}
	wire, e := contracts.DecodeNodeLiveResult(http.MaxBytesReader(w, r.Body, 24<<10))
	if e != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer func() {
		for _, r := range wire.Rows {
			clear(r.Row)
		}
	}()
	reply, e := DomainLiveReply(wire)
	if e != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if e = h.channel.DeliverLive(r.Context(), peer, wire.Epoch, reply); e != nil {
		w.WriteHeader(status(e))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func liveKeys(raw []byte, keys ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	return true
}
