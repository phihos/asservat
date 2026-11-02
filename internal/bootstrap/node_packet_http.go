package bootstrap

import (
	"time"

	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
)

// frameRecorder is what a finite packet capture feeds engine frames into: a
// PCAPNG packets.Recorder or, for an httpHeaders recording, httpRecorder.
type frameRecorder interface {
	Add(frame []byte, wire uint32, at time.Time)
	Snaplen() int
	Close(ended time.Time, lost uint64) ([]byte, packets.Counters, error)
}

var (
	_ frameRecorder = (*packets.Recorder)(nil)
	_ frameRecorder = (*httpRecorder)(nil)
)

// httpRecorder is the node side of an httpHeaders recording (ADR-282). The
// engine hands over frames of at most httpheaders.Snaplen bytes, already
// charged to the observation meter; the hub-compiled filter selects frames
// exactly as for header and raw recordings, and only matching frames reach
// the projector. The native output is the projection's JSON document, at
// most the recording's output cap.
//
// Counters in the PacketResult describe frames, as for PCAPNG recordings:
// Seen is every delivered frame, Filtered the frames the program refused,
// Retained the frames handed to the projector and WireBytes their original
// lengths. What the projector did with them (not TCP, truncated, stopped
// directions, dropped records and values) is accounted in the document's
// own counters, not in the frame counters.
type httpRecorder struct {
	filter   *packets.Filter
	proj     *httpheaders.Projector
	maxBytes int64
	counters packets.Counters
}

func newHTTPRecorder(program []planning.BPFInstruction, maxBytes int64, started time.Time, h collector.HTTPProjection) (*httpRecorder, error) {
	if len(program) == 0 {
		return nil, packets.ErrInvalid
	}
	// The program may read only the header prefix it was proven for, as
	// for a raw recording.
	if err := packets.CheckPrefixProgram(program); err != nil {
		return nil, err
	}
	f, err := packets.NewFilter(program)
	if err != nil {
		return nil, err
	}
	if maxBytes < 1 || maxBytes > collector.MaxPacketCaptureBytes {
		return nil, httpheaders.ErrInvalid
	}
	proj, err := httpheaders.NewProjector(httpheaders.Limits{MaxFlows: h.MaxFlows, MaxHeaderBytes: h.MaxHeaderBytes, MaxFlowBytes: h.MaxFlowBytes, MaxTotalBytes: h.MaxTotalBytes, IdleTimeout: h.IdleTimeout}, started)
	if err != nil {
		return nil, err
	}
	return &httpRecorder{filter: f, proj: proj, maxBytes: maxBytes}, nil
}

func (r *httpRecorder) Snaplen() int { return httpheaders.Snaplen }

func (r *httpRecorder) Add(frame []byte, wire uint32, at time.Time) {
	r.counters.Seen++
	if int(wire) < len(frame) {
		wire = uint32(len(frame))
	}
	if !r.filter.Match(frame, int(wire)) {
		r.counters.Filtered++
		return
	}
	r.counters.Retained++
	r.counters.WireBytes += uint64(wire)
	r.proj.Add(frame, wire, at)
}

// Close completes every open flow and encodes the projection within the
// output cap; records that do not fit are dropped latest first and counted.
func (r *httpRecorder) Close(ended time.Time, lost uint64) ([]byte, packets.Counters, error) {
	pr, _ := r.proj.Close(ended, lost)
	b, err := pr.EncodeWithin(r.maxBytes)
	return b, r.counters, err
}
