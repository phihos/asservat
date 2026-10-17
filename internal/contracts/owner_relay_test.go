package contracts

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestOwnerRelayResponseFrame(t *testing.T) {
	in := OwnerRelayResponse{Format: OwnerRelayFormat, Until: time.Now().UTC(), Enrollment: WorkerEnrollmentResponse{Format: WorkerEnrollmentFormat, Chain: [][]byte{}}}
	wire, err := EncodeOwnerRelayResponse(in)
	if err != nil {
		t.Fatal(err)
	}
	// Decoding must consume exactly one frame, not wait for stream completion or
	// consume subsequent bytes that the lifetime monitor must reject.
	input := bytes.NewReader(append(bytes.Clone(wire), 0x19))
	out, err := DecodeOwnerRelayResponse(input)
	if err != nil || out.Format != in.Format || !out.Until.Equal(in.Until) || input.Len() != 1 {
		t.Fatal("frame boundary", err)
	}
	for _, mode := range []string{"zero", "oversized", "short-prefix", "short-body", "duplicate", "unknown", "missing", "alias", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			bad := bytes.Clone(wire)
			switch mode {
			case "zero":
				binary.BigEndian.PutUint32(bad, 0)
			case "oversized":
				binary.BigEndian.PutUint32(bad, OwnerRelayMaxResponse+1)
			case "short-prefix":
				bad = bad[:3]
			case "short-body":
				bad = bad[:len(bad)-1]
			default:
				body := bytes.Clone(bad[4:])
				switch mode {
				case "duplicate":
					body = append([]byte(`{"format":"x",`), body[1:]...)
				case "unknown":
					body = append([]byte(`{"authority":"x",`), body[1:]...)
				case "missing":
					body = []byte(`{"format":"asservat-owner-relay/v2"}`)
				case "alias":
					body = bytes.Replace(body, []byte(`"format"`), []byte(`"Format"`), 1)
				case "trailing":
					body = append(body, []byte(`{}`)...)
				}
				bad = make([]byte, 4+len(body))
				binary.BigEndian.PutUint32(bad, uint32(len(body)))
				copy(bad[4:], body)
			}
			if _, e := DecodeOwnerRelayResponse(bytes.NewReader(bad)); e == nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
}
