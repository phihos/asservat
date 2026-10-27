package bootstrap

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/packets"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
)

// syntheticTCP builds an Ethernet/IPv4/TCP frame to port dport with a
// synthetic payload marker.
func syntheticTCP(dport uint16, payload string) []byte {
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[12] = 5 << 4
	total := len(ip) + len(tcp) + len(payload)
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	f := append([]byte{0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 8, 0}, ip...)
	f = append(f, tcp...)
	return append(f, payload...)
}

type uploads struct {
	mu   sync.Mutex
	r    []collector.PacketResult
	pcap [][]byte
	done chan struct{}
}

func (u *uploads) upload(_ context.Context, _ string, r collector.PacketResult, pcapng []byte) error {
	u.mu.Lock()
	u.r, u.pcap = append(u.r, r), append(u.pcap, append([]byte(nil), pcapng...))
	u.mu.Unlock()
	close(u.done)
	return nil
}

func TestNodePacketCaptureFiltersCutsAndUploads(t *testing.T) {
	// libpcap 1.11.0 "tcp dst port 80" on EN10MB (feasibility corpus).
	program := []planning.BPFInstruction{{Code: 0x28, K: 12}, {Code: 0x15, Jf: 4, K: 0x86dd}, {Code: 0x30, K: 20}, {Code: 0x15, Jf: 11, K: 6}, {Code: 0x28, K: 56},
		{Code: 0x15, Jt: 8, Jf: 9, K: 80}, {Code: 0x15, Jf: 8, K: 0x800}, {Code: 0x30, K: 23}, {Code: 0x15, Jf: 6, K: 6}, {Code: 0x28, K: 20}, {Code: 0x45, Jt: 4, K: 0x1fff},
		{Code: 0xb1, K: 14}, {Code: 0x48, K: 16}, {Code: 0x15, Jf: 1, K: 80}, {Code: 0x06, K: 65535}, {Code: 0x06}}
	if err := packets.CheckProgram(program); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	budget, _ := collector.NewBudget(collector.Ceilings{RingBytes: 1 << 20, FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, clock)
	var mu sync.Mutex
	up := &uploads{done: make(chan struct{})}
	engine := func(ctx context.Context, pod string, snaplen int, deliver func(gadget.Frame)) (gadget.CaptureStats, error) {
		if pod != "11111111-1111-4111-8111-111111111111" || snaplen != packets.Snaplen {
			return gadget.CaptureStats{}, gadget.ErrTargetNotFound
		}
		for i := 0; i < 10; i++ {
			for _, port := range []uint16{80, 443} {
				f := syntheticTCP(port, "SYNTHETIC-SECRET-MARKER-SYNTHETIC-SECRET-MARKER-SYNTHETIC-SECRET-MARKER-SYNTHETIC-SECRET-MARKER-SYNTHETIC")
				wire := uint32(len(f))
				if len(f) > snaplen {
					f = f[:snaplen]
				}
				deliver(gadget.Frame{Data: f, Wire: wire, At: clock.Add(time.Duration(i) * time.Millisecond)})
			}
		}
		<-ctx.Done()
		return gadget.CaptureStats{LostSamples: 2}, nil
	}
	n := &nodePackets{engine: engine, upload: up.upload, available: true, version: "v0.57.0", now: now, log: func(string) {}, budget: func() *collector.Budget { return budget }, budgetMu: &mu}
	p := collector.PacketCapture{CaptureID: "22222222-2222-4222-8222-222222222222", PodUID: "11111111-1111-4111-8111-111111111111", Program: program,
		ProgramDigest: [32]byte(compiler.FilterProgramDigest(program)), Duration: time.Second, MaxBytes: 1 << 20}
	w := collector.Work{ID: "33333333-3333-4333-8333-333333333333", Sequence: 1, Kind: collector.WorkPacketCapture, NotAfter: clock.Add(10 * time.Second), Packet: &p}
	r := n.start(context.Background(), "epoch", w)
	if r.Outcome != collector.OutcomeAccepted {
		t.Fatalf("%+v", r)
	}
	select {
	case <-up.done:
	case <-time.After(10 * time.Second):
		t.Fatal("no upload")
	}
	n.wg.Wait()
	res := up.r[0]
	if res.Seen != 20 || res.Retained != 10 || res.Filtered != 10 || res.LostSamples != 2 || res.Failure != "" || res.ProgramDigest != p.ProgramDigest || !res.Valid() {
		t.Fatalf("%+v", res)
	}
	if bytes.Contains(up.pcap[0], []byte("SECRET")) {
		t.Fatal("payload in the capture")
	}
	if c, err := packets.CheckHeadersOnly(bytes.NewReader(up.pcap[0])); err != nil || c != 10 {
		t.Fatal(c, err)
	}
	if u := budget.Usage(clock); u.FrozenReserved != 0 {
		t.Fatal("frozen reservation kept")
	}

	// A changed program, an unavailable engine and an exhausted budget refuse.
	bad := p
	bad.Program = append([]planning.BPFInstruction(nil), program...)
	bad.Program[0].K = 13
	if r := n.start(context.Background(), "epoch", collector.Work{ID: w.ID, Sequence: 2, Kind: w.Kind, NotAfter: w.NotAfter, Packet: &bad}); r.Reason != collector.ReasonFilterUnsupported {
		t.Fatalf("%+v", r)
	}
	big := p
	big.MaxBytes = 8 << 20
	_ = budget.ReserveFrozen(10 << 20)
	if r := n.start(context.Background(), "epoch", collector.Work{ID: w.ID, Sequence: 3, Kind: w.Kind, NotAfter: w.NotAfter, Packet: &big}); r.Reason != collector.ReasonCaptureBusy {
		t.Fatalf("%+v", r)
	}
	n.available = false
	if r := n.start(context.Background(), "epoch", collector.Work{ID: w.ID, Sequence: 4, Kind: w.Kind, NotAfter: w.NotAfter, Packet: &p}); r.Reason != collector.ReasonEngineUnavailable {
		t.Fatalf("%+v", r)
	}
	if r := n.start(context.Background(), "epoch", collector.Work{ID: w.ID, Sequence: 5, Kind: w.Kind, NotAfter: clock, Packet: &p}); r.Reason != collector.ReasonWorkExpired {
		t.Fatalf("%+v", r)
	}
}

func TestNodePacketCaptureReportsTargetFailure(t *testing.T) {
	clock := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	budget, _ := collector.NewBudget(collector.Ceilings{RingBytes: 1 << 20, FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, clock)
	var mu sync.Mutex
	up := &uploads{done: make(chan struct{})}
	engine := func(context.Context, string, int, func(gadget.Frame)) (gadget.CaptureStats, error) {
		return gadget.CaptureStats{}, gadget.ErrTargetNotFound
	}
	n := &nodePackets{engine: engine, upload: up.upload, available: true, now: func() time.Time { return clock }, log: func(string) {}, budget: func() *collector.Budget { return budget }, budgetMu: &mu}
	p := collector.PacketCapture{CaptureID: "22222222-2222-4222-8222-222222222222", PodUID: "11111111-1111-4111-8111-111111111111", Duration: time.Second, MaxBytes: 1 << 20}
	if r := n.start(context.Background(), "epoch", collector.Work{ID: "33333333-3333-4333-8333-333333333333", Sequence: 1, Kind: collector.WorkPacketCapture, NotAfter: clock.Add(time.Second), Packet: &p}); r.Outcome != collector.OutcomeAccepted {
		t.Fatalf("%+v", r)
	}
	<-up.done
	n.wg.Wait()
	if up.r[0].Failure != collector.ReasonTargetNotFound || up.r[0].Seen != 0 || !errors.Is(nil, nil) {
		t.Fatalf("%+v", up.r[0])
	}
}
