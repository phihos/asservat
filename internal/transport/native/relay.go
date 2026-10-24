package native

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

// RelayConversation forwards a single admitted operation. Upstream must already
// be connected to the exact current hub process; this type performs no address
// discovery or peer admission. It cannot acknowledge output on the hub's behalf.
// Sequential forwarding bounds each direction to one application frame.
type RelayConversation struct {
	gate     *evidence.NativeFrameGate
	upstream Stream
}

func NewRelayConversation(gate *evidence.NativeFrameGate, upstream Stream) (*RelayConversation, error) {
	if gate == nil || upstream == nil || gate.Context().Err() != nil || upstream.Context().Err() != nil {
		return nil, contracts.ErrNativeProtocol
	}
	return &RelayConversation{gate, newRelayReceive(gate, upstream)}, nil
}
func (r *RelayConversation) Gate() *evidence.NativeFrameGate { return r.gate }
func (r *RelayConversation) Close() error {
	r.gate.Close()
	err := r.upstream.Close()
	_ = r.gate.Wait(context.Background())
	return err
}
func (r *RelayConversation) forward(ctx context.Context, from, to Stream, kind contracts.NativeFrameKind, validate func(contracts.NativeFrame) error) error {
	terminalForward := kind == contracts.NativeDoneFrame && from == r.upstream
	check := r.gate.Check
	if terminalForward {
		check = r.gate.TerminalLease
	}
	lease, err := check(ctx)
	if err != nil {
		return err
	}
	call, stop := context.WithDeadline(ctx, lease.Until)
	defer stop()
	frame, err := from.Receive(call)
	if err != nil {
		return err
	}
	defer clear(frame.Payload)
	if frame.Kind != kind || validate == nil || validate(frame) != nil {
		return contracts.ErrNativeProtocol
	}
	lease, err = check(call)
	if err != nil {
		return err
	}
	send, stopSend := context.WithDeadline(call, lease.Until)
	defer stopSend()
	if terminalForward {
		terminal, ok := to.(interface {
			SendTerminal(context.Context, contracts.NativeFrame) error
		})
		if !ok {
			return contracts.ErrNativeProtocol
		}
		return terminal.SendTerminal(send, frame)
	}
	return to.Send(send, frame)
}
func (r *RelayConversation) Serve(ctx context.Context, worker Stream) error {
	if worker == nil {
		return contracts.ErrNativeProtocol
	}
	// Cancellation of either real stream interrupts the other. Close joins the
	// actual blocking I/O before request-slot ownership is returned.
	stop := context.AfterFunc(r.upstream.Context(), func() { _ = worker.Close() })
	defer stop()
	stopWorker := context.AfterFunc(worker.Context(), func() { _ = r.upstream.Close() })
	defer stopWorker()
	defer r.Close()
	defer worker.Close()
	var command contracts.NativeCommand
	err := r.forward(ctx, r.upstream, worker, contracts.NativeCommandFrame, func(frame contracts.NativeFrame) error {
		var err error
		command, err = contracts.DecodeNativeCommand(frame.Payload)
		if err != nil {
			return err
		}
		lease, err := r.gate.Check(ctx)
		if err != nil {
			return err
		}
		var op value.NativeOperation
		until, e := time.Parse(time.RFC3339Nano, command.Until)
		if e != nil || nativeDecode(command.Operation, &op) != nil || !op.Equal(lease.Operation) || command.Reference != nativeReference(op) || command.Format != contracts.NativeExchangeFormat || !contracts.ValidWorkerNonce(command.Nonce) || command.Kind != string(op.Kind) || command.ParentID != op.ParentID || command.Generation != op.Generation || command.LeaseSequence != lease.Sequence || until.After(lease.Until) || !time.Now().Before(until) {
			return contracts.ErrNativeProtocol
		}
		return nil
	})
	clear(command.Source)
	clear(command.Operation)
	clear(command.Projection)
	command.Source, command.Operation, command.Projection = nil, nil, nil
	if err != nil {
		return err
	}
	control := func(kind contracts.NativeFrameKind, phase string, n int64) func(contracts.NativeFrame) error {
		return func(frame contracts.NativeFrame) error {
			if frame.Kind != kind {
				return contracts.ErrNativeProtocol
			}
			a, e := contracts.DecodeNativeAcknowledge(frame.Payload)
			if e != nil || a.Format != command.Format || a.Reference != command.Reference || a.Nonce != command.Nonce || a.Phase != phase || a.Bytes != n {
				return contracts.ErrNativeProtocol
			}
			return nil
		}
	}
	metadata := func(frame contracts.NativeFrame) error {
		m, e := contracts.DecodeNativeMetadata(frame.Payload)
		if e != nil || m.Format != command.Format || m.Reference != command.Reference || m.Nonce != command.Nonce {
			return contracts.ErrNativeProtocol
		}
		return nil
	}
	data := func(frame contracts.NativeFrame) error {
		if command.Length < 1 || int64(len(frame.Payload)) != command.Length {
			return contracts.ErrNativeProtocol
		}
		return nil
	}
	switch command.Kind {
	case "prepare-context":
		e := r.forward(ctx, worker, r.upstream, contracts.NativeMetadataFrame, metadata)
		if e != nil {
			return e
		}
		e = r.forward(ctx, r.upstream, worker, contracts.NativeCommitFrame, control(contracts.NativeCommitFrame, "prepared", 0))
		if e != nil {
			return e
		}
		e = r.forward(ctx, worker, r.upstream, contracts.NativeAcknowledgeFrame, control(contracts.NativeAcknowledgeFrame, "prepared", 0))
		if e != nil {
			return e
		}
		e = r.forward(ctx, r.upstream, worker, contracts.NativeDoneFrame, control(contracts.NativeDoneFrame, "closed", 0))
		return e
	case "observe-prepared-context":
		e := r.forward(ctx, worker, r.upstream, contracts.NativeMetadataFrame, metadata)
		if e != nil {
			return e
		}
		e = r.forward(ctx, r.upstream, worker, contracts.NativeDoneFrame, control(contracts.NativeDoneFrame, "closed", 0))
		return e
	case "read-approved-context":
		if e := r.forward(ctx, worker, r.upstream, contracts.NativeMetadataFrame, metadata); e != nil {
			return e
		}
		if e := r.forward(ctx, r.upstream, worker, contracts.NativeAcknowledgeFrame, control(contracts.NativeAcknowledgeFrame, "approved", 0)); e != nil {
			return e
		}
		if e := r.forward(ctx, worker, r.upstream, contracts.NativeDoneFrame, control(contracts.NativeDoneFrame, "closed", 0)); e != nil {
			return e
		}
		return r.forward(ctx, r.upstream, worker, contracts.NativeDoneFrame, control(contracts.NativeDoneFrame, "joined", 0))
	case "read-context-response":
		e := r.forward(ctx, worker, r.upstream, contracts.NativeDataFrame, data)
		if e != nil {
			return e
		}
		e = r.forward(ctx, r.upstream, worker, contracts.NativeAcknowledgeFrame, control(contracts.NativeAcknowledgeFrame, "delivered", command.Length))
		if e != nil {
			return e
		}
		e = r.forward(ctx, worker, r.upstream, contracts.NativeDoneFrame, control(contracts.NativeDoneFrame, "closed", 0))
		if e != nil {
			return e
		}
		e = r.forward(ctx, r.upstream, worker, contracts.NativeDoneFrame, control(contracts.NativeDoneFrame, "joined", 0))
		return e
	default:
		return contracts.ErrNativeProtocol
	}
}
