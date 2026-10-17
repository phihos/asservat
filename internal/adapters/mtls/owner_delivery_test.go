package mtls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

var _ evidence.WorkerEnrollmentExchange = (*OwnerForwarder)(nil)

func TestOwnerForwarderRetainsLiveDelivery(t *testing.T) {
	for _, mode := range []string{"remote-owner", "caller", "root", "close", "network-loss", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newForwardLab(t, "valid")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			delivery, err := f.forwarder.BeginWorkerEnrollment(ctx, ownerTestID, ownerTestID, ownerTestID, []byte("synthetic.pod.token"), f.csr)
			if err != nil {
				t.Fatal(err)
			}
			defer delivery.Close()
			until, ok := delivery.Context().Deadline()
			if !ok || until.After(time.Now().Add(5*time.Second)) || delivery.Context().Err() != nil || f.released.Load() != 0 {
				t.Fatal("remote operation released before downstream delivery")
			}
			if _, e := f.forward(ctx); !errors.Is(e, artifact.ErrDownloadCapacity) {
				t.Fatal("live delivery no longer charged", e)
			}
			switch mode {
			case "remote-owner":
				f.cancelOwner()
			case "caller":
				cancel()
			case "root":
				f.forwarder.Close()
			case "close":
				delivery.Close()
			case "network-loss":
				f.srv.CloseClientConnections()
			}
			wait := time.Second
			if mode == "deadline" {
				wait = 6 * time.Second
			}
			select {
			case <-delivery.Context().Done():
			case <-time.After(wait):
				t.Fatal("live remote cancellation/deadline not propagated")
			}
			delivery.Close()
			delivery.Close()
			limit := time.After(time.Second)
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for f.released.Load() == 0 {
				select {
				case <-tick.C:
				case <-limit:
					t.Fatal("remote operation not released")
				}
			}
			if f.released.Load() != 1 || len(f.forwarder.slots) != 0 || f.requests.Load() != 1 {
				t.Fatal("release/slot/replay mismatch")
			}
		})
	}
}

// A TLS-authenticated peer is not entitled to change the finite framing or
// claim a completed response is live. These faults occur on the real wire.
type badOwnerStream struct {
	http.ResponseWriter
	mode string
}

func (w *badOwnerStream) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *badOwnerStream) Write(b []byte) (int, error) {
	n := len(b)
	if w.mode == "stream-finite" {
		w.Header().Set("Content-Length", "0")
		return n, nil
	}
	if w.mode == "stream-huge" {
		b = bytes.Clone(b)
		binary.BigEndian.PutUint32(b, contracts.OwnerRelayMaxResponse+1)
	}
	if w.mode == "stream-expired" || w.mode == "stream-foreign-format" {
		frame, err := contracts.DecodeOwnerRelayResponse(bytes.NewReader(b))
		if err != nil {
			return 0, err
		}
		if w.mode == "stream-expired" {
			frame.Until = time.Now().Add(-time.Second)
		} else {
			frame.Format = "asservat-owner-relay/v1"
		}
		b, err = contracts.EncodeOwnerRelayResponse(frame)
		if err != nil {
			return 0, err
		}
	}
	_, err := w.ResponseWriter.Write(b)
	return n, err
}
func (w *badOwnerStream) FlushError() error {
	if err := http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
		return err
	}
	if w.mode == "stream-extra" {
		_, _ = w.ResponseWriter.Write([]byte{0x19})
		_ = http.NewResponseController(w.ResponseWriter).Flush()
	}
	// Returning releases the real handler and emits EOF. No test manufactures a
	// live context from a response or assumes the sender has processed it yet.
	return errors.New("synthetic stream termination")
}

func TestOwnerForwarderStreamFailureClosesDelivery(t *testing.T) {
	for _, mode := range []string{"stream-finite", "stream-eof", "stream-extra", "stream-huge", "stream-expired", "stream-foreign-format"} {
		t.Run(mode, func(t *testing.T) {
			f := newForwardLab(t, mode)
			d, err := f.forwarder.BeginWorkerEnrollment(context.Background(), ownerTestID, ownerTestID, ownerTestID, []byte("synthetic.pod.token"), f.csr)
			if d != nil {
				defer d.Close()
			}
			if err == nil {
				if mode != "stream-eof" && mode != "stream-extra" {
					t.Fatal("invalid stream admitted")
				}
				select {
				case <-d.Context().Done():
				case <-time.After(time.Second):
					t.Fatal("terminated stream remained usable")
				}
				d.Close()
			}
			if f.requests.Load() != 1 || len(f.forwarder.slots) != 0 {
				t.Fatal("stream replay or leaked slot")
			}
		})
	}
}
