package mtls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/contextstart"
)

type historyTLSObjects struct {
	calls  atomic.Int64
	delay  atomic.Int64
	bundle capture.HistoryCiphertexts
	copies artifact.Copies
}

func (h *historyTLSObjects) ExecuteHistory(ctx context.Context, a capture.HistoryOperationAuthority, b capture.HistoryCiphertexts, c artifact.Copies) (app.HistoryReply, error) {
	h.calls.Add(1)
	if ctx.Err() != nil {
		return app.HistoryReply{}, ctx.Err()
	}
	if delay := time.Duration(h.delay.Load()); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return app.HistoryReply{}, ctx.Err()
		case <-timer.C:
		}
	}
	if a.Operation == "read" {
		return app.HistoryReply{Copies: c, Bundle: capture.HistoryCiphertexts{bytes.Clone(h.bundle[0]), bytes.Clone(h.bundle[1]), bytes.Clone(h.bundle[2]), bytes.Clone(h.bundle[3])}}, nil
	}
	if !bytes.Equal(b[0], h.bundle[0]) {
		return app.HistoryReply{}, value.ErrDenied
	}
	completion := &capture.HistoryWriterCompletion{RootID: a.Expectation.RootID, CaptureID: a.Expectation.CaptureID, AttemptID: a.Expectation.Registration.Location.AttemptID, OperationID: a.RequestID, ProcessEpoch: a.ExecutorEpoch, ExpectationDigest: capture.HistoryExpectationDigest(a.Expectation), CopiesDigest: capture.HistoryCopiesDigest(h.copies), CompletedAt: time.Now(), NotAfter: a.NotAfter}
	return app.HistoryReply{Copies: h.copies, WriterCompletion: completion}, nil
}

type historyTLSSource struct {
	inner   app.ConnectorIdentitySourceReader
	delay   time.Duration
	calls   atomic.Int64
	changed atomic.Bool
}

func (s *historyTLSSource) ReadConnectorIdentitySource(ctx context.Context) (value.ConnectorIdentitySource, error) {
	s.calls.Add(1)
	timer := time.NewTimer(s.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return value.ConnectorIdentitySource{}, ctx.Err()
	case <-timer.C:
	}
	observed, err := s.inner.ReadConnectorIdentitySource(ctx)
	if s.changed.Load() {
		observed.Observation.Profile.Binding.PeerID = "00000000-0000-4000-8000-999999999999"
	}
	return observed, err
}

// HistoryTLSHarness is test-only glue for the external-package test, which
// invokes the actual bootstrap dispatch without a production import cycle.
type HistoryTLSHarness struct {
	RootID           string
	Receiver         value.APIContextReceiver
	Router           *contextstart.Router
	Signer           *jose.APIContextWorkSignatures
	Bundle           capture.HistoryCiphertexts
	Copies           artifact.Copies
	Sources, Effects func() int64
	ChangeSource     func()
	DelayEffects     func(time.Duration)
}

func NewHistoryTLSHarness(t *testing.T, delay time.Duration) HistoryTLSHarness {
	t.Helper()
	f := newContextStartTLSFixture(t)
	owner, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	exchange, err := f.client.Open(owner, f.owner)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	response, writer, socket, err := exchange.IO()
	if err != nil {
		exchange.Close()
		cancel()
		t.Fatal(err)
	}
	source := &historyTLSSource{inner: f.connector, delay: delay}
	stream, err := contextstart.NewOutboundStream(exchange.Context(), exchange.Receiver().Channel, exchange.Check, source, nil, nil, response, writer, socket, exchange.Close)
	if err != nil {
		exchange.Close()
		cancel()
		t.Fatal(err)
	}
	receiver := exchange.Receiver()
	signer := f.workSigner(t, receiver)
	objects := &historyTLSObjects{bundle: capture.HistoryCiphertexts{[]byte("data"), []byte("index"), []byte("manifest"), []byte("commit")}}
	for i, b := range objects.bundle {
		objects.copies[i] = artifact.CopyReceipt{VersionID: "synthetic", ETag: "synthetic", Bytes: int64(len(b)), SHA256: sha256.Sum256(b)}
	}
	region := &regionalOperationsFixture{t: t, process: f.api}
	local := contextstart.RegionalLocal{Process: region, Targets: region, Local: region, Starts: region, Output: region, Collector: region, Source: source, History: &contextstart.HistoryLocal{Verifier: signer, Effects: objects}, Now: time.Now}
	joined := make(chan error, 1)
	go func() {
		joined <- contextstart.ServeRegionalOperations(owner, stream, receiver, signer, local, time.Now)
	}()
	t.Cleanup(func() { cancel(); stream.Close(); exchange.Close(); <-joined })
	return HistoryTLSHarness{f.rootID, receiver, f.router, signer, objects.bundle, objects.copies, source.calls.Load, objects.calls.Load, func() { source.changed.Store(true) }, func(delay time.Duration) { objects.delay.Store(int64(delay)) }}
}
