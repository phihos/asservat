package contextstart

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"time"
)

// RegionalHistory receives only authenticated, independently SQL-authorized
// history effects. Its installed adapter holds history-prefix credentials only.
type RegionalHistory interface {
	ExecuteHistory(context.Context, capture.HistoryOperationAuthority, capture.HistoryCiphertexts, artifact.Copies) (fleetapp.HistoryReply, error)
}
type HistoryLocal struct {
	Verifier fleetapp.HistoryWorkVerifier
	Effects  RegionalHistory
	// Report, if set, receives the operation word and its fixed step timing
	// once per exchange. Diagnostic only.
	Report func(string, string)
}

func historyJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func historyDecode(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	// Unknown fields of a newer peer are ignored (ADR-332).
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return contracts.ErrAPIContextProtocol
	}
	return nil
}
func historyRequest(a capture.HistoryOperationAuthority, b capture.HistoryCiphertexts, c artifact.Copies) (contracts.HistoryCiphertextMessage, error) {
	m := contracts.HistoryCiphertextMessage{Format: contracts.HistoryCiphertextFormat, OperationID: a.RequestID}
	switch a.Operation {
	case "write":
		encoded, e := capture.EncodeHistoryCiphertexts(b)
		if e != nil {
			return m, e
		}
		if artifact.Digest(sha256.Sum256(encoded)) != a.BundleDigest {
			clear(encoded)
			return m, artifact.ErrIntegrity
		}
		m.Bundle = encoded
	case "read", "purge":
		if !fleetapp.HistoryCopiesMatch(a, c) {
			return m, artifact.ErrIntegrity
		}
		m.Copies = historyJSON(c)
	default:
		return m, artifact.ErrInvalid
	}
	return m, nil
}
func historyReplyMessage(a capture.HistoryOperationAuthority, r fleetapp.HistoryReply) (contracts.HistoryCiphertextMessage, error) {
	m := contracts.HistoryCiphertextMessage{Format: contracts.HistoryCiphertextFormat, OperationID: a.RequestID}
	switch a.Operation {
	case "write":
		if r.Copies.Validate(a.Expectation.Registration) != nil || r.WriterCompletion == nil || !r.WriterCompletion.Valid(a.Expectation) || r.WriterCompletion.OperationID != a.RequestID || r.WriterCompletion.ProcessEpoch != a.ExecutorEpoch || r.WriterCompletion.CopiesDigest != capture.HistoryCopiesDigest(r.Copies) || !r.WriterCompletion.NotAfter.Equal(a.NotAfter) || r.WriterCompletion.CompletedAt.Before(a.StartedAt) {
			return m, artifact.ErrIntegrity
		}
		m.Copies, m.WriterCompletion = historyJSON(r.Copies), historyJSON(r.WriterCompletion)
	case "read":
		if r.Copies.Validate(a.Expectation.Registration) != nil || capture.HistoryCopiesDigest(r.Copies) != a.CopiesDigest {
			return m, artifact.ErrIntegrity
		}
		b, e := capture.EncodeHistoryCiphertexts(r.Bundle)
		if e != nil {
			return m, e
		}
		m.Bundle, m.Copies = b, historyJSON(r.Copies)
	case "purge":
		if r.DeleteCompletion == nil || !r.DeleteCompletion.Valid(a) {
			return m, artifact.ErrIntegrity
		}
		m.DeleteCompletion = historyJSON(r.DeleteCompletion)
	default:
		return m, artifact.ErrInvalid
	}
	return m, nil
}
func historyReplyValue(a capture.HistoryOperationAuthority, m contracts.HistoryCiphertextMessage) (fleetapp.HistoryReply, error) {
	var r fleetapp.HistoryReply
	if m.OperationID != a.RequestID || m.Failure != "" {
		return r, contracts.ErrAPIContextProtocol
	}
	switch a.Operation {
	case "write":
		if len(m.Bundle) != 0 || len(m.DeleteCompletion) != 0 || historyDecode(m.Copies, &r.Copies) != nil {
			return r, contracts.ErrAPIContextProtocol
		}
		r.WriterCompletion = new(capture.HistoryWriterCompletion)
		if historyDecode(m.WriterCompletion, r.WriterCompletion) != nil {
			return fleetapp.HistoryReply{}, contracts.ErrAPIContextProtocol
		}
	case "read":
		if len(m.WriterCompletion) != 0 || len(m.DeleteCompletion) != 0 || historyDecode(m.Copies, &r.Copies) != nil {
			return r, contracts.ErrAPIContextProtocol
		}
		b, e := capture.DecodeHistoryCiphertexts(m.Bundle)
		if e != nil {
			return r, e
		}
		r.Bundle = b
	case "purge":
		if len(m.Bundle) != 0 || len(m.Copies) != 0 || len(m.WriterCompletion) != 0 {
			return r, contracts.ErrAPIContextProtocol
		}
		r.DeleteCompletion = new(capture.HistoryDeleteCompletion)
		if historyDecode(m.DeleteCompletion, r.DeleteCompletion) != nil {
			return fleetapp.HistoryReply{}, contracts.ErrAPIContextProtocol
		}
	}
	if _, e := historyReplyMessage(a, r); e != nil {
		r.Bundle.Clear()
		return fleetapp.HistoryReply{}, e
	}
	return r, nil
}
func serveHubHistory(ctx context.Context, s Stream, w fleetapp.HistoryWork, signed []byte, b capture.HistoryCiphertexts, c artifact.Copies, now func() time.Time) (fleetapp.HistoryReply, error) {
	var out fleetapp.HistoryReply
	if ctx == nil || s == nil || now == nil || !w.Valid(now()) || ctx.Err() != nil {
		return out, fleet.ErrInvalid
	}
	if e := requireCapability(s, capabilityHistory, errHistoryClass); e != nil {
		return out, e
	}
	call, cancel := context.WithDeadline(ctx, w.Authority.NotAfter)
	defer cancel()
	// Step marks are diagnostic only (the caller's step timing, if any).
	began := time.Now()
	if e := s.Send(call, contracts.APIContextFrame{Kind: contracts.HistoryWorkFrame, Payload: signed}); e != nil {
		return out, e
	}
	auditapp.MarkStep(ctx, "x-send-work", began)
	began = time.Now()
	request, e := historyRequest(w.Authority, b, c)
	if e != nil {
		return out, e
	}
	defer clear(request.Bundle)
	encoded, e := contracts.EncodeHistoryCiphertexts(request)
	if e != nil {
		return out, e
	}
	defer clear(encoded)
	if e = s.Send(call, contracts.APIContextFrame{Kind: contracts.HistoryRequestFrame, Payload: encoded}); e != nil {
		return out, e
	}
	auditapp.MarkStep(ctx, "x-send-request", began)
	began = time.Now()
	f, e := s.Receive(call)
	auditapp.MarkStep(ctx, "x-await-reply", began)
	defer clear(f.Payload)
	if e != nil || f.Kind != contracts.HistoryResponseFrame {
		return out, contracts.ErrAPIContextProtocol
	}
	m, e := contracts.DecodeHistoryCiphertexts(f.Payload)
	if e != nil || m.OperationID != w.Authority.RequestID {
		return out, contracts.ErrAPIContextProtocol
	}
	var effectErr error
	if m.Failure != "" {
		if len(m.Bundle)+len(m.Copies)+len(m.WriterCompletion)+len(m.DeleteCompletion) != 0 {
			return out, contracts.ErrAPIContextProtocol
		}
		effectErr = operationFailureError(m.Failure)
	} else {
		out, e = historyReplyValue(w.Authority, m)
		if e != nil {
			return fleetapp.HistoryReply{}, e
		}
	}
	if call.Err() != nil || !w.Valid(now()) {
		out.Bundle.Clear()
		return fleetapp.HistoryReply{}, fleet.ErrUnavailable
	}
	ack, e := contracts.EncodeAPIContextReceipt(contracts.APIContextReceipt{Format: contracts.HistoryCiphertextFormat, ExchangeID: w.Channel.ExchangeID, CaptureID: w.Authority.Expectation.CaptureID, State: "received"})
	if e != nil {
		out.Bundle.Clear()
		return fleetapp.HistoryReply{}, e
	}
	defer clear(ack)
	began = time.Now()
	if e = s.Send(call, contracts.APIContextFrame{Kind: contracts.HistoryReceiptFrame, Payload: ack}); e != nil {
		out.Bundle.Clear()
		return fleetapp.HistoryReply{}, e
	}
	auditapp.MarkStep(ctx, "x-send-ack", began)
	return out, effectErr
}
func serveRegionalHistory(ctx context.Context, s Stream, r fleet.APIContextReceiver, signed []byte, l *HistoryLocal, now func() time.Time) error {
	if l == nil || l.Verifier == nil || l.Effects == nil {
		return fleet.ErrUnavailable
	}
	// Step timing for the region's fixed diagnostic report: only fixed step
	// names and duration buckets, reported once the exchange ends.
	ctx, steps := auditapp.WithStepTimes(ctx)
	operation, total := "unknown", time.Now()
	defer func() {
		if l.Report != nil {
			auditapp.MarkStep(ctx, "r-total", total)
			l.Report(operation, steps.String())
		}
	}()
	began := time.Now()
	verified, e := l.Verifier.VerifyHistoryWork(ctx, signed, r)
	auditapp.MarkStep(ctx, "r-verify", began)
	if e != nil || !verified.Valid(now()) || verified.Work.Authority.ExecutorEpoch != r.Channel.Executor.ProcessEpoch {
		return fleet.ErrDenied
	}
	a := verified.Work.Authority
	switch a.Operation {
	case "write", "read", "purge":
		operation = a.Operation
	}
	call, cancel := context.WithDeadline(ctx, verified.ValidUntil)
	ended := make(chan struct{})
	stopStream := context.AfterFunc(s.Context(), func() { cancel(); close(ended) })
	defer func() {
		if !stopStream() {
			<-ended
		}
		cancel()
	}()
	began = time.Now()
	f, e := s.Receive(call)
	auditapp.MarkStep(ctx, "r-receive-request", began)
	defer clear(f.Payload)
	if e != nil || f.Kind != contracts.HistoryRequestFrame {
		return contracts.ErrAPIContextProtocol
	}
	m, e := contracts.DecodeHistoryCiphertexts(f.Payload)
	if e != nil || m.OperationID != a.RequestID || m.Failure != "" || len(m.WriterCompletion)+len(m.DeleteCompletion) != 0 {
		return contracts.ErrAPIContextProtocol
	}
	var b capture.HistoryCiphertexts
	var copies artifact.Copies
	if a.Operation == "write" {
		if len(m.Copies) != 0 || artifact.Digest(sha256.Sum256(m.Bundle)) != a.BundleDigest {
			return fleet.ErrDenied
		}
		b, e = capture.DecodeHistoryCiphertexts(m.Bundle)
		if e != nil {
			return e
		}
		defer b.Clear()
	} else {
		if len(m.Bundle) != 0 || historyDecode(m.Copies, &copies) != nil || !fleetapp.HistoryCopiesMatch(a, copies) {
			return fleet.ErrDenied
		}
	}
	if !a.Valid(now()) || call.Err() != nil {
		return fleet.ErrDenied
	}
	began = time.Now()
	reply, e := l.Effects.ExecuteHistory(call, a, b, copies)
	auditapp.MarkStep(ctx, "r-effect", began)
	defer reply.Bundle.Clear()
	response := contracts.HistoryCiphertextMessage{Format: contracts.HistoryCiphertextFormat, OperationID: a.RequestID}
	if e != nil {
		response.Failure = operationFailureLabel(e)
	} else {
		response, e = historyReplyMessage(a, reply)
		if e != nil {
			response = contracts.HistoryCiphertextMessage{Format: contracts.HistoryCiphertextFormat, OperationID: a.RequestID, Failure: "unavailable"}
		}
	}
	defer clear(response.Bundle)
	if call.Err() != nil || !a.Valid(now()) {
		return fleet.ErrUnavailable
	}
	encoded, e := contracts.EncodeHistoryCiphertexts(response)
	if e != nil {
		return e
	}
	defer clear(encoded)
	began = time.Now()
	if e = s.Send(call, contracts.APIContextFrame{Kind: contracts.HistoryResponseFrame, Payload: encoded}); e != nil {
		return e
	}
	auditapp.MarkStep(ctx, "r-send-reply", began)
	began = time.Now()
	f, e = s.Receive(call)
	auditapp.MarkStep(ctx, "r-await-ack", began)
	defer clear(f.Payload)
	if e != nil || f.Kind != contracts.HistoryReceiptFrame {
		return contracts.ErrAPIContextProtocol
	}
	ack, e := contracts.DecodeAPIContextReceipt(f.Payload)
	if e != nil || ack.Format != contracts.HistoryCiphertextFormat || ack.ExchangeID != r.Channel.ExchangeID || ack.CaptureID != a.Expectation.CaptureID || ack.State != "received" {
		return contracts.ErrAPIContextProtocol
	}
	return nil
}
