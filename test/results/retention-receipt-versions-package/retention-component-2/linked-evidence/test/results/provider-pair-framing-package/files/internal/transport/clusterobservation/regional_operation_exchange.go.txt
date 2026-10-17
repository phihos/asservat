package clusterobservation

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// The concrete adapter owns both the actual TLS stream and its private proof
// channel. This purpose-fixed seam permits the transport to own framing without
// importing adapters, accepting arbitrary RPCs or constructing peer authority.
type regionalObservationOperationConnection interface {
	Context() context.Context
	Hello() contracts.ClusterObservationHello
	Receive(context.Context) (contracts.ClusterObservationFrame, error)
	Send(context.Context, contracts.ClusterObservationFrame) error
	AnswerConnectorObservation(context.Context, contracts.ClusterObservationOperationProbe) (contracts.ConnectorObservationOperationReply, error)
	ObserveCluster(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error)
	AcceptObservationReceipt(context.Context, contracts.ClusterObservationReceipt) error
	FinishObservation(context.Context) error
	Close() error
}

// ServeRegionalObservationOperation executes exactly one already opened conversation.
// It never reconnects, repeats an unknown phase or generates fresh request IDs.
// It always joins the actual connection before returning, including invalid
// first input and terminal-delivery failure. Results are routing/metadata only.
func ServeRegionalObservationOperation(ctx context.Context, connection regionalObservationOperationConnection, now func() time.Time) (resultErr error) {
	if connection == nil {
		return fleet.ErrInvalid
	}
	defer func() {
		if connection.Close() != nil {
			resultErr = fleet.ErrUnavailable
		}
	}()
	if ctx == nil || ctx.Err() != nil || now == nil || connection.Context() == nil || connection.Context().Err() != nil {
		return fleet.ErrUnavailable
	}
	hello := connection.Hello()
	end, finite := connection.Context().Deadline()
	if !finite || !now().Before(end) || end.After(now().Add(30*time.Second)) || hello.Format != contracts.ClusterObservationOperationExchangeFormat || !authorization.UUID(hello.ExchangeID) || !authorization.UUID(hello.RootID) || !authorization.UUID(hello.ClusterID) {
		return fleet.ErrInvalid
	}
	call, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	joined := make(chan struct{})
	stop := context.AfterFunc(connection.Context(), func() { cancel(); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	var order exchangeOrder
	helloBytes, err := contracts.EncodeClusterObservationHello(hello)
	if err != nil || order.admit(contracts.ClusterObservationHelloFrame, true, len(helloBytes)) != nil {
		return fleet.ErrInvalid
	}
	clear(helloBytes)
	until := end
	var original contracts.ObservationOperationRequest
	var ordinal int
	for !order.complete() {
		bounded, narrow := context.WithDeadline(call, until)
		frame, e := connection.Receive(bounded)
		if e != nil || bounded.Err() != nil || !now().Before(until) || order.admit(frame.Kind, false, len(frame.Payload)) != nil {
			clear(frame.Payload)
			narrow()
			return fleet.ErrUnavailable
		}
		var output contracts.ClusterObservationFrame
		switch frame.Kind {
		case contracts.ClusterObservationProbeFrame:
			probe, e := contracts.DecodeClusterObservationOperationProbe(frame.Payload)
			ordinal++
			if e != nil || probe.Format != contracts.ClusterObservationOperationExchangeFormat || probe.ExchangeID != hello.ExchangeID || probe.Ordinal != ordinal || probe.Owner.Request.Format != contracts.OwnerObservationOperationFormat || probe.Owner.Request.RootID != hello.RootID || !authorization.UUID(probe.Owner.Request.ID) || !authorization.UUID(probe.Owner.Request.Challenge) || !identity.Fresh(readTime(probe.Owner.Request.RequestedAt), readTime(probe.Owner.Request.NotAfter), now(), 5*time.Second) || original.ID != "" && probe.Owner.Request != original {
				err = fleet.ErrUnavailable
				break
			}
			if original.ID == "" {
				original = probe.Owner.Request
			}
			until = identity.Earlier(until, identity.Earlier(readTime(original.NotAfter), identity.Earlier(readTime(probe.Owner.NativeUntil), readTime(probe.Owner.RegistrationUntil))))
			proofCall, stopProof := context.WithDeadline(bounded, until)
			proof, e := connection.AnswerConnectorObservation(proofCall, probe)
			stopProof()
			if e != nil || proof.Ordinal != ordinal || proof.Request != original {
				err = fleet.ErrUnavailable
				break
			}
			until = identity.Earlier(until, identity.Earlier(readTime(proof.NativeUntil), identity.Earlier(readTime(proof.SourceFreshUntil), readTime(proof.WorkloadFreshUntil))))
			output.Kind = contracts.ClusterObservationSourceFrame
			output.Payload, err = contracts.EncodeConnectorObservationOperationReply(proof)
		case contracts.ClusterObservationReadFrame:
			wire, e := contracts.DecodeClusterObservationRequest(frame.Payload)
			request, digest, pe := ParseRequest(wire, now())
			if e != nil || pe != nil || request.RootID != hello.RootID || request.ClusterID != hello.ClusterID || request.ID != original.ID || request.Challenge != original.Challenge || !request.RequestedAt.Equal(readTime(original.RequestedAt)) || !request.NotAfter.Equal(readTime(original.NotAfter)) {
				err = fleet.ErrUnavailable
				break
			}
			result, e := connection.ObserveCluster(bounded, request)
			if e != nil || !result.Matches(request, digest, now()) {
				err = fleet.ErrUnavailable
				break
			}
			until = identity.Earlier(until, result.Interval.FreshUntil)
			output.Kind = contracts.ClusterObservationResultFrame
			output.Payload, err = contracts.EncodeClusterObservationResult(ResultWire(result))
		case contracts.ClusterObservationReceiptFrame:
			receipt, e := contracts.DecodeClusterObservationReceipt(frame.Payload)
			if e != nil || !order.complete() {
				err = fleet.ErrUnavailable
				break
			}
			err = connection.AcceptObservationReceipt(bounded, receipt)
			if err == nil {
				err = connection.FinishObservation(bounded)
			}
		default:
			err = fleet.ErrUnavailable
		}
		clear(frame.Payload)
		if err == nil && output.Kind != 0 {
			if order.admit(output.Kind, true, len(output.Payload)) != nil || bounded.Err() != nil || !now().Before(until) {
				err = fleet.ErrUnavailable
			} else {
				write, stopWrite := context.WithDeadline(bounded, until)
				err = connection.Send(write, output)
				stopWrite()
			}
		}
		clear(output.Payload)
		failed := err != nil || bounded.Err() != nil || !now().Before(until)
		narrow()
		if failed {
			return fleet.ErrUnavailable
		}
	}
	if call.Err() != nil || !now().Before(until) {
		return fleet.ErrUnavailable
	}
	return nil
}
