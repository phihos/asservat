package contextstart

import (
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-333 capability names. A connector announces what its release answers
// (contracts.APIContextCapabilities); the hub sends an operation, query or
// history work only when it is announced and otherwise refuses that one
// request as "connector too old". A test keeps the lists below and the
// announcement equal.
const capabilityHistory = "history"

func operationCapability(method string) string { return "operation/" + method }
func queryCapability(method string) string     { return "query/" + method }

var (
	operationMethods = []string{opResolvePod, opResolvePacketSource, opResolveArgumentSource, opStartArgumentRecording, opStartPolicyRecording, opReadProcess, opPrepareOutput, opAcquire, opComplete, opFinish, opStartProfile, opStartLogs, opStartRecording, opCollect, opStartSourceSnapshot, opResolveSourceSnapshot}
	queryMethods     = []string{queryResolveWorkload, queryResolveWorkloadIdentity, queryResolvePod, queryObserveRestarts, queryReviewAccess, queryCaptureProfiles, queryListCaptureProfiles, queryResolvePacketPeers, queryResolveProfileEndpoint, queryProfileEndpointDefinition, queryPacketRecorder, queryResolvePacketRecorder, queryResolveProfileRecorder, queryResolveSyscallRecorder, queryResolveOngoingRecorders, querySourceWork, queryLiveProjection, queryManualLive}
)

// capabilityStream is a stream that knows its connector's announcement.
type capabilityStream interface {
	connectorCapabilities() contracts.ConnectorCapabilities
}

func (s *frameStream) connectorCapabilities() contracts.ConnectorCapabilities {
	if s == nil {
		return nil
	}
	return s.capabilities
}

// requireCapability refuses one request the connector did not announce. A
// stream without an announcement (in-process fakes, the connector's own end)
// is unrestricted; the hub handler always records the Hello's set.
func requireCapability(s Stream, name string, class error) error {
	c, ok := s.(capabilityStream)
	if !ok {
		return nil
	}
	if set := c.connectorCapabilities(); set != nil && !set.Has(name) {
		return &contracts.ConnectorTooOldError{Capability: name, Class: class}
	}
	return nil
}

// Refusal classes: an operation or history work is unavailable on this
// connector; a pre-work query is unsupported, as for a region without the
// optional reader.
var (
	errOperationClass = value.ErrUnavailable
	errHistoryClass   = fleet.ErrUnavailable
	errQueryClass     = targets.ErrUnsupported
)
