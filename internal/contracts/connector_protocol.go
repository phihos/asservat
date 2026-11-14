package contracts

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
)

// ConnectorProtocolMajor is the hub↔connector protocol generation (ADR-333).
// A hub admits connectors of the same major only; within it, releases differ
// by announced capabilities, and decoders ignore fields they do not know.
// Raise it only for a change an older peer cannot ignore or refuse per
// operation.
const ConnectorProtocolMajor = 1

// apiContextCapabilities is what this release's connector answers on the
// context-start exchange: "operation/<method>", "query/<method>" and
// "history". Add a name with every new operation or query and never reuse a
// name with another meaning.
var apiContextCapabilities = []string{
	"operation/resolve-pod", "operation/resolve-packet-source", "operation/resolve-argument-source", "operation/start-argument-recording", "operation/start-policy-recording",
	"operation/read-process", "operation/prepare-start", "operation/ready-start", "operation/consume-start", "operation/prepare-output", "operation/acquire-context",
	"operation/complete-stored", "operation/finish", "operation/start-profile", "operation/start-logs", "operation/start-recording", "operation/collect-recording",
	"operation/start-source-snapshot", "operation/resolve-source-snapshot",
	"query/resolve-workload", "query/resolve-workload-identity", "query/resolve-pod", "query/observe-workload-restarts", "query/review-access", "query/capture-profiles",
	"query/list-capture-profiles", "query/resolve-packet-peers", "query/resolve-profile-endpoint", "query/profile-endpoint-definition", "query/packet-recorder",
	"query/resolve-packet-recorder", "query/resolve-profile-recorder", "query/resolve-syscall-recorder", "query/resolve-ongoing-recorders", "query/source-work",
	"query/read-live-projection", "query/inspect-manual-live",
	"history",
}

// APIContextCapabilities returns this release's announcement (a copy).
func APIContextCapabilities() []string { return append([]string(nil), apiContextCapabilities...) }

// MaxConnectorCapabilities bounds a connector's announcement.
const MaxConnectorCapabilities = 128

// ConnectorCapabilities is a connector's announced capability set. A missing
// capability means the connector is too old for that operation; it never
// grants authority.
type ConnectorCapabilities map[string]struct{}

// NewConnectorCapabilities accepts at most MaxConnectorCapabilities short
// names; nil means the announcement is unusable.
func NewConnectorCapabilities(names []string) ConnectorCapabilities {
	if len(names) > MaxConnectorCapabilities {
		return nil
	}
	out := make(ConnectorCapabilities, len(names))
	for _, n := range names {
		if n == "" || len(n) > 64 {
			return nil
		}
		out[n] = struct{}{}
	}
	return out
}

func (c ConnectorCapabilities) Has(name string) bool {
	_, ok := c[name]
	return ok
}

// ConnectorTooOldError refuses one operation the connected connector did not
// announce. Class is the caller's error class (unavailable/unsupported).
type ConnectorTooOldError struct {
	Capability string
	Class      error
}

func (e *ConnectorTooOldError) Error() string {
	return "connector too old for " + e.Capability
}
func (e *ConnectorTooOldError) Unwrap() error     { return e.Class }
func (e *ConnectorTooOldError) FixedStep() string { return "connector-too-old/" + e.Capability }

// decodeOpenRPC decodes one bounded JSON value of a cross-release channel:
// unknown fields are ignored so a peer one release newer stays readable
// (ADR-333). Signed payloads keep their signature over the received bytes.
func decodeOpenRPC[T any](source io.Reader, limit int64) (T, error) {
	var out T
	if source == nil {
		return out, ErrKeyRPC
	}
	b, err := io.ReadAll(io.LimitReader(source, limit+1))
	defer clear(b)
	if err != nil || len(b) == 0 || int64(len(b)) > limit || !jsontext.Value(b).IsValid() || jsontext.Value(b).Kind() != '{' {
		return out, ErrKeyRPC
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return out, ErrKeyRPC
	}
	return out, nil
}
