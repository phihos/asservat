package contracts

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"strings"
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
	"operation/read-process", "operation/prepare-output", "operation/acquire-context",
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

// decodeOpenRPC decodes one bounded JSON value of a cross-release channel.
// Unknown members are ignored so a peer one release newer stays readable
// (ADR-333); known members keep the closed decoder's rules (exact case, no
// duplicate, no null for a value, canonical spelling), checked by
// SameKnownFields against the typed value's re-encoding.
func decodeOpenRPC[T any](source io.Reader, limit int64) (T, error) {
	var out, zero T
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
		return zero, ErrKeyRPC
	}
	normal, err := json.Marshal(out)
	defer clear(normal)
	if err != nil || !SameKnownFields(b, normal) {
		return zero, ErrKeyRPC
	}
	return out, nil
}

// SameKnownFields reports whether received equals canonical after removing
// the object members of received that canonical (this release's encoding of
// the decoded value) does not have. Member names are compared exactly, so a
// wrong-case alias of a known member is not that member, and a null or
// noncanonical spelling of a known value differs. received must be valid
// JSON without duplicate names (jsontext validation).
func SameKnownFields(received, canonical []byte) bool {
	if !jsontext.Value(received).IsValid() {
		return false
	}
	var r, c any
	for _, x := range []struct {
		b   []byte
		out *any
	}{{received, &r}, {canonical, &c}} {
		d := json.NewDecoder(bytes.NewReader(x.b))
		d.UseNumber()
		if d.Decode(x.out) != nil || d.Decode(new(any)) != io.EOF {
			return false
		}
	}
	p, ok := knownProjection(r, c)
	if !ok {
		return false
	}
	projected, err := json.Marshal(p)
	if err != nil {
		return false
	}
	want, err := json.Marshal(c)
	if err != nil {
		return false
	}
	a, b := jsontext.Value(projected), jsontext.Value(want)
	return a.Canonicalize() == nil && b.Canonicalize() == nil && bytes.Equal(a, b)
}

// knownProjection keeps the members of r that shape has, recursively. A
// member that matches a known name only case-insensitively is an alias of a
// known field (encoding/json would read it), so it is refused.
func knownProjection(r, shape any) (any, bool) {
	switch s := shape.(type) {
	case map[string]any:
		m, ok := r.(map[string]any)
		if !ok {
			return r, true
		}
		out := make(map[string]any, len(s))
		for k, v := range m {
			sv, known := s[k]
			if !known {
				for name := range s {
					if strings.EqualFold(name, k) {
						return nil, false
					}
				}
				continue
			}
			p, ok := knownProjection(v, sv)
			if !ok {
				return nil, false
			}
			out[k] = p
		}
		return out, true
	case []any:
		a, ok := r.([]any)
		if !ok || len(a) != len(s) {
			return r, true
		}
		out := make([]any, len(a))
		for i := range a {
			p, ok := knownProjection(a[i], s[i])
			if !ok {
				return nil, false
			}
			out[i] = p
		}
		return out, true
	}
	return r, true
}
