// Package connectorlifecycle carries the connector's finite hub
// conversations: one opening authenticated by the connector's ServiceAccount
// token (ADR-334), then at most one hub request for a delivery answered over
// the same full-duplex HTTP/2 stream. Every effect stays with the hub.
package connectorlifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Purpose names one conversation's single question or delivery.
type Purpose string

const (
	Path        = "/v1/connector-lifecycle"
	ContentType = "application/x-ndjson"
	// MaxRegionFrame bounds the connector's frames in one conversation.
	MaxFrameBytes  = 256 << 10
	MaxRegionFrame = 2
	// ADR-172 read-only owner purposes: the current context-start owner set,
	// and the hub's authentication facts for one observed owner certificate.
	PurposeOwnerCandidates     Purpose = "owner-candidates"
	PurposeOwnerAuthentication Purpose = "owner-authentication"
	// PurposeAccessBindings delivers the connector's complete AccessBinding
	// LIST of its cluster (ADR-329). The hub asks for it only after the
	// presentation verified; the delivery is attributed to that cluster.
	PurposeAccessBindings Purpose = "access-bindings"
	// PurposeSettings returns the settings the connector needs from the hub
	// (REQ-FED-001): its cluster and peer IDs, the hub's offer and its
	// cluster's object-store capabilities. It is the first conversation of
	// a connector process, so its opening names no process binding.
	PurposeSettings Purpose = "settings"
)

// Settings are the hub's answer to PurposeSettings. Evidence and History are
// the cluster's own object-store capabilities, scoped to its cluster ID.
type Settings struct {
	ClusterID, PeerID string
	Offer             contracts.RegionalOffer
	Evidence, History contracts.OwnerStorageCredential
}

// OwnerAuthentication is the hub's answer for one observed owner certificate.
// It cannot authenticate a TLS peer until the region verifies its own actual
// session against Configuration and requires the identical certificate.
type OwnerAuthentication struct {
	Owner         value.AuthenticatedOwner
	Configuration value.OwnerConfigurationObservation
}

var ErrChannel = errors.New("connector lifecycle channel unavailable")

// Opening is the connector's first frame. Process names the connector
// process; its binding must name the token's cluster and peer.
type Opening struct {
	Purpose     Purpose
	OperationID string
	Process     value.ConnectorProcessIdentity
	Owner       *value.OwnerCertificate `json:",omitempty"` // owner authentication only
}

// HubFrame drives the conversation; exactly one of its payloads is set.
type HubFrame struct {
	Kind     string                           // access-bindings, result, failure
	Owners   *value.APIContextOwnerCandidates `json:",omitempty"`
	Owner    *OwnerAuthentication             `json:",omitempty"`
	Settings *Settings                        `json:",omitempty"`
	Failure  string                           `json:",omitempty"`
	// Digest is the hub's stored delivery digest of an "access-bindings"
	// request; the connector answers Unchanged when its current delivery has
	// the same digest (ADR-329).
	Digest string `json:",omitempty"`
}

// RegionFrame answers one hub frame.
type RegionFrame struct {
	Kind string // access-bindings, capacity, error
	// AccessBindings answers the hub's "access-bindings" request (ADR-329).
	AccessBindings *contracts.AccessBindingDelivery `json:",omitempty"`
	// Unchanged answers a delivery request whose digest matches.
	Unchanged bool `json:",omitempty"`
}

// AccessBindingsLocal is the regional reader of the connector's own
// AccessBinding LIST (ADR-329), offered only by a delivering conversation.
type AccessBindingsLocal interface {
	ReadAccessBindings(context.Context) (contracts.AccessBindingDelivery, error)
}

// Conn is one decoded/encoded frame stream with a per-read deadline control.
type Conn struct {
	mu       sync.Mutex
	limit    *frameLimit
	dec      *json.Decoder
	enc      *json.Encoder
	flush    func() error
	deadline func(time.Time) error
	frames   int
}

func NewConn(r io.Reader, w io.Writer, flush func() error, deadline func(time.Time) error) *Conn {
	limit := &frameLimit{r: r, n: int64(MaxRegionFrame+1) * MaxFrameBytes}
	d := json.NewDecoder(limit)
	// Unknown fields of a newer peer are ignored (ADR-333).
	return &Conn{limit: limit, dec: d, enc: json.NewEncoder(w), flush: flush, deadline: deadline}
}

// frameLimit bounds the bytes a conversation reads; only an authenticated
// AccessBinding delivery raises it, once, by its own bound (ADR-329).
type frameLimit struct {
	r io.Reader
	n int64
}

func (l *frameLimit) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

func (c *Conn) Send(v any) error {
	if err := c.enc.Encode(v); err != nil {
		return ErrChannel
	}
	if c.flush != nil {
		if err := c.flush(); err != nil {
			return ErrChannel
		}
	}
	return nil
}

func (c *Conn) Receive(ctx context.Context, v any) error {
	if c.frames >= MaxRegionFrame+1 {
		return ErrChannel
	}
	c.frames++
	// A bounded read deadline is mandatory: it is what unblocks Decode when the
	// caller's context ends, so no receive can outlive its original bound.
	d, ok := ctx.Deadline()
	if !ok || c.deadline == nil || c.deadline(d) != nil {
		return ErrChannel
	}
	done := make(chan error, 1)
	go func() { done <- c.dec.Decode(v) }()
	select {
	case err := <-done:
		if err != nil {
			return ErrChannel
		}
		return ctx.Err()
	case <-ctx.Done():
		<-done // the read deadline above ends Decode by the same instant
		return ctx.Err()
	}
}
