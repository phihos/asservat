// Package connectorlifecycle carries ADR-169's delegated regional lifecycle
// conversation: one exporter-bound ADR-168 presentation, then hub-driven
// ADR-153 phase requests answered by the regional process over the same
// full-duplex HTTP/2 stream. Every effect stays with the hub.
package connectorlifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

const (
	Path        = "/v1/connector-lifecycle"
	ContentType = "application/x-ndjson"
	// Enrollment needs six (one configuration, one begin acknowledgement and
	// four phase observations) and registration two; two spare.
	MaxFrameBytes  = 256 << 10
	MaxRegionFrame = 8
	// PurposeRegistration asks for the current activated registration of one
	// leaf of the presenting process. It runs no lifecycle and has no effect.
	PurposeRegistration value.ConnectorLifecyclePurpose = "registration"
	// ADR-172 read-only owner purposes: the current context-start owner set,
	// and the hub's authentication facts for one observed owner certificate.
	PurposeOwnerCandidates     value.ConnectorLifecyclePurpose = "owner-candidates"
	PurposeOwnerAuthentication value.ConnectorLifecyclePurpose = "owner-authentication"
	// ADR-197 read-only owner purposes for regional capacity observation: the
	// owner observation candidates, and one owner certificate's current
	// registration. Answered from hub SQL; no delegated region reads.
	PurposeOwnerObservationCandidates value.ConnectorLifecyclePurpose = "owner-observation-candidates"
	PurposeOwnerRegistration          value.ConnectorLifecyclePurpose = "owner-registration"
	// PurposeRecovery asks for the hub's current recovery state, which the
	// region's verify-only work-trust reader requires. It is read-only.
	PurposeRecovery value.ConnectorLifecyclePurpose = "recovery"
	// PurposeBootstrap enrolls cluster credential generation 1 from a fleet
	// operator's one-use bootstrap (ADR-193). It carries no presentation.
	PurposeBootstrap value.ConnectorLifecyclePurpose = "bootstrap"
)

// BootstrapOpening is the generation-1 request: the one-use bootstrap
// secret, the identity-free CSR of the pending key, and the signature of that
// key over this connection's exporter.
type BootstrapOpening struct {
	Secret    string
	CSRDER    []byte
	Request   value.ClusterBootstrapRequest
	Signature []byte
}

// OwnerAuthentication is the hub's answer for one observed owner certificate.
// It cannot authenticate a TLS peer until the region verifies its own actual
// session against Configuration and requires the identical certificate.
type OwnerAuthentication struct {
	Owner         value.AuthenticatedOwner
	Configuration value.OwnerConfigurationObservation
}

var ErrChannel = errors.New("connector lifecycle channel unavailable")

// Opening is the connector's first frame.
type Opening struct {
	Presentation contracts.ClusterCredentialWire
	Purpose      value.ConnectorLifecyclePurpose
	OperationID  string
	Request      value.ConnectorProcessRequest
	Certificate  *value.ConnectorCredentialCertificate `json:",omitempty"` // registration only
	Owner        *value.OwnerCertificate               `json:",omitempty"` // owner authentication only
	Bootstrap    *BootstrapOpening                     `json:",omitempty"` // bootstrap only
}

// HubFrame drives the conversation; exactly one of its payloads is set.
type HubFrame struct {
	Kind         string                            // begin, read, close, source, configuration, result, failure
	Begin        *app.ConnectorLifecycleRequest    `json:",omitempty"`
	Phase        value.ConnectorLifecyclePhase     `json:",omitempty"`
	Process      *value.ConnectorCredentialProcess `json:",omitempty"`
	Credential   *value.IssuedConnectorCredential  `json:",omitempty"`
	Registration *app.ConnectorLeafRegistration    `json:",omitempty"`
	Owners       *value.APIContextOwnerCandidates  `json:",omitempty"`
	Owner        *OwnerAuthentication              `json:",omitempty"`
	// OwnerRegistration answers PurposeOwnerRegistration (ADR-197).
	OwnerRegistration *value.OwnerRegistrationObservation `json:",omitempty"`
	Recovery     *value.RecoveryState              `json:",omitempty"`
	Bootstrap    *value.ClusterBootstrapResult     `json:",omitempty"`
	Failure      string                            `json:",omitempty"`
}

// RegionFrame answers one hub frame.
type RegionFrame struct {
	Kind          string                               // begun, observation, source, configuration, error
	Observation   *value.ConnectorLifecycleObservation `json:",omitempty"`
	Source        *value.ConnectorIdentitySource       `json:",omitempty"`
	Configuration *app.ConnectorIdentityConfiguration  `json:",omitempty"`
}

// Local is the regional process's in-cluster reader set: the native lifecycle
// phases and the protected connector source/configuration.
type Local interface {
	app.ConnectorLifecycleOperationReader
	app.ConnectorIdentitySourceReader
	app.ConnectorIdentityConfigurationReader
}

// Conn is one decoded/encoded frame stream with a per-read deadline control.
type Conn struct {
	mu       sync.Mutex
	dec      *json.Decoder
	enc      *json.Encoder
	flush    func() error
	deadline func(time.Time) error
	frames   int
}

func NewConn(r io.Reader, w io.Writer, flush func() error, deadline func(time.Time) error) *Conn {
	d := json.NewDecoder(io.LimitReader(r, int64(MaxRegionFrame+1)*MaxFrameBytes))
	d.DisallowUnknownFields()
	return &Conn{dec: d, enc: json.NewEncoder(w), flush: flush, deadline: deadline}
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
