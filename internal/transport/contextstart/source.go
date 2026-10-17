package contextstart

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

// SourceFeed holds one exchange's regional connector source observations
// (ADR-178). It is read only within its own original validity and is never
// renewed. The hub's ingress reads it in place of the regional Kubernetes API.
// Each observation must be no older than the last.
type SourceFeed struct {
	mu       sync.Mutex
	exchange string
	latest   *fleet.ConnectorIdentitySource
	now      func() time.Time
}

var _ app.ConnectorIdentitySourceReader = (*SourceFeed)(nil)

func NewSourceFeed(exchange string, now func() time.Time) *SourceFeed {
	return &SourceFeed{exchange: exchange, now: now}
}

// accept decodes one source frame with the expected sequence.
func (f *SourceFeed) accept(payload []byte, sequence int) error {
	if f == nil || f.now == nil {
		return fleet.ErrInvalid
	}
	m, e := contracts.DecodeAPIContextSource(payload)
	if e != nil || m.ExchangeID != f.exchange || m.Sequence != sequence {
		return contracts.ErrAPIContextProtocol
	}
	var s fleet.ConnectorIdentitySource
	d := json.NewDecoder(bytes.NewReader(m.Source))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.More() {
		return contracts.ErrAPIContextProtocol
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Validity is the reader's check, at its own time; acceptance only keeps
	// observations monotonic so an older one can never return.
	if f.latest != nil && s.Observation.ObservedAt.Before(f.latest.Observation.ObservedAt) {
		return fleet.ErrDenied
	}
	f.latest = &s
	return nil
}

func (f *SourceFeed) ReadConnectorIdentitySource(ctx context.Context) (fleet.ConnectorIdentitySource, error) {
	if f == nil || ctx == nil || ctx.Err() != nil {
		return fleet.ConnectorIdentitySource{}, fleet.ErrUnavailable
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.latest == nil || !f.latest.Valid(f.now()) {
		return fleet.ConnectorIdentitySource{}, fleet.ErrUnavailable
	}
	return *f.latest, nil
}

// ReadSourceAfterHello reads the region's first source frame, which follows
// its Hello on the same body, into a new feed.
func ReadSourceAfterHello(r interface{ Read([]byte) (int, error) }, exchange string, now func() time.Time) (*SourceFeed, error) {
	frame, e := contracts.ReadAPIContextFrame(r)
	defer clear(frame.Payload)
	if e != nil || frame.Kind != contracts.APIContextSourceFrame {
		return nil, contracts.ErrAPIContextProtocol
	}
	feed := NewSourceFeed(exchange, now)
	if e = feed.accept(frame.Payload, 0); e != nil {
		return nil, e
	}
	return feed, nil
}

// SourceFrame reads the region's own current source and encodes it for one
// exchange. It is the only way a source enters the exchange.
func SourceFrame(ctx context.Context, source app.ConnectorIdentitySourceReader, exchange string, sequence int) (contracts.APIContextFrame, error) {
	if source == nil || ctx == nil {
		return contracts.APIContextFrame{}, fleet.ErrInvalid
	}
	observed, e := source.ReadConnectorIdentitySource(ctx)
	if e != nil {
		return contracts.APIContextFrame{}, e
	}
	raw, e := json.Marshal(observed)
	if e != nil {
		return contracts.APIContextFrame{}, fleet.ErrInvalid
	}
	payload, e := contracts.EncodeAPIContextSource(contracts.APIContextSource{Format: contracts.APIContextExchangeFormat, ExchangeID: exchange, Sequence: sequence, Source: raw})
	if e != nil {
		return contracts.APIContextFrame{}, e
	}
	return contracts.APIContextFrame{Kind: contracts.APIContextSourceFrame, Payload: payload}, nil
}
