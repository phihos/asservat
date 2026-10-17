package contextstart

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

func sourcePayload(t *testing.T, exchange string, sequence int, observed time.Time) []byte {
	t.Helper()
	raw, err := json.Marshal(fleet.ConnectorIdentitySource{Observation: fleet.ConnectorCredentialObservation{ObservedAt: observed, FreshUntil: observed.Add(5 * time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := contracts.EncodeAPIContextSource(contracts.APIContextSource{Format: contracts.APIContextExchangeFormat, ExchangeID: exchange, Sequence: sequence, Source: raw})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// ADR-178: the feed accepts only this exchange's expected sequence, never an
// older observation, and returns nothing that is not currently valid.
func TestSourceFeedBindsExchangeSequenceAndOrder(t *testing.T) {
	now := time.Now().UTC()
	feed := NewSourceFeed("exchange-a", func() time.Time { return now })
	if err := feed.accept(sourcePayload(t, "exchange-b", 0, now), 0); err == nil {
		t.Fatal("another exchange's source accepted")
	}
	if err := feed.accept(sourcePayload(t, "exchange-a", 1, now), 0); err == nil {
		t.Fatal("unexpected sequence accepted")
	}
	if err := feed.accept(sourcePayload(t, "exchange-a", 0, now), 0); err != nil {
		t.Fatal(err)
	}
	if err := feed.accept(sourcePayload(t, "exchange-a", 1, now.Add(-time.Second)), 1); err == nil {
		t.Fatal("older observation accepted")
	}
	if err := feed.accept(sourcePayload(t, "exchange-a", 1, now.Add(time.Second)), 1); err != nil {
		t.Fatal(err)
	}
	// The synthetic observation carries no valid profile, so it is never read
	// back as a current source: validity belongs to the reader at its own time.
	if _, err := feed.ReadConnectorIdentitySource(context.Background()); err == nil {
		t.Fatal("invalid observation returned")
	}
	unknown := bytes.Replace(sourcePayload(t, "exchange-a", 2, now.Add(2*time.Second)), []byte(`"Roles"`), []byte(`"Extra"`), 1)
	if err := feed.accept(unknown, 2); err == nil {
		t.Fatal("unknown source field accepted")
	}
}

func TestReadSourceAfterHelloRequiresSourceFrame(t *testing.T) {
	var b bytes.Buffer
	_ = contracts.WriteAPIContextFrame(&b, contracts.APIContextFrame{Kind: contracts.APIContextWorkFrame, Payload: []byte("{}")})
	if _, err := ReadSourceAfterHello(&b, "exchange-a", time.Now); err == nil {
		t.Fatal("non-source frame accepted after Hello")
	}
	b.Reset()
	_ = contracts.WriteAPIContextFrame(&b, contracts.APIContextFrame{Kind: contracts.APIContextSourceFrame, Payload: sourcePayload(t, "exchange-a", 0, time.Now().UTC())})
	if _, err := ReadSourceAfterHello(&b, "exchange-a", time.Now); err != nil {
		t.Fatal(err)
	}
}
