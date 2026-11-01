package contextstart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type overLimitProfiles struct{ countingLocal }

func (*overLimitProfiles) ReadCaptureProfiles(context.Context, targets.ProfileCatalogRequest) (targets.ProfileCatalogAnswer, error) {
	return targets.ProfileCatalogAnswer{}, targets.ErrUnavailable
}
func (*overLimitProfiles) ListCaptureProfiles(context.Context, targets.ProfileListRequest) (targets.ProfileCatalogAnswer, error) {
	return targets.ProfileCatalogAnswer{}, targets.ErrProfileLimit
}

// REQ-CPR-001: an over-limit namespace catalog crosses the regional exchange
// as its own closed label, so the hub can report TooManyProfiles rather than
// an outage, without reusing the generic target limit.
func TestProfileListLimitCrossesRegionalExchange(t *testing.T) {
	now := time.Now().UTC()
	work := workFixture()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	receiver := fleet.APIContextReceiver{Channel: work.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	var output bytes.Buffer
	stream, err := newFrameStream(ctx, work.Work.Channel, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil }, bytes.NewReader(nil), &output, func(time.Time) error { return nil }, func(time.Time) error { return nil }, func() error { return nil }, func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.targets = &overLimitProfiles{}
	raw, _ := json.Marshal(targets.ProfileListRequest{ClusterID: work.Work.Channel.Connector.Binding.ClusterID, Namespace: cfg.NamespaceRef{Name: "app", UID: "namespace"}})
	payload, err := contracts.EncodeAPIContextOperation(contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: queryListCaptureProfiles, Body: raw})
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.answerQuery(ctx, contracts.APIContextFrame{Kind: contracts.APIContextQueryFrame, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame, err := contracts.ReadAPIContextFrame(&output)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := contracts.DecodeAPIContextOperationReply(frame.Payload)
	if err != nil || reply.Failure != "profile-limit" || !errors.Is(queryFailureError(reply.Failure), targets.ErrProfileLimit) || errors.Is(queryFailureError(reply.Failure), targets.ErrLimit) {
		t.Fatal("profile limit lost across the exchange", reply, err)
	}
}
