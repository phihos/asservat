package mtls

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

func TestConnectorOperationWireBindsActualV2ExporterAndOriginalDates(t *testing.T) {
	f := newConnectorOperationFixture(t)
	o := f.begin(t, f.root)
	w, err := o.read(f.root, 1)
	if err != nil {
		t.Fatal(err)
	}
	channel, err := observationOperationConnection(f.state, f.request)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := ownerObservationConnection(f.state, f.request)
	if err != nil || v1 == channel {
		t.Fatal("v2 reused v1 exporter domain", err)
	}
	if _, err := parseConnectorOperationReply(w, f.pin, f.local.Registration.Certificate, f.request, 1, channel, f.f.clock()); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"v1-purpose", "v1-request", "v1-exporter", "bracket", "ordinal", "early-final", "native-start", "native-end", "value-before-native", "value-after-now", "source-after-native", "workload-after-native", "leaf", "pin", "role-pins", "request", "noncanonical-time"} {
		t.Run(mode, func(t *testing.T) {
			x := w
			p := f.pin.Clone()
			switch mode {
			case "v1-purpose":
				x.Format = contracts.ConnectorObservationFormat
			case "v1-request":
				x.Request.Format = contracts.OwnerObservationFormat
			case "v1-exporter":
				x.ConnectionBinding = ownerObservationHex(v1)
			case "bracket":
				x.BracketID = ""
			case "ordinal":
				x.Ordinal = 2
			case "early-final":
				x.Final = true
			case "native-start":
				x.NativeStartedAt = f.request.RequestedAt.Add(-time.Second).Format(time.RFC3339Nano)
			case "native-end":
				x.NativeUntil = f.request.NotAfter.Add(time.Second).Format(time.RFC3339Nano)
			case "value-before-native":
				x.ValueObservedAt = f.request.RequestedAt.Add(-time.Millisecond).Format(time.RFC3339Nano)
			case "value-after-now":
				x.ValueObservedAt = f.f.clock().Add(time.Millisecond).Format(time.RFC3339Nano)
			case "source-after-native":
				x.SourceFreshUntil = f.request.NotAfter.Add(time.Second).Format(time.RFC3339Nano)
			case "workload-after-native":
				x.WorkloadFreshUntil = f.request.NotAfter.Add(time.Second).Format(time.RFC3339Nano)
			case "leaf":
				x.ConnectorLeaf = ownerObservationHex(artifact.Digest{99})
			case "pin":
				x.PinDigest = ownerObservationHex(artifact.Digest{99})
			case "role-pins":
				p.Roles.Source = "changed_source"
			case "request":
				x.Request.Challenge = ownerTestID
			case "noncanonical-time":
				x.ValueObservedAt = "2026-10-13T12:00:00.000Z"
			}
			if _, err := parseConnectorOperationReply(x, p, f.local.Registration.Certificate, f.request, 1, channel, f.f.clock()); err == nil {
				t.Fatal("wrong v2 correlation accepted")
			}
		})
	}
	if _, err := f.producer.begin(context.Background(), f.root, f.state, f.local.Registration.Certificate, f.request); err == nil {
		t.Fatal("unbounded stream root accepted")
	}
}
