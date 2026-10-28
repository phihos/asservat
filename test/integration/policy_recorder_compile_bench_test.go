//go:build cgo && libpcap

package integration

import (
	"bytes"
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/adapters/pcap"
	captureapp "asservat.local/asservat/internal/application/capture"
	planningapp "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/conversion"
)

// Real static libpcap on a dead EN10MB handle. No device/socket/collector,
// protected read, SQL or recurring worker runs in this pure compilation probe.
func BenchmarkPolicyRecorderPollCompilation(b *testing.B) {
	filters := pcap.NewCompiler()
	b.Log("linked filter compiler", filters.Version())
	compile := func(raw json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
		var wire contracts.CaptureComposition
		if err := json.Unmarshal(raw, &wire); err != nil {
			return planvalue.PolicyRecorderConfiguration{}, err
		}
		c, err := conversion.CompositionFromWire(wire)
		if err != nil || c == nil {
			return planvalue.PolicyRecorderConfiguration{}, planvalue.ErrInvalid
		}
		return planningapp.CompilePolicyRecorder(*c, filters)
	}
	original := publicPolicySpec(b, authorization.AcceptedPolicyAuthority{ClusterID: "11111111-1111-4111-8111-111111111111"})
	for _, item := range []struct{ name, filter string }{{"ordinary-port-filter", "tcp dst port 80"}, {"raw-predicate-inert-only", "tcp[13] & 2 != 0"}} {
		b.Run(item.name, func(b *testing.B) {
			spec := bytes.ReplaceAll(original, []byte("tcp dst port 80"), []byte(item.filter))
			b.ReportAllocs()
			for b.Loop() {
				p, err := captureapp.CompilePolicyWithRecorders(spec, planningapp.ContextRecipeName, planningapp.RecipeDigest(), compile)
				if err != nil || p.Recorder == nil {
					b.Fatal("real policy compilation", err)
				}
			}
		})
	}
}
