package integration

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
	planvalue "asservat.local/asservat/internal/domain/planning"
)

func manualArgumentsNativeFixture(t *testing.T) ([]byte, installedArgumentsSource) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	args, err := (installedArgumentsCompiler{}).CompileArguments([]string{"write"}, true, 128)
	if err != nil {
		t.Fatal(err)
	}
	source := artifact.ArgumentSourceProvenance{PodUID: "pod", NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", SessionID: "session", Fence: "fence", StartedAt: now, StartBy: now.Add(time.Second), Until: now.Add(6 * time.Second)}
	expected := installedArgumentsSource{Source: source, Arguments: args, ByteCredit: 6 * planvalue.SensitiveMaxBytesPerSecond, EventCredit: manualArgumentsRate * 6, DurationMillis: 5000, Rate: manualArgumentsRate}
	header := artifact.ArgumentHeader{Record: "header", Format: syscalls.ArgumentNativeFormat, PodUID: source.PodUID, NodeUID: source.NodeUID, BootID: source.BootID, CollectorPodUID: source.CollectorPodUID, SourceEpoch: source.CollectorEpoch, SessionID: source.SessionID, Fence: source.Fence, EngineDigest: hex.EncodeToString(args.ProgramDigest[:]), DefinitionDigest: hex.EncodeToString(args.DefinitionDigest[:]), AccountingRule: hex.EncodeToString(args.AccountingRule[:]), Decoder: syscalls.ArgumentDecoderVersion, ABI: syscalls.ABI, StartedAt: now}
	duration, events, charged := uint64(1), uint64(2), uint64(768)
	event := artifact.ArgumentEventLine{Record: "event", Event: artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{PodUID: "pod", ProcessRef: "p:1:1@boot@epoch", ThreadRef: "t:1:1@boot@epoch"}, Syscall: "write", ABI: syscalls.ABI, Timestamp: now.Format(time.RFC3339Nano), DurationNS: &duration, Outcome: "success", Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:1"}, {Name: "buffer", Value: "base64:" + base64.StdEncoding.EncodeToString([]byte(manualArgumentsMarker+"\n"))}}}}
	footer := artifact.ArgumentFooter{Record: "footer", EndedAt: now.Add(5 * time.Second), Outcome: "completed", Retained: 1, CoverageUnknown: true, ObservedEvents: &events, ObservedBytes: &charged}
	var native []byte
	for _, line := range []any{header, event, footer} {
		native, err = syscalls.AppendArgumentLine(native, line)
		if err != nil {
			t.Fatal(err)
		}
	}
	return native, expected
}
