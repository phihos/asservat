package integration

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The owned fixture supplies a real independently reviewed argument acquisition,
// encrypted verified publication and compiled hub/key roles. Payload, target,
// native Job/Pod/issuer/join facts are synthetic; no collector is invoked.
func TestRawSyscallQueryLifecycleWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifyPacketQueryManagedLifecycle, false, false, false, false, false, true)
	})
}
func packetQueryFixtureOperation(f *queryLedgerFixture) string {
	if f.published.Expectation.NativeType == artifact.LogsArtifact {
		return value.GrantLogQueryOperation
	}
	if f.published.Expectation.NativeType == artifact.SyscallArgumentsArtifact {
		return value.GrantSyscallQueryOperation
	}
	return value.GrantPacketQueryOperation
}
func syscallQuerySyntheticNative(t *testing.T, e artifact.ContextExpectation, original installedArgumentsSource, from, until time.Time) []byte {
	t.Helper()
	a, s := original.Arguments, original.Source
	header := artifact.ArgumentHeader{Record: "header", Format: syscalls.ArgumentNativeFormat, PodUID: s.PodUID, NodeUID: s.NodeUID, BootID: s.BootID, CollectorPodUID: s.CollectorPodUID, SourceEpoch: s.CollectorEpoch, SessionID: s.SessionID, Fence: s.Fence, EngineDigest: hex.EncodeToString(a.ProgramDigest[:]), DefinitionDigest: hex.EncodeToString(a.DefinitionDigest[:]), AccountingRule: hex.EncodeToString(a.AccountingRule[:]), Decoder: syscalls.ArgumentDecoderVersion, ABI: syscalls.ABI, StartedAt: from}
	duration, events, charged := uint64(1), uint64(2), uint64(768)
	event := artifact.ArgumentEventLine{Record: "event", Event: artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{PodUID: e.PodUID, ProcessRef: "p:1:1@" + s.BootID + "@" + s.CollectorEpoch, ThreadRef: "t:1:1@" + s.BootID + "@" + s.CollectorEpoch}, Syscall: "write", ABI: syscalls.ABI, Timestamp: from.Add(time.Microsecond).Format(time.RFC3339Nano), DurationNS: &duration, Outcome: "success", Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:1"}, {Name: "buffer", Value: "base64:" + base64.StdEncoding.EncodeToString([]byte(manualArgumentsMarker+"\n"))}}}}
	footer := artifact.ArgumentFooter{Record: "footer", EndedAt: until, Outcome: "completed", Retained: 1, CoverageUnknown: true, ObservedEvents: &events, ObservedBytes: &charged}
	var body []byte
	for _, line := range []any{header, event, footer} {
		var err error
		body, err = syscalls.AppendArgumentLine(body, line)
		if err != nil {
			t.Fatal(err)
		}
	}
	check, err := syscalls.NewArgumentCheck(e, s)
	if err != nil {
		t.Fatal(err)
	}
	if err = check.Write(body); err != nil || check.Close() != nil {
		t.Fatal("synthetic argument source violates accepted source", err)
	}
	return body
}

func TestRawSyscallQueryManagedPayloadPreservesArgumentProvenance(t *testing.T) {
	_, original := manualArgumentsNativeFixture(t)
	expected := artifact.ContextExpectation{PodUID: original.Source.PodUID, Recording: &artifact.Recording{Kind: "syscallTrace", Profile: "arguments", MaxBytes: artifact.RecordingNativeLimit, DurationMillis: 5000, Syscalls: &artifact.RecordingSyscalls{Names: []string{"write"}, MaxEvents: manualArgumentsRetained, MaxEventsPerSecond: manualArgumentsRate, MaxTrackedThreads: 64}, Arguments: &original.Arguments}}
	body := syscallQuerySyntheticNative(t, expected, original, original.Source.StartedAt, original.Source.StartedAt.Add(2*time.Millisecond))
	if footer, err := checkManualArgumentsNative(body, expected.PodUID, original); err != nil || footer.Retained != 1 {
		t.Fatal("managed argument payload/source/counters", footer.Retained, err)
	}
}
