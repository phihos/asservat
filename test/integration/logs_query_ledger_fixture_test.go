package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/logs"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real protected admission/publication and compiled query/key roles. The native
// payload, process/Job/Pod/issuer and positive transport joins are synthetic.
func TestLogsQueryLifecycleWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, objects *objectstore.Store) {
		withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, objects, qualifyPacketQueryManagedLifecycle, false, false, false, false, false, false, true)
	})
}
func logsQueryComposition() planvalue.ProfileComposition {
	return planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "saved", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "finite-logs", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "logs", Field: "actionMaxBytes", Number: artifact.LogNativeLimit}}}}, MaxTotalBytes: artifact.LogNativeLimit, MaxDuration: "10s"}
}
func logsLedgerFunding(t *testing.T, f *capacitySQLFixture, group ...bool) {
	t.Helper()
	registration := artifact.Registration{NativeLimit: artifact.LogNativeLimit}
	stream := artifact.StreamingPlan{Registration: registration}
	native := registration.ReservedBytes() + stream.TemporaryBytes()
	objects := int64(5 + stream.PartLimit())
	if len(group) > 0 && group[0] {
		native = 2*native + 2*(artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
		objects = 2*objects + 8
	}
	// Reuse the existing qualified large-native protocol. The legacy eight-MiB
	// evidence ceiling cannot fund a64MiB log, irrespective of spare bytes.
	in := &f.qualification.RootBacking
	in.ContextHistory.ProfileProtocol = capacityapp.ProfileProtocolVersion
	records := objects / 4
	if records > in.RecordsPerAccount {
		in.RecordsPerAccount, in.Capture.RecordsPerAccount = records, records
		in.Capture.Policy.MetadataSlots = in.Capture.Accounts * records
		backup, wal := in.ContextHistory.Capture.SlotBacking(in.ContextHistory.CapturePurgeLeases)
		in.Capture.Policy.BackupReservedBytes = in.Capture.Policy.MetadataSlots * backup
		in.Capture.Policy.WALReservedBytes = in.Capture.Policy.MetadataSlots * wal
		in.ProcessingState.MaxCaptures = in.Accounts * records
		in.ProcessingState.BackupBytes, in.ProcessingState.WALBytes, _ = in.ProcessingState.RequiredBytes()
	}
	f.fund(native)
}
func logsQuerySyntheticNative(t *testing.T, e artifact.ContextExpectation, from, until time.Time) []byte {
	t.Helper()
	start, end, err := e.Logs.Window(e.TriggeredAt)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	enc, err := logs.NewEncoder(t.Context(), &b, artifact.LogHeader{Record: "header", Format: artifact.LogFormat, PodUID: e.PodUID, WindowStart: start, WindowEnd: end, Origins: 1}, e.Registration.NativeLimit)
	if err != nil {
		t.Fatal(err)
	}
	if err = enc.BeginOrigin(artifact.LogOrigin{Record: "origin", OriginID: 0, ContainerKind: "regular", ContainerName: "app", Source: "current", Stream: "combined"}); err != nil {
		t.Fatal(err)
	}
	if _, err = enc.Write([]byte("synthetic managed logs\nsecond line\n")); err != nil {
		t.Fatal(err)
	}
	if err = enc.EndOrigin(artifact.LogCoverage{Record: "coverage", OriginID: 0, FetchOutcome: "complete", FetchStartedAt: &from, FetchFinishedAt: &until, Gaps: []string{"rotationUnknown", "timestampUnknown"}}); err != nil {
		t.Fatal(err)
	}
	if err = enc.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func assertLogsOriginalCollectCutoff(t *testing.T, ctx context.Context, store *postgres.APIContextExecutions, e artifact.ContextExpectation) {
	t.Helper()
	_, end, err := e.Logs.Window(e.TriggeredAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, ready := range []bool{false, true} {
		cutoff := end
		if !ready {
			cutoff = cutoff.Add(-time.Microsecond)
		}
		ids, err := store.StartedRecordings(ctx, cutoff, 64)
		if err != nil {
			t.Fatal("logs original collect cutoff", err)
		}
		found := false
		for _, id := range ids {
			found = found || id == e.CaptureUID
		}
		if found != ready {
			t.Fatal("logs readiness renewed/replaced original trigger+after", ready, found)
		}
	}
}

func publishQueryLedgerLogs(t *testing.T, f *capacitySQLFixture, s captureAdmissionScenario, accepted capture.Accepted, execSQL *postgres.APIContextExecutions) (captureAdmissionScenario, publishedContext) {
	t.Helper()
	started, refresh := startQueryLedgerProfile(t, f, s, accepted, execSQL)
	return publishPreparedQueryLedgerContext(t, f, s, accepted, execSQL, started, refresh, false)
}

// Reconstruct the already accepted root's existing capture publication facets;
// unlike prepareManagedContext this does not initialize a new retention epoch.
func logsExistingCapturePublisher(t *testing.T, f *queryLedgerFixture) *postgres.CaptureIntents {
	t.Helper()
	b := f.base
	intents, err := postgres.NewCaptureIntents(b.ctx, b.roles["capture-admit"], b.input.PermissionRootID)
	if err != nil {
		t.Fatal(err)
	}
	return intents
}
