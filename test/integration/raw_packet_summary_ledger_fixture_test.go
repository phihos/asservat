package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual reviewed raw capture admission/publication and compiled hub/key roles.
// The workload packet generator, Pod/Job/issuer and native join remain synthetic.
func TestRawPacketSummaryLifecycleWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		t.Run("raw-pcapng-compiled-lifecycle", func(t *testing.T) {
			withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifyRawPacketSummaryLifecycle, false, false, false, true, true)
		})
	})
}

func syntheticRawPacketSummaryRecording(t *testing.T, started, end time.Time) []byte {
	t.Helper()
	rec, err := packets.NewRawRecorder(recordingProgram, 1<<20, started, "synthetic", packets.RawLimits{Snaplen: 96, TCP: manualRawTCPCap})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[:2], 40000)
		binary.BigEndian.PutUint16(tcp[2:4], 80)
		tcp[12] = 5 << 4
		payload := []byte(strings.Repeat("SYNTHETIC-RAW-PAYLOAD", 5))
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+len(tcp)+len(payload)))
		frame := append(append(append([]byte{0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 8, 0}, ip...), tcp...), payload...)
		rec.Add(frame, uint32(len(frame)), started.Add(time.Duration(i)*time.Microsecond))
	}
	out, c, err := rec.Close(end, 0)
	if err != nil || c.Retained != 50 {
		t.Fatal("raw fixture packets", c, err)
	}
	return append([]byte(nil), out...)
}

func refuseRetainedRawPacketSummaryDowngrade(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	// The shared metadata fixture checks the same minimized-audit conservative
	// rollback fence and all retained query/key/allocation snapshots at138.
	refuseRetainedPacketSummaryDowngrade(t, f)
}

func qualifyRawPacketSummaryLifecycle(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	snapshot := func() string {
		var b []byte
		if err := f.base.admin.QueryRow(f.base.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY id),'[]'::jsonb) FROM access_grant g WHERE root_id=$1`, f.base.input.PermissionRootID).Scan(&b); err != nil || !json.Valid(b) {
			t.Fatal("grant snapshot", err)
		}
		return string(b)
	}
	before := snapshot()
	routes, err := postgres.NewContextCaseReads(f.base.ctx, f.base.roles["hub-runtime"], f.base.input.PermissionRootID, f.scenario.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	who := f.scenario.a.Eligibility.VerifiedIdentity
	who.Scopes = []string{"evidence:read"}
	now := time.Now().UTC().Truncate(time.Microsecond)
	who.VerifiedAt, who.ValidUntil = now, now.Add(5*time.Second)
	recovery, err := f.scenario.recovery.reader.RecoveryState(f.base.ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := f.published.Expectation
	route, err := routes.ResolvePacketProjectionRoute(f.base.ctx, e.CaseID, e.Registration.Location.ArtifactID, who, recovery)
	if err != nil || route.NativeType != artifact.RawPCAPNGArtifact || route.PodUID != e.PodUID {
		t.Fatal("same-read raw native route", route.NativeType, err)
	}
	qualifySharedProjectionLifecycle(t, f)
	if after := snapshot(); after != before {
		t.Fatal("ordinary raw summary changed any acquisition/raw/native grant or spend")
	}
	t.Log("raw source preserved; ordinary fixed summary leaves every grant and spend byte-exact, no native session; same bounded route lookup exposes only raw native discriminator")
}

func TestRawPacketSummaryManagedPayload(t *testing.T) {
	start := time.Now().UTC()
	end := start.Add(time.Millisecond)
	native := syntheticRawPacketSummaryRecording(t, start, end)
	if !bytes.Contains(native, []byte("SYNTHETIC-RAW-PAYLOAD")) {
		t.Fatal("managed source was silently sanitized")
	}
	if count, err := packets.CheckRaw(bytes.NewReader(native), packets.RawLimits{Snaplen: 96, TCP: manualRawTCPCap}); err != nil || count != 50 {
		t.Fatal("actual raw canonical check", count, err)
	}
	e := artifact.ContextExpectation{NativeType: artifact.RawPCAPNGArtifact, DataClass: "raw", Registration: artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}, Recording: &artifact.Recording{Profile: "rawPackets", Snaplen: 96, ProtocolSnaplen: &artifact.RecordingProtocolSnaplen{TCP: manualRawTCPCap}}}
	summary, err := packets.SummarizePCAPNG(context.Background(), bytes.NewReader(native), e, start, end)
	if err != nil || !summary.Valid() || summary.Packets != 50 || summary.UnclassifiedPackets == nil || *summary.UnclassifiedPackets != 0 {
		t.Fatal("raw metadata summary", summary.Packets, err)
	}
	output, err := json.Marshal(summary)
	if err != nil || bytes.Contains(output, []byte("SYNTHETIC-RAW-PAYLOAD")) {
		t.Fatal("raw payload escaped summary", err)
	}
}
