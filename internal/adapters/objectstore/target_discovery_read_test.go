package objectstore

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	processcodec "asservat.local/asservat/internal/adapters/processes"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func processEncryptedFixture(t *testing.T, dir string, sealers ...evidence.KeySealer) profileEncryptedFixture {
	t.Helper()
	unused, e, _ := writerFixture(t, http.NotFoundHandler())
	unused.Close()
	e.NativeType = artifact.ProcessesArtifact
	e.DataClass = "metadata"
	e.ActionID = "a0123456789abcdef01234567"
	e.ExecutionClass = artifact.ContextAPIExecution
	e.NodeUID = ""
	e.NodeBootID = ""
	e.Registration.NativeLimit = artifact.ProcessNativeLimit
	e.RequestedAgeSeconds = 3600
	e.MaximumAgeSeconds = 7200
	e.Registration.ExpiresAt = e.Registration.AnchorAt.Add(time.Hour)
	e.Registration.DeleteBy = e.Registration.ExpiresAt.Add(time.Minute)
	e.Processes = &artifact.ProcessCapture{ActionID: e.ActionID, Mode: artifact.ProcessAll, MaxNativeBytes: artifact.ProcessNativeLimit, TimeoutMillis: 5000, Composition: []byte(`{}`)}
	boot := "10000000-0000-4000-8000-000000000001"
	runtimeID := "containerd://" + strings.Repeat("a", 64)
	p := artifact.ProcessInventory{Format: artifact.ProcessFormat, PodUID: e.PodUID, NodeUID: "node", NodeBootID: boot, Mode: artifact.ProcessAll, StartedAt: e.TriggeredAt, CompletedAt: e.TriggeredAt.Add(time.Millisecond), Origins: []artifact.ProcessOrigin{{RuntimeID: runtimeID, MainPID: 123, Outcome: "observed"}}, Processes: []artifact.ProcessRecord{{Identity: artifact.ProcessIdentity{PodUID: e.PodUID, NodeBootID: boot, RuntimeID: runtimeID, HostPID: 123, StartTimeTicks: 10, CgroupPath: "/pod/" + strings.Repeat("a", 64), CgroupID: 10}, NamespacePID: 1, ObservedAt: e.TriggeredAt, Main: true, State: "S", Threads: 1, ExecutablePath: "/app/server"}}, Gaps: []string{"socketOwnersUnsupported"}}
	raw, _ := json.Marshal(p)
	copies := prepareEncryptedProjectionSource(t, dir, bytes.NewReader(raw), e, false, sealers...)
	f := profileEncryptedFixture{Source: evidence.NativeContextSource{Expectation: e, Copies: copies}, Scope: testProjectionScope()}
	s := &f.Scope
	s.CaseID = e.CaseID
	s.CaptureID = e.CaptureUID
	s.ArtifactID = e.Registration.Location.ArtifactID
	s.ClusterID = e.Registration.Location.ClusterID
	s.NamespaceUID = e.NamespaceUID
	s.WorkloadUID = e.WorkloadUID
	s.PodUID = e.PodUID
	s.Version = evidence.ContextCopiesDigest(copies)
	s.NativeType = artifact.ProcessesArtifact
	s.SourceFormat = artifact.ProcessFormat
	s.DisplayVersion = query.TargetDiscoveryDisplayVersion
	s.Selection = query.LineSelection{}
	s.SourceProjectionDigest = artifact.Digest{}
	s.Discovery = query.TargetDiscoveryWindow{Section: "processes", Limit: 20}
	if !s.Valid() || !f.Source.Valid(s.Version) {
		t.Fatal("invalid encrypted process source")
	}
	return f
}

func TestTargetDiscoveryEncryptedReaderRequiresConfiguredInterpreter(t *testing.T) {
	dir := t.TempDir()
	f := processEncryptedFixture(t, dir)
	verifier, keys, _, _ := profileEncryptedVerifier(t, dir, f, false)
	r, err := NewContextProjectionReader(verifier.store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if p, err := r.ReadProjectionNative(ctx, f.Source, f.Scope, keys, time.Now().Add(10*time.Second)); err == nil || p.TargetDiscovery != nil {
		t.Fatal("missing interpreter accepted")
	}
	r.ServeTargetDiscoveries(processcodec.Query)
	p, err := r.ReadProjectionNative(ctx, f.Source, f.Scope, keys, time.Now().Add(10*time.Second))
	if err != nil || p.TargetDiscovery == nil || p.TargetDiscovery.Total != 1 || p.TargetDiscovery.Processes[0].DisplayPID != 1 {
		t.Fatal("encrypted saved source not projected", err)
	}
}
