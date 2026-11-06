package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/node"
)

// This composition uses real TLS enrollment, Poll wire/domain conversion, the
// node dispatcher, native upload, regional holder and encrypted writer. All
// authorization/node facts, process metadata and object-store replies are
// synthetic. It never invokes procfs collection, setns, BPF or an external lab,
// and Stored is not verified catalog publication or installed qualification.
func TestProcessTransportComposed(t *testing.T) {
	for _, mode := range []string{"stored", "source-failed"} {
		t.Run(mode, func(t *testing.T) {
			holder, _, expected, pin, _ := processHolderFixture(t)
			server, attester, endpoint, roots, _ := startNodeServer(t)
			attester.mu.Lock()
			attester.pod = "11111111-1111-4111-8111-111111111111"
			attester.nodeUID = "22222222-2222-4222-8222-222222222222"
			attester.mu.Unlock()
			credentials, err := mtls.NewNodeCredentials()
			if err != nil {
				t.Fatal("credentials", err)
			}
			client, err := node.NewClient(endpoint, "asservat-connector-nodes", roots, credentials.GetClientCertificate)
			if err != nil {
				t.Fatal("client", err)
			}
			defer client.CloseIdle()
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			budget, err := collector.NewBudget(collector.Ceilings{FrozenBytes: 32 << 20, UploadBytesPerSecond: 1 << 20, UploadBurstBytes: 1 << 20}, time.Now())
			if err != nil {
				t.Fatal("budget", err)
			}
			process := &nodeProcess{client: client, creds: credentials, podUID: attester.pod, bootID: testNodeBoot, epoch: testNodeEpoch, now: time.Now, sleep: nodeSleep, log: io.Discard, budget: budget, token: func(context.Context) ([]byte, error) { return []byte("synthetic.node.token"), nil }}
			if _, err := process.enroll(ctx); err != nil {
				t.Fatal("enrollment", err)
			}
			identity := process.packetIdentity()
			if identity.NodeUID != attester.nodeUID || identity.PodUID != attester.pod || identity.NodeName != "worker-1" {
				t.Fatal("synthetic enrolled identity changed")
			}
			facts := collector.Facts{KernelRelease: "6.8.0", Kernel: collector.KernelVersion{Major: 6, Minor: 8}, BTF: collector.Supported, CgroupV2: collector.Supported, BPF: collector.Denied, TCX: collector.Denied, TC: collector.Denied, DebugFS: collector.Unsupported, TraceFS: collector.Unsupported, BPFFS: collector.Unsupported, HostProcesses: collector.Supported, Runtime: collector.RuntimeContainerd}
			report := collector.Report{Sequence: 1, ObservedAt: time.Now(), Facts: facts, Mechanisms: []collector.Availability{{Mechanism: collector.MechanismProcesses, Prerequisites: true, Adapter: collector.AdapterAvailable, Hook: collector.HookNone}}, Budget: budget.Usage(time.Now())}
			if err := client.Status(ctx, process.epoch, report); err != nil {
				t.Fatal("process availability", err)
			}
			holder.nodes = server.Channel
			holder.now = time.Now
			holder.pods = profilePodNodeFunc(func(context.Context, artifact.PinnedPod) (string, error) { return identity.NodeName, nil })
			server.Channel.SetProcessSink(holder)
			var puts, acquired, uploaded atomic.Int32
			prepared := preparedSnapshot(t, expected, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { snapshotPUT(t, w, r, puts.Add(1)) }))
			started := time.Now().UTC()
			if _, err := holder.PrepareProcesses(prepared, expected).StartProcesses(ctx, pin, started, started.Add(4*time.Second)); err != nil {
				t.Fatal("regional enqueue", err)
			}
			holder.mu.Lock()
			originalWork := holder.processes[expected.CaptureUID].workID
			holder.mu.Unlock()
			var polled collector.ProcessCapture
			var diagnostics bytes.Buffer
			upload := loggedProcessUploader(client.UploadProcessesStream, &diagnostics)
			uploadedResult := make(chan error, 1)
			process.profiles = &nodeProfiles{identity: process.packetIdentity, now: time.Now, budget: func() *collector.Budget { return budget }, budgetMu: &process.mu,
				processes: func(_ context.Context, capture collector.ProcessCapture) (artifact.ProcessInventory, error) {
					acquired.Add(1)
					polled = capture
					if mode == "source-failed" {
						return artifact.ProcessInventory{}, errors.New("synthetic source failure")
					}
					at := time.Now().UTC()
					runtimeID := "containerd://" + strings.Repeat("1", 64)
					return artifact.ProcessInventory{Format: artifact.ProcessFormat, PodUID: capture.Request.Pin.UID, NodeUID: identity.NodeUID, NodeBootID: identity.BootID, Mode: capture.Request.Mode, StartedAt: at, CompletedAt: at,
						Origins: []artifact.ProcessOrigin{{RuntimeID: runtimeID, MainPID: 100, Outcome: "observed"}}, Processes: []artifact.ProcessRecord{{Identity: artifact.ProcessIdentity{PodUID: capture.Request.Pin.UID, NodeBootID: identity.BootID, RuntimeID: runtimeID, HostPID: 100, StartTimeTicks: 10, CgroupPath: "/synthetic/pod/container", CgroupID: 10}, NamespacePID: 1, ObservedAt: at, Main: true, State: "S", Threads: 1, ExecutablePath: "/synthetic/process"}}, Gaps: []string{"socketOwnersUnsupported"}}, nil
				}, uploadProcesses: func(call context.Context, epoch string, result collector.ProcessResult, body io.Reader) error {
					uploaded.Add(1)
					err := upload(call, epoch, result, body)
					uploadedResult <- err
					return err
				}}
			pollCtx, stopPoll := context.WithCancel(ctx)
			defer stopPoll()
			pollDone := make(chan error, 1)
			go func() { pollDone <- process.pollLoop(pollCtx, make(chan struct{}, 1)) }()
			pollJoined := false
			defer func() {
				stopPoll()
				if !pollJoined {
					<-pollDone
				}
				process.profiles.wg.Wait()
			}()
			select {
			case err := <-uploadedResult:
				if err != nil {
					t.Fatal("node TLS upload", err)
				}
			case <-ctx.Done():
				t.Fatal("dispatch/upload did not finish within fixture bound")
			}
			stopPoll()
			pollError := <-pollDone
			pollJoined = true
			if !errors.Is(pollError, context.Canceled) {
				t.Fatal("poll did not join", pollError)
			}
			process.profiles.wg.Wait()
			wantAcquisition := "native-ready"
			if mode == "source-failed" {
				wantAcquisition = "source-failed"
			}
			if diagnostics.String() != "node processes: acquisition="+wantAcquisition+" upload=ok\n" {
				t.Fatal("missing fixed process task outcome", diagnostics.String())
			}
			if polled.CaptureID != expected.CaptureUID || polled.ExpectationDigest != evidence.ContextExpectationDigest(expected) || polled.CollectorEpoch != identity.Epoch || polled.Request.Pin.NodeName != identity.NodeName || polled.Request.NodeUID != identity.NodeUID || polled.Request.NodeBootID != identity.BootID || polled.Request.Deadline != started.Add(5*time.Second) {
				t.Fatal("original work changed through Poll/wire/domain/dispatch")
			}
			outcome, err := holder.Collect(fleet.APIContextWork{CaptureID: expected.CaptureUID, AttemptID: expected.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(expected)})
			want, wantPuts := evidence.RecordingStored, int32(4)
			if mode == "source-failed" {
				want, wantPuts = evidence.RecordingFailed, 0
			}
			if err != nil || outcome.State != want || !outcome.Valid(expected.Registration) || acquired.Load() != 1 || uploaded.Load() != 1 || puts.Load() != wantPuts {
				t.Fatal("regional Collect final outcome", outcome.State, err, acquired.Load(), uploaded.Load(), puts.Load())
			}
			process.mu.Lock()
			receipts := append([]collector.Receipt(nil), process.receipts...)
			usage, running := budget.Usage(time.Now()), len(process.profiles.running)
			process.mu.Unlock()
			if len(receipts) != 1 || receipts[0].WorkID != originalWork || receipts[0].Outcome != collector.OutcomeAccepted || usage.FrozenReserved != 0 || running != 0 {
				t.Fatal("original dispatch receipt or joined budget", receipts, usage, running)
			}
			if replay := process.profiles.startProcesses(ctx, process.epoch, collector.Work{ID: originalWork, Sequence: receipts[0].Sequence, Kind: collector.WorkProcesses, NotAfter: started.Add(4 * time.Second), Processes: &polled}); replay.Outcome == collector.OutcomeAccepted || acquired.Load() != 1 || uploaded.Load() != 1 {
				t.Fatal("original acquisition replayed")
			}
			t.Log("real local TLS Poll/dispatcher/upload/holder/Collect joined; synthetic identity, source and store replies; no publication or installed claim")
		})
	}
}

func TestProcessUploadDiagnosticIsClosedAndPreservesOriginalAttempt(t *testing.T) {
	const hidden = "opaque-error-ID-body-must-not-be-logged"
	for _, tc := range []struct {
		name, category string
		err            error
		cancel         bool
	}{
		{name: "ok", category: "ok"},
		{name: "refused", category: "refused", err: fmt.Errorf("%s: %w", hidden, node.ErrRefused)},
		{name: "unauthenticated", category: "unauthenticated", err: node.ErrUnauthenticated},
		{name: "unavailable", category: "unavailable", err: node.ErrUnavailable},
		{name: "opaque", category: "unavailable", err: errors.New(hidden)},
		{name: "canceled-error", category: "canceled", err: context.Canceled},
		{name: "deadline-error", category: "canceled", err: context.DeadlineExceeded},
		{name: "canceled-context", category: "canceled", err: node.ErrUnavailable, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			result := collector.ProcessResult{WorkID: hidden, Failure: collector.ReasonCaptureFailed}
			body := strings.NewReader(hidden)
			var log bytes.Buffer
			calls := 0
			upload := loggedProcessUploader(func(gotCtx context.Context, epoch string, got collector.ProcessResult, gotBody io.Reader) error {
				calls++
				if gotCtx != ctx || epoch != hidden || got != result || gotBody != body {
					t.Error("diagnostics changed original upload inputs")
				}
				return tc.err
			}, &log)
			if got := upload(ctx, hidden, result, body); got != tc.err || calls != 1 {
				t.Fatal("upload result changed or retried", calls)
			}
			if log.String() != "node processes: acquisition=source-failed upload="+tc.category+"\n" || strings.Contains(log.String(), hidden) {
				t.Fatal("diagnostics leaked content or invented a stage", log.String())
			}
		})
	}
}
