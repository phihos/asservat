package bootstrap

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/transport/node"
)

type profileRefusalUpload struct {
	result collector.ProfileResult
	body   []byte
}
type refusingProfileAuthorization struct {
	failed   string
	reads    atomic.Int32
	uploads  chan profileRefusalUpload
	during   func(context.Context)
	finished chan struct{}
}

func (p *refusingProfileAuthorization) DeliverProfile(_ context.Context, _ collector.Identity, result collector.ProfileResult, body io.Reader) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if p.uploads != nil {
		p.uploads <- profileRefusalUpload{result: result, body: data}
	}
	return nil
}
func (p *refusingProfileAuthorization) ReadNodeProfileAuthorization(ctx context.Context, _ collector.Identity, w collector.Work) ([]byte, error) {
	p.reads.Add(1)
	if w.Profile.CaptureID == p.failed {
		if p.finished != nil {
			defer close(p.finished)
		}
		if p.during != nil {
			p.during(ctx)
		}
		return nil, errors.New("synthetic selected material unavailable")
	}
	return []byte("Bearer synthetic-private-value"), nil
}

func TestProfileAuthorizationRefusalDoesNotBlockMixedPollOverTLS(t *testing.T) {
	qualifyMixedProfileAuthorizationPoll(t, "material")
}

func TestProfileAuthorizationPollAbortsForWholeRequestOrReplacedPeer(t *testing.T) {
	for _, mode := range []string{"cancelled", "peer-replaced"} {
		t.Run(mode, func(t *testing.T) { qualifyMixedProfileAuthorizationPoll(t, mode) })
	}
}

func qualifyMixedProfileAuthorizationPoll(t *testing.T, mode string) {
	t.Helper()
	s, att, endpoint, roots, _ := startNodeServer(t)
	const id = "11111111-1111-4111-8111-111111111111"
	const failed = "22222222-2222-4222-8222-222222222222"
	const healthy = "33333333-3333-4333-8333-333333333333"
	att.nodeUID = id
	creds, err := mtls.NewNodeCredentials()
	if err != nil {
		t.Fatal(err)
	}
	client, err := node.NewClient(endpoint, "asservat-connector-nodes", roots, creds.GetClientCertificate)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdle()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	cert, err := client.Enroll(ctx, contracts.NodeEnrollRequest{Token: "synthetic.node.token", CSR: creds.CSR(), BootID: testNodeBoot, Epoch: testNodeEpoch})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = creds.Install(cert.Certificate, time.Now()); err != nil {
		t.Fatal(err)
	}
	client.CloseIdle()
	facts := collector.Facts{KernelRelease: "6.8.0-1017-azure", Kernel: collector.KernelVersion{Major: 6, Minor: 8}, BTF: collector.Supported, CgroupV2: collector.Supported, BPF: collector.Denied, TCX: collector.Denied, TC: collector.Denied, DebugFS: collector.Unsupported, TraceFS: collector.Unsupported, BPFFS: collector.Unsupported, HostProcesses: collector.Supported, Runtime: collector.RuntimeContainerd}
	budget, _ := collector.NewBudget(collector.Ceilings{FrozenBytes: 32 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, time.Now())
	report := collector.Report{Facts: facts, Sequence: 1, ObservedAt: time.Now(), Budget: budget.Usage(time.Now()), Mechanisms: []collector.Availability{{Mechanism: collector.MechanismProfile, Prerequisites: true, Adapter: collector.AdapterAvailable, ProfileTLS: true, ProfileAuthorization: true}}}
	if err = client.Status(ctx, testNodeEpoch, report); err != nil {
		t.Fatal(err)
	}
	_, _, public := serverCertificate(t)
	canonical, digest, err := mtls.CanonicalProfileRoots(public)
	if err != nil {
		t.Fatal(err)
	}
	material := execution.GoProfileTLSMaterial{RootsPEM: canonical, RootsDigest: digest, ServerName: "asservat-connector-nodes"}
	provider := &refusingProfileAuthorization{failed: failed, uploads: make(chan profileRefusalUpload, 8)}
	s.Channel.SetProfileSink(provider)
	now := time.Now().UTC().Truncate(time.Microsecond)
	profile := func(capture string, auth bool) collector.ProfileCapture {
		return collector.ProfileCapture{CaptureID: capture, CollectorEpoch: testNodeEpoch, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: "targetLoopback", Address: netip.MustParseAddr("::1"), Port: 6060, Host: "profile.internal", TLS: material, AuthorizationRequired: auth, Request: execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: capture, AttemptID: capture, MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "app", UID: capture, NodeName: "worker-1"}, NodeUID: id, NodeBootID: testNodeBoot, SourceRef: "pprof", EndpointDigest: artifact.Digest{3}, Parameters: execution.GoProfileParameters{Type: "heap", Mode: "snapshot"}, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(10 * time.Second)}}
	}
	first, err := s.Channel.EnqueueProfile(ctx, profile(id, false), now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	bad, err := s.Channel.EnqueueProfile(ctx, profile(failed, true), now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	stop, err := s.Channel.EnqueueProfileCancel(ctx, id, id, first.ID, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	last, err := s.Channel.EnqueueProfile(ctx, profile(healthy, true), now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	want := []collector.Work{first, bad, stop, last}
	if mode != "material" {
		provider.finished = make(chan struct{})
		provider.during = func(call context.Context) {
			if mode == "cancelled" {
				cancel()
				<-call.Done()
				return
			}
			replacement, err := mtls.NewNodeCredentials()
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := client.Enroll(call, contracts.NodeEnrollRequest{Token: "synthetic.node.token", CSR: replacement.CSR(), BootID: testNodeBoot, Epoch: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}); err != nil {
				t.Error("replace current peer", err)
			}
		}
	}
	got, err := client.Poll(ctx, testNodeEpoch, 0)
	if mode != "material" {
		select {
		case <-provider.finished:
		case <-time.After(time.Second):
			t.Fatal("cancelled/replaced read did not join")
		}
		if err == nil || len(got) != 0 || provider.reads.Load() != 1 {
			t.Fatal("whole request failure became per-item delivery", mode, err)
		}
		if mode == "peer-replaced" && !errors.Is(err, node.ErrUnauthenticated) {
			t.Fatal("final current-peer error was masked", err)
		}
		if mode == "cancelled" && ctx.Err() == nil {
			t.Fatal("caller cancellation was lost")
		}
		return
	}
	if err != nil || len(got) != len(want) {
		t.Fatalf("one material refusal blocked unrelated work/cancel: delivered=%d wanted=%d err=%v", len(got), len(want), err)
	}
	for i, w := range got {
		if w.ID != want[i].ID || w.Sequence != want[i].Sequence || !w.NotAfter.Equal(want[i].NotAfter) {
			t.Fatal("mixed poll changed original work", i)
		}
	}
	if !got[1].ProfileAuthorizationUnavailable || len(got[1].ProfileAuthorization) != 0 || got[3].ProfileAuthorizationUnavailable || len(got[3].ProfileAuthorization) == 0 || provider.reads.Load() != 2 {
		t.Fatal("per-item refusal escaped or blocked healthy material")
	}
	var mu sync.Mutex
	var acquired atomic.Int32
	entered := make(chan struct{})
	profiles := &nodeProfiles{identity: func() collector.Identity { return s.Channel.Nodes()[0].Identity }, now: time.Now, budgetMu: &mu, budget: func() *collector.Budget { return budget }, upload: client.UploadProfileStream,
		acquire: func(call context.Context, p collector.ProfileCapture, auth []byte, w io.Writer) (execution.GoProfileOutcome, error) {
			acquired.Add(1)
			if p.CaptureID == failed {
				t.Error("unavailable item acquired or opened a socket")
			}
			if p.CaptureID == id {
				close(entered)
				<-call.Done()
				return execution.GoProfileOutcome{Format: artifact.PprofFormat, CompletedAt: time.Now()}, call.Err()
			}
			if string(auth) != "Bearer synthetic-private-value" {
				t.Error("healthy item lost selected value")
			}
			start := time.Now()
			_, err := w.Write([]byte("native"))
			return execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: start, CompletedAt: time.Now(), MayHaveStarted: true, ResponseComplete: true, NativeBytes: 6}, err
		}}
	for i, w := range got {
		var receipt collector.Receipt
		if w.Kind == collector.WorkCancelProfileCapture {
			receipt = profiles.stop(w.Work)
		} else {
			receipt = profiles.start(ctx, testNodeEpoch, w.Work, w.ProfileAuthorization, w.ProfileAuthorizationUnavailable)
		}
		if receipt.WorkID != want[i].ID || receipt.Sequence != want[i].Sequence {
			t.Fatal("receipt changed original item")
		}
		if i == 1 {
			if receipt.Outcome != collector.OutcomeRefused || receipt.Reason != collector.ReasonProfileUnavailable {
				t.Fatal("own refusal not terminal", receipt)
			}
			mu.Lock()
			reserved := budget.Usage(time.Now()).FrozenReserved
			mu.Unlock()
			if reserved != 16<<20 {
				t.Fatal("unavailable item reserved frozen bytes", reserved)
			}
		} else if receipt.Outcome != collector.OutcomeAccepted {
			t.Fatal("unrelated acquisition/cancel blocked", i, receipt)
		}
		report.Receipts = append(report.Receipts, receipt)
		if i == 0 {
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("healthy acquisition did not start")
			}
		}
		clear(w.ProfileAuthorization)
	}
	profiles.wg.Wait()
	seen := map[string]profileRefusalUpload{}
	for range 3 {
		select {
		case upload := <-provider.uploads:
			seen[upload.result.CaptureID] = upload
		case <-ctx.Done():
			t.Fatal("original outcomes did not join")
		}
	}
	refusal, ok := seen[failed]
	if !ok || refusal.result.Failure != collector.ReasonProfileUnavailable || refusal.result.Outcome.NativeBytes != 0 || refusal.result.Outcome.MayHaveStarted || len(refusal.body) != 0 || !refusal.result.Valid() {
		t.Fatal("unavailable item lost its zero-byte outcome")
	}
	if acquired.Load() != 2 || string(seen[healthy].body) != "native" {
		t.Fatal("unrelated healthy work did not complete")
	}
	if replay := profiles.start(ctx, testNodeEpoch, got[1].Work, nil, true); replay.Outcome != collector.OutcomeRefused {
		t.Fatal("unavailable item replayed")
	}
	profiles.wg.Wait()
	if len(provider.uploads) != 0 || acquired.Load() != 2 {
		t.Fatal("unavailable replay repeated upload/acquisition")
	}
	time.Sleep(collector.StatusMinimumSpacing)
	report.Sequence++
	report.ObservedAt = time.Now()
	report.Budget = budget.Usage(time.Now())
	if err := client.Status(ctx, testNodeEpoch, report); err != nil {
		t.Fatal("original mixed receipts failed", err)
	}
	if queued := s.Channel.Nodes()[0].Queued; queued != 0 {
		t.Fatal("mixed receipts lost original cursor", queued)
	}
	t.Log("real mTLS mixed4 delivered in order; unavailable own item uploaded zero-byte ProfileUnavailable once; healthy acquisition+Stop+receipts continued without unavailable native reservation")
}
