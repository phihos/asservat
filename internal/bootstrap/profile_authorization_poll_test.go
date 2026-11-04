package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
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

type pollProfileAuthorization struct{ reads atomic.Int32 }

func (*pollProfileAuthorization) DeliverProfile(context.Context, collector.Identity, collector.ProfileResult, io.Reader) error {
	return nil
}
func (p *pollProfileAuthorization) ReadNodeProfileAuthorization(_ context.Context, _ collector.Identity, w collector.Work) ([]byte, error) {
	p.reads.Add(1)
	return bytes.Repeat([]byte{'x'}, execution.GoProfileAuthorizationLimit), nil
}

// Actual mTLS Handler -> bounded response -> Client -> closed receive-only
// codec. The existing receipt path removes exactly the delivered prefix.
// Attestation and credential provider are explicit synthetic fixture inputs.
func TestProfileAuthorizationPollRetainsOriginalTailAndReceiptsOverTLS(t *testing.T) {
	s, att, endpoint, roots, _ := startNodeServer(t)
	const id = "11111111-1111-4111-8111-111111111111"
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
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cert, err := client.Enroll(ctx, contracts.NodeEnrollRequest{Token: "synthetic.node.token", CSR: creds.CSR(), BootID: testNodeBoot, Epoch: testNodeEpoch})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = creds.Install(cert.Certificate, time.Now()); err != nil {
		t.Fatal(err)
	}
	client.CloseIdle()
	budget, _ := collector.NewBudget(collector.Ceilings{FrozenBytes: 256 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, time.Now())
	facts := collector.Facts{KernelRelease: "6.8.0-1017-azure", Kernel: collector.KernelVersion{Major: 6, Minor: 8, Patch: 0}, BTF: collector.Supported, CgroupV2: collector.Supported, BPF: collector.Denied, TCX: collector.Denied, TC: collector.Denied,
		DebugFS: collector.Unsupported, TraceFS: collector.Unsupported, BPFFS: collector.Unsupported, HostProcesses: collector.Supported, Runtime: collector.RuntimeContainerd}
	report := collector.Report{Facts: facts, Sequence: 1, ObservedAt: time.Now(), Budget: budget.Usage(time.Now()), Mechanisms: []collector.Availability{{Mechanism: collector.MechanismProfile, Prerequisites: true, Adapter: collector.AdapterAvailable, ProfileTLS: true, ProfileAuthorization: true}}}
	if err = client.Status(ctx, testNodeEpoch, report); err != nil {
		t.Fatal(err)
	}
	_, _, one := serverCertificate(t)
	public := one
	for len(public)+len(one) <= execution.GoProfileTLSRootsLimit {
		public += one
	}
	canonical, digest, err := mtls.CanonicalProfileRoots(public)
	if err != nil {
		t.Fatal(err)
	}
	material := execution.GoProfileTLSMaterial{RootsPEM: canonical, RootsDigest: digest, ServerName: "asservat-connector-nodes"}
	provider := &pollProfileAuthorization{}
	s.Channel.SetProfileSink(provider)
	now := time.Now().UTC().Truncate(time.Microsecond)
	want := make([]collector.Work, collector.MaxWorkPerPoll)
	for i := range want {
		uid := fmt.Sprintf("%08d-1111-4111-8111-111111111111", i+1)
		p := collector.ProfileCapture{CaptureID: uid, CollectorEpoch: testNodeEpoch, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: "targetLoopback", Address: netip.MustParseAddr("::1"), Port: 6060, Host: strings.Repeat("<", 253), TLS: material, AuthorizationRequired: true, Request: execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: uid, AttemptID: uid, MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: strings.Repeat("<", 63), NamespaceUID: id, Name: strings.Repeat("<", 253), UID: id, NodeName: "worker-1"}, NodeUID: id, NodeBootID: testNodeBoot, SourceRef: strings.Repeat("<", 63), EndpointDigest: artifact.Digest{3}, Parameters: execution.GoProfileParameters{Type: "runtimeTrace", Mode: "interval", Duration: 15 * time.Second}, NativeLimit: artifact.MaxGoTraceBytes, NotBefore: now, Deadline: now.Add(25 * time.Second)}}
		want[i], err = s.Channel.EnqueueProfile(ctx, p, now.Add(4*time.Second))
		if err != nil {
			t.Fatal(err)
		}
	}
	first, err := client.Poll(ctx, testNodeEpoch, 0)
	if err != nil || len(first) == 0 || len(first) >= len(want) {
		t.Fatal("maximum private response did not deliver a prefix", err, len(first))
	}
	if int(provider.reads.Load()) != len(first) {
		t.Fatal("overflow candidate read private material", provider.reads.Load(), len(first))
	}
	// Returned work remains retained until its original receipt arrives.
	if v := s.Channel.Nodes(); len(v) != 1 || v[0].Queued != len(want) {
		t.Fatal("poll dequeued undisclosed tail", v[0].Queued)
	}
	for i, got := range first {
		if got.ID != want[i].ID || got.Sequence != want[i].Sequence || !got.NotAfter.Equal(want[i].NotAfter) || len(got.ProfileAuthorization) != execution.GoProfileAuthorizationLimit {
			t.Fatal("first prefix changed original work")
		}
		report.Receipts = append(report.Receipts, collector.Receipt{WorkID: got.ID, Sequence: got.Sequence, Outcome: collector.OutcomeRefused, Reason: collector.ReasonCaptureBusy})
		clear(got.ProfileAuthorization)
	}
	// The real protocol's existing minimum report spacing is unchanged.
	time.Sleep(collector.StatusMinimumSpacing)
	report.Sequence++
	report.ObservedAt = time.Now()
	if err = client.Status(ctx, testNodeEpoch, report); err != nil {
		t.Fatal(err)
	}
	last := first[len(first)-1].Sequence
	second, err := client.Poll(ctx, testNodeEpoch, last)
	if err != nil || len(second) != len(want)-len(first) {
		t.Fatal("ordinary next poll lost tail", err, len(second))
	}
	for i, got := range second {
		expected := want[len(first)+i]
		if got.ID != expected.ID || got.Sequence != expected.Sequence || !got.NotAfter.Equal(expected.NotAfter) || len(got.ProfileAuthorization) != execution.GoProfileAuthorizationLimit {
			t.Fatal("tail reordered or renewed")
		}
		clear(got.ProfileAuthorization)
	}
	if int(provider.reads.Load()) != len(want) {
		t.Fatal("private reader called outside delivered prefixes", provider.reads.Load())
	}
	t.Logf("real TLS poll first=%d tail=%d; original queue retained until exact receipts; private reads=%d", len(first), len(second), provider.reads.Load())
}
