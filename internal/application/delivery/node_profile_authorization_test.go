package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/netip"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

type privateProfileSink struct {
	read func(context.Context, collector.Identity, collector.Work) ([]byte, error)
}

func (s privateProfileSink) ReadNodeProfileAuthorization(ctx context.Context, id collector.Identity, w collector.Work) ([]byte, error) {
	return s.read(ctx, id, w)
}
func (privateProfileSink) DeliverProfile(context.Context, collector.Identity, collector.ProfileResult, io.Reader) error {
	return nil
}

func TestProfileAuthorizationCurrentProcessAndRetainedWorkAfterRead(t *testing.T) {
	for _, mode := range []string{"current", "changed-epoch", "cancelled", "expired", "receipted"} {
		t.Run(mode, func(t *testing.T) {
			ch, _, clock, _ := newChannel(t)
			clock.t = time.Now().UTC().Truncate(time.Microsecond)
			peer, _ := enroll(t, ch, epochA)
			const id = "11111111-1111-4111-8111-111111111111"
			entry := ch.nodes[peer.NodeUID]
			delete(ch.nodes, peer.NodeUID)
			entry.id.NodeUID = id
			ch.nodes[id] = entry
			peer.NodeUID = id
			now := clock.now()
			entry.report = &collector.Report{Sequence: 1, Mechanisms: []collector.Availability{{Mechanism: collector.MechanismProfile, Prerequisites: true, Adapter: collector.AdapterAvailable, ProfileTLS: true, ProfileAuthorization: true}}}
			entry.reportedAt = now
			material := execution.GoProfileTLSMaterial{RootsPEM: "public", RootsDigest: artifact.Digest(sha256.Sum256([]byte("public"))), ServerName: "profile.internal"}
			p := collector.ProfileCapture{CaptureID: id, CollectorEpoch: epochA, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: "targetLoopback", Address: netip.MustParseAddr("::1"), Port: 6060, Host: "profile.internal", TLS: material, AuthorizationRequired: true, Request: execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: id, AttemptID: id, MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "app", UID: id, NodeName: entry.id.NodeName}, NodeUID: id, NodeBootID: boot, SourceRef: "pprof", EndpointDigest: artifact.Digest{3}, Parameters: execution.GoProfileParameters{Type: "heap", Mode: "snapshot"}, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(10 * time.Second)}}
			work, err := ch.EnqueueProfile(t.Context(), p, now.Add(3*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reads := 0
			var value []byte
			ch.SetProfileSink(privateProfileSink{read: func(call context.Context, got collector.Identity, w collector.Work) ([]byte, error) {
				reads++
				if got != entry.id || w.ID != work.ID {
					t.Error("provider got different work/process")
				}
				if until, ok := call.Deadline(); !ok || until.After(work.NotAfter) {
					t.Error("provider escaped original dispatch deadline")
				}
				switch mode {
				case "changed-epoch":
					ch.mu.Lock()
					entry.id.Epoch = epochB
					ch.mu.Unlock()
				case "cancelled":
					cancel()
				case "expired":
					clock.add(3 * time.Second)
				case "receipted":
					clock.add(time.Second)
					r := *entry.report
					r.Sequence++
					r.ObservedAt = clock.now()
					r.Receipts = []collector.Receipt{{WorkID: work.ID, Sequence: work.Sequence, Outcome: collector.OutcomeAccepted}}
					if err := ch.Report(peer, epochA, r); err != nil {
						t.Error(err)
					}
				}
				value = []byte("Bearer synthetic-private-value")
				return value, nil
			}})
			wrong := work
			wrong.Sequence++
			if _, err := ch.ProfileAuthorization(ctx, peer, epochA, wrong); err == nil || reads != 0 {
				t.Fatal("wrong sequence reached provider")
			}
			got, err := ch.ProfileAuthorization(ctx, peer, epochA, work)
			if mode == "current" {
				if err != nil || len(got) == 0 || reads != 1 {
					t.Fatal("current work refused", err, reads)
				}
			} else if err == nil || len(got) != 0 || !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatal("changed process/work released private value", mode, err)
			}
		})
	}
}
