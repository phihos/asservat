package fleet

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func routingPeerValues(now time.Time) ClusterObservationRoutingPeers {
	v := ownerObservationFixture(now)
	v.Workload.Pin.RootID = "30000000-0000-0000-0000-000000000001"
	v.Workload.Pin.Pool.NativeCandidateLimit = OwnerRegistrationsPerPool
	v.Owner.Pool = v.Workload.Pin.Pool
	v.Workload.Pin.Pool = v.Owner.Pool
	p := ClusterObservationRoutingPeers{Query: ClusterObservationLocatorQuery{RequestID: observationTestID, Challenge: observationOtherID, RootID: v.Workload.Pin.RootID, ClusterID: observationOtherID, RequestedAt: now, NotAfter: now.Add(4 * time.Second)}, Pin: v.Workload.Pin, Holder: v.Owner, HolderWorkload: v.Workload, Interval: ClusterObservationInterval{ObservedAt: now.Add(3 * time.Millisecond), FreshUntil: now.Add(2 * time.Second)}}
	p.Sender, p.SenderWorkload = p.Holder, p.HolderWorkload
	p.Sender.Certificate.Usage = "client"
	p.Sender.Certificate.Binding.PodUID = observationOtherID
	p.Sender.Pod = "hub-2"
	p.SenderWorkload.Binding = p.Sender.Certificate.Binding
	p.SenderWorkload.Pod = p.Sender.Pod
	return p
}

func TestClusterObservationRoutingPeersOriginalProofs(t *testing.T) {
	start := time.Now()
	now := start.Add(10 * time.Millisecond)
	p := routingPeerValues(start)
	if !p.Valid(now) || !p.SamePeers(p) {
		t.Fatal("exact independent same-pool proofs rejected")
	}
	for name, mutate := range map[string]func(*ClusterObservationRoutingPeers){
		"unselected-limit":   func(v *ClusterObservationRoutingPeers) { v.Pin.Pool.NativeCandidateLimit = 0 },
		"permission-root":    func(v *ClusterObservationRoutingPeers) { v.Query.RootID = v.Pin.Pool.InstallationID },
		"sender-purpose":     func(v *ClusterObservationRoutingPeers) { v.Sender.Certificate.Usage = "server" },
		"holder-purpose":     func(v *ClusterObservationRoutingPeers) { v.Holder.Certificate.Usage = "client" },
		"source-revision":    func(v *ClusterObservationRoutingPeers) { v.Sender.ConfigurationRevision.Generation++ },
		"source-uid":         func(v *ClusterObservationRoutingPeers) { v.Sender.ConfigurationRevision.UID = observationOtherID },
		"sender-pool":        func(v *ClusterObservationRoutingPeers) { v.Sender.Pool.ServiceUID = observationOtherID },
		"workload-pool":      func(v *ClusterObservationRoutingPeers) { v.SenderWorkload.Pin.Pool.ServiceUID = observationOtherID },
		"workload-pod":       func(v *ClusterObservationRoutingPeers) { v.SenderWorkload.Binding.PodUID = observationTestID },
		"workload-name":      func(v *ClusterObservationRoutingPeers) { v.SenderWorkload.Pod = "replacement" },
		"replicaset":         func(v *ClusterObservationRoutingPeers) { v.HolderWorkload.ReplicaSetUID = observationOtherID },
		"template":           func(v *ClusterObservationRoutingPeers) { v.SenderWorkload.Pin.TemplateDigest[0]++ },
		"guard":              func(v *ClusterObservationRoutingPeers) { v.Holder.ProtectionDigest[0]++ },
		"earlier-than-proof": func(v *ClusterObservationRoutingPeers) { v.Interval.ObservedAt = v.Query.RequestedAt },
		"proof-expired":      func(v *ClusterObservationRoutingPeers) { v.Sender.ValidUntil = now },
		"workload-expired":   func(v *ClusterObservationRoutingPeers) { v.HolderWorkload.FreshUntil = now },
		"extended-output":    func(v *ClusterObservationRoutingPeers) { v.Interval.FreshUntil = v.Query.NotAfter },
	} {
		t.Run(name, func(t *testing.T) {
			v := p
			mutate(&v)
			if v.Valid(now) {
				t.Fatal("contradictory or extended peer proof accepted")
			}
		})
	}
	last := p
	last.Sender.VerifiedAt = now
	last.Holder.VerifiedAt = now
	last.SenderWorkload.ObservedAt = now
	last.HolderWorkload.ObservedAt = now
	last.Interval.ObservedAt = now
	if !last.Valid(now) || !p.SamePeers(last) {
		t.Fatal("independent unchanged proof rejected")
	}
	if p.Valid(p.Interval.FreshUntil) {
		t.Fatal("later proof revived original interval")
	}
	last.Sender.Certificate.Digest[0]++
	if p.SamePeers(last) {
		t.Fatal("same-process leaf replacement accepted")
	}
}

func TestOwnerPoolNativeCandidateLimitIsExplicitAndLegacyOmitted(t *testing.T) {
	p := ownerObservationFixture(time.Now()).Owner.Pool
	if !p.Valid() {
		t.Fatal("legacy pool invalid")
	}
	b, err := json.Marshal(p)
	if err != nil || strings.Contains(string(b), "NativeCandidateLimit") {
		t.Fatal("legacy omitted bytes changed")
	}
	for _, n := range []int{-1, 1, OwnerRegistrationsPerPool, OwnerRegistrationsPerPool + 1} {
		p.NativeCandidateLimit = n
		if p.Valid() != (n > 0 && n <= OwnerRegistrationsPerPool) {
			t.Fatal("candidate population bound", n)
		}
	}
	p.NativeCandidateLimit = 1
	p.NativeBootstrap = ""
	if p.Valid() {
		t.Fatal("candidate population selected without bootstrap profile")
	}
	p.NativeBootstrap = OwnerBootstrapProfile
	p.NativePort = 0
	if p.Valid() {
		t.Fatal("candidate population selected without native port")
	}
}

// ADR-197: the v2 operation port is optional, omitted when unset and distinct
// from both other ports; unset, the v2 server keeps the native port.
func TestOwnerPoolOperationPortIsOptionalAndDistinct(t *testing.T) {
	p := ownerObservationFixture(time.Now()).Owner.Pool
	p.NativeCandidateLimit = 1
	b, err := json.Marshal(p)
	if err != nil || strings.Contains(string(b), "OperationPort") || p.OperationListenPort() != p.NativePort {
		t.Fatal("unset operation port changed bytes or listener")
	}
	for port, valid := range map[int]bool{9448: true, 1023: false, 65536: false, p.Port: false, p.NativePort: false} {
		p.OperationPort = port
		if p.Valid() != valid {
			t.Fatal("operation port bound", port)
		}
	}
	p.OperationPort = 9448
	if p.OperationListenPort() != 9448 {
		t.Fatal("operation listener not selected")
	}
	p.NativeCandidateLimit = 0
	if p.Valid() {
		t.Fatal("operation port without candidate population")
	}
}
