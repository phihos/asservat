package capture

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"testing"
	"time"
)

func TestRecordingSelectionBindsPrincipalClientExpiryAndAllHandles(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	id := "10000000-0000-4000-8000-000000000001"
	set := RecordingSelectionSet{ID: id, RootID: id, Actor: identity.Principal{Issuer: "https://issuer.example", Subject: "service", ClientID: "mcp", Kind: identity.Workload}, Target: authorization.WorkloadTarget{ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload"}, CreatedAt: now, ExpiresAt: now.Add(time.Minute), References: []RecordingReference{{SourceID: id, Fence: id, PolicyUID: "policy", PodUID: "pod", ActionID: "packets", BindingDigest: artifact.Digest{1}, ExecutionDigest: artifact.Digest{2}}}}
	if !set.Valid() {
		t.Fatal("valid bounded service selection rejected")
	}
	selected, err := set.Select(set.Actor, []string{set.Handle(0)}, now)
	if err != nil || len(selected) != 1 || selected[0] != set.References[0] {
		t.Fatal("exact selection", err)
	}
	for _, mutate := range []func(*RecordingSelectionSet, *identity.Principal, *[]string, *time.Time){
		func(_ *RecordingSelectionSet, p *identity.Principal, _ *[]string, _ *time.Time) {
			p.ClientID = "browser"
		},
		func(_ *RecordingSelectionSet, p *identity.Principal, _ *[]string, _ *time.Time) { p.Subject = "other" },
		func(s *RecordingSelectionSet, _ *identity.Principal, _ *[]string, n *time.Time) { *n = s.ExpiresAt },
		func(s *RecordingSelectionSet, _ *identity.Principal, h *[]string, _ *time.Time) {
			*h = append(*h, s.Handle(0))
		},
		func(s *RecordingSelectionSet, _ *identity.Principal, h *[]string, _ *time.Time) {
			*h = append(*h, s.ID+":1")
		},
		func(_ *RecordingSelectionSet, _ *identity.Principal, h *[]string, _ *time.Time) {
			*h = []string{"20000000-0000-4000-8000-000000000001:0"}
		},
	} {
		s := set.Clone()
		p := s.Actor
		h := []string{s.Handle(0)}
		n := now
		mutate(&s, &p, &h, &n)
		if got, err := s.Select(p, h, n); err == nil || len(got) != 0 {
			t.Fatal("invalid selection partially returned", got, err)
		}
	}
	clone := set.Clone()
	clone.References[0].ActionID = "other"
	if set.References[0].ActionID != "packets" {
		t.Fatal("mutable shared selector slice")
	}
	for _, h := range []string{set.ID + ":00", set.ID + ":-1", set.ID + ":100", set.ID + ":0:1", "bad:0"} {
		if _, _, ok := ParseRecordingHandle(h); ok {
			t.Fatal("noncanonical handle", h)
		}
	}
}
