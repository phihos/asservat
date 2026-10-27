package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	app "asservat.local/asservat/internal/application/fleet"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
)

type namespaceJournalFixture struct{ snap port.NamespaceJournalSnapshot }

func (j *namespaceJournalFixture) Snapshot(context.Context, cfg.NamespaceKeys) (port.NamespaceJournalSnapshot, error) {
	return j.snap, nil
}

// ADR-247: the journal is paged at one (journal, sequence) state; a cursor of
// another state is a change, and without a journal the purpose is unavailable.
func TestClusterObservationMetadataPagesPermissionNamespaceJournal(t *testing.T) {
	f := observationMetadataTestFixture(t, "valid")
	const journal = "61000000-0000-4000-8000-0000000000aa"
	j := &namespaceJournalFixture{snap: port.NamespaceJournalSnapshot{Journal: journal, Sequence: 3, ObservedAt: f.start}}
	for i := range fleet.ClusterObservationMaximumItems + 6 {
		j.snap.Namespaces = append(j.snap.Namespaces, cfg.ObservedNamespace{Name: fmt.Sprintf("ns-%03d", i), UID: fmt.Sprintf("uid-%03d", i), ResourceVersion: journal + ":0", Labels: map[string]string{"team": strings.Repeat("a", 64)}})
	}
	r := f.request(fleet.ObservePermissionNamespaces)
	r.Keys = []string{"team"}
	observe := func(reader *ClusterObservationMetadata, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		return reader.ObserveCluster(ctx, r)
	}
	if _, err := observe(f.reader, r); !errors.Is(err, cfg.ErrUnavailable) {
		t.Fatal("no journal was not unavailable", err)
	}
	reader := f.reader.WithPermissionNamespaces(j)
	first, err := observe(reader, r)
	digest, _ := app.ClusterObservationRequestDigest(r)
	if err != nil || !first.Matches(r, digest, f.now()) || len(first.PermissionNamespaces.Items) != fleet.ClusterObservationMaximumItems || first.PermissionNamespaces.Continue != journal+"/3/64" {
		t.Fatalf("first page: %v %+v", err, first.PermissionNamespaces)
	}
	r.Continue = first.PermissionNamespaces.Continue
	second, err := observe(reader, r)
	if err != nil || len(second.PermissionNamespaces.Items) != 6 || second.PermissionNamespaces.Continue != "" {
		t.Fatalf("second page: %v", err)
	}
	j.snap.Sequence = 4
	if _, err = observe(reader, r); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("cursor of another journal state accepted", err)
	}
	if f.calls.Load() != 0 {
		t.Fatal("journal page made API calls", f.calls.Load())
	}
}

type workloadJournalFixture struct{ snap port.WorkloadJournalSnapshot }

func (j *workloadJournalFixture) Snapshot(context.Context, cfg.WorkloadSelection) (port.WorkloadJournalSnapshot, error) {
	return j.snap, nil
}

// ADR-247: workload journal pages carry their selection's journal versions;
// without a workload guard its proof purpose is unavailable.
func TestClusterObservationMetadataPagesPermissionWorkloadJournal(t *testing.T) {
	f := observationMetadataTestFixture(t, "valid")
	const journal = "61000000-0000-4000-8000-0000000000bb"
	digest := strings.Repeat("a", 64)
	j := &workloadJournalFixture{snap: port.WorkloadJournalSnapshot{Journal: journal, Sequence: 1, ObservedAt: f.start, Workloads: []cfg.ObservedWorkload{{Kind: "Deployment", Namespace: cfg.NamespaceRef{Name: "payments", UID: "payments-uid"},
		ObservedNamespace: cfg.ObservedNamespace{Name: "api", UID: "workload-uid", ResourceVersion: journal + ":1", Labels: map[string]string{"team": digest}}}}}}
	r := f.request(fleet.ObservePermissionWorkloads)
	r.Selector, r.Keys = map[string]string{"team": "payments"}, []string{"team"}
	reader := f.reader.WithPermissionWorkloads(j, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := reader.ObserveCluster(ctx, r)
	digestOf, _ := app.ClusterObservationRequestDigest(r)
	if err != nil || !out.Matches(r, digestOf, f.now()) || len(out.PermissionWorkloads.Items) != 1 || out.PermissionWorkloads.Continue != "" {
		t.Fatalf("workload page: %v %+v", err, out.PermissionWorkloads)
	}
	g := f.request(fleet.ObservePermissionWorkloadGuard)
	if _, err = reader.ObserveCluster(ctx, g); !errors.Is(err, cfg.ErrUnavailable) {
		t.Fatal("missing workload guard was not unavailable", err)
	}
}
