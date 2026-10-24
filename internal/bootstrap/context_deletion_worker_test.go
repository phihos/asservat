package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

func deletionTestSection(t *testing.T) contracts.ContextDeletionDeployment {
	t.Helper()
	key, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.ContextDeletionDeployment{
		EvidenceStore: contracts.OwnerAuditStore{Endpoint: "https://evidence.synthetic.invalid", Region: "test", Bucket: "evidence", Roots: [][]byte{downloadTestRoot(t, 205)}},
		Signing:       contracts.ContextDeletionSigning{Mount: "transit", Key: "context-deletion", Version: 1, KeyID: "v1", PublicKeys: map[string][]byte{"v1": key}},
	}
}

func TestContextDeletionPreparationFailureDoesNotRetainResources(t *testing.T) {
	w := &contextDeletionWorker{}
	defer w.Close()
	for range 3 {
		if err := w.prepare(deletionTestSection(t), "invalid-store-id"); err == nil {
			t.Fatal("unqualified store accepted")
		}
		if len(w.closers) != 0 || w.cleaner != nil {
			t.Fatal("failed preparation retained resources for the next sweep")
		}
	}
}

func TestContextDeletionHandoffDoesNotExposeMutablePins(t *testing.T) {
	v := deletionTestSection(t)
	d := &CapacityHubWorkerDeployment{root: context.Background(), contextDeletion: &v, evidenceStoreID: runtimeID}
	got, store, ok := d.ContextDeletion()
	if !ok || store != runtimeID {
		t.Fatal("verified pins missing")
	}
	got.Signing.PublicKeys["v1"][0] ^= 1
	got.EvidenceStore.Roots[0][0] ^= 1
	again, _, _ := d.ContextDeletion()
	if again.Signing.PublicKeys["v1"][0] == got.Signing.PublicKeys["v1"][0] || again.EvidenceStore.Roots[0][0] == got.EvidenceStore.Roots[0][0] {
		t.Fatal("consumer can mutate verified pins")
	}
	d.closed = true
	if _, _, ok := d.ContextDeletion(); ok {
		t.Fatal("closed deployment still hands off pins")
	}
}

func deletionTestQualification() capacityapp.CapacityQualification {
	return capacityapp.CapacityQualification{ID: runtimeID, Digest: artifact.Digest{1},
		RootBacking: capacityapp.RootBackingInput{RootID: runtimeID, InstallationID: runtimeID, QualificationID: runtimeID, QualificationDigest: artifact.Digest{1}, SystemPoolUID: "pool",
			Capture: capacityapp.RootAuditBacking{Policy: audit.OperationLifecyclePolicy{StoreID: runtimeID}}},
		NamespaceGuards: []capacityapp.CapacityNamespaceQualification{{ClusterID: runtimeID, Digest: artifact.Digest{2}, Keys: []string{"team"}}},
		Backends:        []capacityapp.CapacityBackendQualification{{Layout: capacityapp.CapacityBackendLayout, ID: runtimeID, Digest: artifact.Digest{3}, PoolUID: "pool", StorageProfile: "store", CapacityID: runtimeID, PoolID: runtimeID, EvidenceStoreID: runtimeID, AuditStoreID: runtimeID, Usable: capacityapp.BudgetAmount{Bytes: 1 << 20, Objects: 10}}},
	}
}

func TestContextDeletionCapacityHandoffRequiresExactQualification(t *testing.T) {
	// These are immutable pins only. The fixtures supply no runtime authority;
	// both layout openers must finish their native projection proof first.
	for _, layout := range []string{contracts.HubWorkerInstalledLayout, contracts.HubWorkerProviderInstalledLayout} {
		t.Run(layout, func(t *testing.T) {
			for _, fault := range []string{"none", "no section", "invalid section", "unqualified", "multiple backends", "foreign root", "foreign installation", "expired", "canceled", "closed"} {
				t.Run(fault, func(t *testing.T) {
					call, cancel := context.WithCancel(context.Background())
					defer cancel()
					section := deletionTestSection(t)
					c := contracts.CapacityDeployment{InstallationID: runtimeID, PermissionRootID: runtimeID, ContextDeletion: &section}
					q := deletionTestQualification()
					if !q.Valid() {
						t.Fatal("invalid qualification fixture")
					}
					d := &CapacityHubWorkerDeployment{root: call, input: contracts.HubWorkerDeployment{InstallationID: runtimeID, Activation: &contracts.HubWorkerRuntimeActivation{WorkerLayout: layout}}}
					until := time.Now().Add(time.Second)
					switch fault {
					case "no section":
						c.ContextDeletion = nil
					case "invalid section":
						section.Signing.PublicKeys = nil
					case "unqualified":
						q.Digest = artifact.Digest{}
					case "multiple backends":
						q.Backends = append(q.Backends, q.Backends[0])
					case "foreign root":
						c.PermissionRootID = "20000000-0000-4000-8000-000000000001"
					case "foreign installation":
						c.InstallationID = "20000000-0000-4000-8000-000000000001"
					case "expired":
						until = time.Now().Add(-time.Second)
					case "canceled":
						cancel()
					case "closed":
						d.closed = true
					}
					err := d.acceptContextDeletion(call, c, q, until)
					_, store, ok := d.ContextDeletion()
					if fault == "none" {
						if err != nil || !ok || store != q.Backends[0].EvidenceStoreID {
							t.Fatal("qualified backend not handed off", err)
						}
						section.Signing.PublicKeys["v1"][0] ^= 1
						pinned, _, _ := d.ContextDeletion()
						if pinned.Signing.PublicKeys["v1"][0] == section.Signing.PublicKeys["v1"][0] {
							t.Fatal("input mutation changed the accepted signing key")
						}
						c.ContextDeletion = &pinned
						q.Backends[0].EvidenceStoreID = "20000000-0000-4000-8000-000000000001"
						if d.acceptContextDeletion(call, c, q, until) == nil {
							t.Fatal("replacement store accepted")
						}
					} else if ok || fault != "no section" && err == nil || fault == "no section" && err != nil {
						t.Fatal("invalid handoff accepted or optional section required", ok, err)
					}
				})
			}
		})
	}
}

func TestContextDeletionCapacityHandoffPreservesDeadlineAfterLock(t *testing.T) {
	ctx := context.Background()
	section := deletionTestSection(t)
	c := contracts.CapacityDeployment{InstallationID: runtimeID, PermissionRootID: runtimeID, ContextDeletion: &section}
	d := &CapacityHubWorkerDeployment{root: ctx, input: contracts.HubWorkerDeployment{InstallationID: runtimeID}}
	d.mu.Lock()
	until := time.Now().Add(30 * time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- d.acceptContextDeletion(ctx, c, deletionTestQualification(), until) }()
	<-time.After(time.Until(until) + time.Millisecond)
	d.mu.Unlock()
	if err := <-done; err == nil {
		t.Fatal("expired startup proof accepted after waiting for the lock")
	}
	if _, _, ok := d.ContextDeletion(); ok {
		t.Fatal("expired startup exposed deletion pins")
	}
}

func TestContextDeletionSweepRevisitsFailuresWithoutStarvingLaterWork(t *testing.T) {
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	var poison []artifact.Location
	for i := range 16 {
		poison = append(poison, artifact.Location{ClusterID: runtimeID, ArtifactID: runtimeID, AttemptID: fmt.Sprintf("20000000-0000-4000-8000-%012d", i+1)})
	}
	healthy := artifact.Location{ClusterID: runtimeID, ArtifactID: runtimeID, AttemptID: "30000000-0000-4000-8000-000000000001"}
	afterPoison := postgres.ContextDeletionCursor{Through: at, AfterExpiresAt: at.Add(-time.Hour), AfterAttemptID: poison[15].AttemptID}
	var cursor postgres.ContextDeletionCursor
	seen := map[artifact.Location]int{}
	lists := 0
	list := func(call context.Context, got postgres.ContextDeletionCursor) (postgres.ContextDeletionPage, error) {
		lists++
		if until, ok := call.Deadline(); !ok || time.Until(until) > 5*time.Second {
			t.Fatal("list has no finite original deadline")
		}
		switch lists {
		case 1, 4:
			if got != (postgres.ContextDeletionCursor{}) {
				t.Fatal("completed pass did not wrap to retry failed attempts")
			}
			return postgres.ContextDeletionPage{Locations: poison, Next: afterPoison}, nil
		case 2:
			if got != afterPoison {
				t.Fatal("failed oldest page prevented cursor progress")
			}
			return postgres.ContextDeletionPage{}, errors.New("synthetic list outage")
		case 3:
			if got != afterPoison {
				t.Fatal("list outage discarded the existing pass cursor")
			}
			return postgres.ContextDeletionPage{Locations: []artifact.Location{healthy}}, nil
		}
		t.Fatal("unexpected extra page")
		return postgres.ContextDeletionPage{}, nil
	}
	clean := func(call context.Context, loc artifact.Location) error {
		if call != ctx {
			t.Fatal("cleanup did not retain the original Lease context")
		}
		seen[loc]++
		if loc != healthy {
			return errors.New("synthetic permanently unavailable checkpoint")
		}
		return nil
	}
	for range 4 {
		cursor, _ = sweepContextDeletionPage(ctx, cursor, list, clean)
	}
	if seen[healthy] != 1 {
		t.Fatal("healthy later attempt starved")
	}
	for _, loc := range poison {
		if seen[loc] != 2 {
			t.Fatal("failed attempt was not retried on wraparound")
		}
	}
}

func TestContextDeletionSweepStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	list := func(context.Context, postgres.ContextDeletionCursor) (postgres.ContextDeletionPage, error) {
		cancel()
		return postgres.ContextDeletionPage{Locations: []artifact.Location{{ClusterID: runtimeID, ArtifactID: runtimeID, AttemptID: runtimeID}}}, nil
	}
	clean := func(context.Context, artifact.Location) error {
		t.Fatal("canceled list started cleanup")
		return nil
	}
	cursor, _ := sweepContextDeletionPage(ctx, postgres.ContextDeletionCursor{}, list, clean)
	if cursor != (postgres.ContextDeletionCursor{}) {
		t.Fatal("canceled list advanced its cursor")
	}
	list = func(context.Context, postgres.ContextDeletionCursor) (postgres.ContextDeletionPage, error) {
		t.Fatal("canceled sweep listed another page")
		return postgres.ContextDeletionPage{}, nil
	}
	_, _ = sweepContextDeletionPage(ctx, cursor, list, clean)
}

func TestEvidenceDeleteStorageRereadsAndRefusesSessionTokens(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, contracts.EvidenceDeleteDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	s := evidenceDeleteStorage{&providerInputs{files: root, dir: contracts.EvidenceDeleteDirectory}}
	if _, err = s.Retrieve(context.Background()); err == nil {
		t.Fatal("missing credential accepted")
	}
	in := filepath.Join(dir, contracts.EvidenceDeleteDirectory)
	writeOwnerJSON(t, in, contracts.EvidenceDeleteCredentialFile, contracts.OwnerStorageCredential{AccessKeyID: "delete", SecretAccessKey: "secret"})
	c, err := s.Retrieve(context.Background())
	if err != nil || c.AccessKeyID != "delete" || c.SessionToken != "" {
		t.Fatal("credential not read", err)
	}
	writeOwnerJSON(t, in, contracts.EvidenceDeleteCredentialFile, contracts.OwnerStorageCredential{AccessKeyID: "rotated", SecretAccessKey: "secret", SessionToken: "session"})
	if _, err = s.Retrieve(context.Background()); err == nil {
		t.Fatal("session token accepted")
	}
}

func TestContextDeletionLoginsFollowTheWorkerConfigurationLogins(t *testing.T) {
	got := contracts.PermissionProjectionPurposes(true, true, true, false)
	want := append(append(append(contracts.PublicRuntimePermissionPurposes(), contracts.PublicRuntimeRetentionPurposes()...), contracts.PublicRuntimeWorkerConfigurationPurposes()...), contracts.PublicRuntimeContextDeletionPurposes()...)
	if !slices.Equal(got, want) || slices.ContainsFunc(contracts.PermissionProjectionPurposes(true, true, false, false), func(p string) bool { return slices.Contains(contracts.PublicRuntimeContextDeletionPurposes(), p) }) {
		t.Fatal("deletion logins out of order or present without deletion", got)
	}
	if w, err := openContextDeletion(context.Background(), contracts.PermissionDeployment{}, nil, nil, nil, nil, nil); w != nil || err != nil {
		t.Fatal("deletion child opened without its flag", err)
	}
}

type deadlineObserverFunc func(context.Context, int) (int64, error)

func (f deadlineObserverFunc) ObserveOverdueContextCaptures(ctx context.Context, limit int) (int64, error) {
	return f(ctx, limit)
}

// ADR-223: full pages continue within one sweep up to the fixed bound; a
// short page or a failure ends it. Every page is bounded by its own deadline.
func TestContextDeadlineObservationPagesAreBounded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pages []int64
		fail  int
		calls int
		ok    bool
	}{
		{"empty", []int64{0}, -1, 1, true},
		{"short-second-page", []int64{16, 3}, -1, 2, true},
		{"backlog-bound", []int64{16, 16, 16, 16, 16, 16, 16, 16, 16}, -1, contextDeadlinePages, true},
		{"failure", []int64{16, 0}, 1, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			outcome := observeContextDeadlines(t.Context(), func(ctx context.Context, limit int) (int64, error) {
				defer func() { calls++ }()
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second || limit != 16 {
					t.Fatal("unbounded deadline page", limit)
				}
				if calls == tc.fail {
					return 0, errors.New("synthetic SQL failure")
				}
				return tc.pages[calls], nil
			})
			if calls != tc.calls || (outcome == "") != tc.ok {
				t.Fatal("deadline paging", calls, outcome)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if outcome := observeContextDeadlines(ctx, func(context.Context, int) (int64, error) {
		t.Fatal("canceled sweep observed deadlines")
		return 0, nil
	}); outcome != "" {
		t.Fatal(outcome)
	}
}

// The installed sweep observes deadlines on every pass, including before the
// capacity projection supplies the deletion pins, and stops with its Lease.
func TestContextDeletionSweepObservesDeadlinesWithoutDeletionPins(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	observed := 0
	w := &contextDeletionWorker{
		deadlines: deadlineObserverFunc(func(context.Context, int) (int64, error) {
			observed++
			cancel()
			return 1, nil
		}),
		section: func() (contracts.ContextDeletionDeployment, string, bool) {
			return contracts.ContextDeletionDeployment{}, "", false
		},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.run(ctx)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("sweep did not stop with its context")
	}
	if observed != 1 || w.cleaner != nil {
		t.Fatal("deadline observation did not run independently of deletion", observed)
	}
}
