package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

const permissionTestCluster = "22222222-2222-4222-8222-222222222222"

func permissionTestControl() cfg.NamespaceRef {
	return cfg.NamespaceRef{Name: "asservat", UID: "33333333-3333-4333-8333-333333333333"}
}

func permissionTestConfig() contracts.HubWorkerConfig {
	return contracts.HubWorkerConfig{
		KeyService: contracts.HubWorkerKeyService{AuditMount: "asservat-audit", AuditKey: "configuration"},
		Provider: contracts.HubWorkerProvider{
			WorkerConfigurationAudit: contracts.OwnerPublicTransit{Mount: "asservat-audit", Key: "worker-configuration"},
			ContextDeletionSigning:   contracts.OwnerPublicTransit{Mount: "asservat-audit", Key: "context-deletion"},
		},
		Permission: &contracts.HubWorkerPermission{
			StatusUsers: []string{"system:serviceaccount:asservat:asservat-hub-worker"},
			Delegations: []contracts.PermissionDelegation{{
				Writers:   []contracts.OwnerDeploymentActor{{Kind: "Group", Name: "team-a"}},
				ClusterID: permissionTestCluster, Namespace: contracts.WorkerObjectReference{Name: "team-a", UID: "44444444-4444-4444-8444-444444444444"},
				Workloads: []contracts.PermissionWorkload{}, Roles: []string{"evidence-reader"}, Issuers: []string{"https://id.example.test/realms/a"},
			}},
			Review:              "asservat-permission-review",
			Retention:           true,
			WorkerConfiguration: &contracts.HubWorkerWorkerConfiguration{Namespace: "asservat-workers", Source: "asservat-worker-profile"},
			ContextDeletion:     &contracts.HubWorkerContextDeletion{EvidenceStore: contracts.HubWorkerObjectStore{Endpoint: "https://objects.example.test", Region: "us-east-1", Bucket: "evidence"}},
			Browser:             &contracts.HubWorkerBrowserSettings{Settings: "asservat-browser-settings"},
			Identity:            &contracts.HubWorkerIdentitySettings{Settings: "asservat-identity-settings", Issuer: "https://id.example.test/realms/a"},
		},
	}
}

func TestHubWorkerPermissionConfigDecodesClosed(t *testing.T) {
	body := `{"format":"` + contracts.HubWorkerConfigFormat + `","permission":{"statusUsers":["u"],"delegations":[],"retention":true,` +
		`"workerConfiguration":{"namespace":"w","source":"s"},"contextDeletion":{"evidenceStore":{"endpoint":"https://e","region":"r","bucket":"b"}},` +
		`"browser":{"settings":"b"},"identity":{"settings":"i","issuer":"https://i"},"review":"r"}}`
	c, err := contracts.DecodeHubWorkerConfig(strings.NewReader(body))
	if err != nil || c.Permission == nil || !c.Permission.Retention || c.Permission.WorkerConfiguration.Source != "s" || c.Permission.ContextDeletion.EvidenceStore.Bucket != "b" {
		t.Fatal("permission section not decoded", err)
	}
	for _, removed := range []string{`"rootID":"x"`, `"guard":{}`, `"uid":"x"`} {
		if _, err := contracts.DecodeHubWorkerConfig(strings.NewReader(strings.Replace(body, `"retention":true`, `"retention":true,`+removed, 1))); err == nil {
			t.Fatal("removed installer field accepted", removed)
		}
	}
}

func TestHubWorkerPermissionValidation(t *testing.T) {
	control := permissionTestControl()
	if err := validateHubWorkerPermission(permissionTestConfig(), control); err != nil {
		t.Fatal("valid section refused", err)
	}
	minimal := permissionTestConfig()
	minimal.Permission = &contracts.HubWorkerPermission{StatusUsers: []string{"u"}}
	if err := validateHubWorkerPermission(minimal, control); err != nil {
		t.Fatal("minimal section refused", err)
	}
	for name, mutate := range map[string]func(*contracts.HubWorkerConfig){
		"no-status-users":      func(c *contracts.HubWorkerConfig) { c.Permission.StatusUsers = nil },
		"unknown-role":         func(c *contracts.HubWorkerConfig) { c.Permission.Delegations[0].Roles = []string{"admin"} },
		"delegation-no-writer": func(c *contracts.HubWorkerConfig) { c.Permission.Delegations[0].Writers = nil },
		"review-name":          func(c *contracts.HubWorkerConfig) { c.Permission.Review = "Bad_Name" },
		"worker-in-hub":        func(c *contracts.HubWorkerConfig) { c.Permission.WorkerConfiguration.Namespace = control.Name },
		"worker-no-transit": func(c *contracts.HubWorkerConfig) {
			c.Provider.WorkerConfigurationAudit = contracts.OwnerPublicTransit{}
		},
		"deletion-no-signing": func(c *contracts.HubWorkerConfig) { c.Provider.ContextDeletionSigning = contracts.OwnerPublicTransit{} },
		"deletion-audit-key":  func(c *contracts.HubWorkerConfig) { c.Provider.ContextDeletionSigning.Key = c.KeyService.AuditKey },
		"deletion-endpoint": func(c *contracts.HubWorkerConfig) {
			c.Permission.ContextDeletion.EvidenceStore.Endpoint = "http://objects"
		},
		"identity-no-issuer": func(c *contracts.HubWorkerConfig) { c.Permission.Identity.Issuer = "" },
		"browser-name":       func(c *contracts.HubWorkerConfig) { c.Permission.Browser.Settings = "" },
	} {
		c := permissionTestConfig()
		mutate(&c)
		if err := validateHubWorkerPermission(c, control); err == nil {
			t.Fatal("invalid section accepted", name)
		}
	}
}

func TestPermissionTrustDigestIsDeterministic(t *testing.T) {
	control := permissionTestControl()
	c := *permissionTestConfig().Permission
	a, err := permissionTrustDigest(permissionTestCluster, permissionPlan(c, control))
	b, err2 := permissionTrustDigest(permissionTestCluster, permissionPlan(c, control))
	if err != nil || err2 != nil || a != b || a == (artifact.Digest{}) {
		t.Fatal("digest not deterministic", err, err2)
	}
	c.Delegations[0].Roles = []string{"evidence-owner"}
	changed, _ := permissionTrustDigest(permissionTestCluster, permissionPlan(c, control))
	other, _ := permissionTrustDigest("55555555-5555-4555-8555-555555555555", permissionPlan(*permissionTestConfig().Permission, control))
	if changed == a || other == a {
		t.Fatal("digest ignores the installed delegations or the cluster")
	}
}

func TestPermissionChildSelection(t *testing.T) {
	w := &hubWorker{config: permissionTestConfig()}
	found := false
	for _, c := range w.children() {
		found = found || c.name == "permission"
	}
	w.config.Permission = nil
	for _, c := range w.children() {
		if c.name == "permission" {
			t.Fatal("permission child runs without its section")
		}
	}
	if !found {
		t.Fatal("permission child missing with its section")
	}
	got := contracts.PermissionProjectionPurposes(true, true, true, true)
	if len(got) != 12 || got[0] != "permission-accept" || got[len(got)-1] != "browser-settings" {
		t.Fatal("unexpected permission logins", got)
	}
	for _, p := range got {
		if _, ok := postgres.PublicRuntimeRoleName(permissionTestCluster, p); !ok {
			t.Fatal("purpose without derived role", p)
		}
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

func TestEvidenceDeleteStorageRereadsAndRefusesSessionTokens(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	s := evidenceDeleteStorage{&providerInputs{files: root}}
	if _, err = s.Retrieve(context.Background()); err == nil {
		t.Fatal("missing credential accepted")
	}
	writeOwnerJSON(t, dir, contracts.HubWorkerEvidenceDeleteStorageFile, contracts.OwnerStorageCredential{AccessKeyID: "delete", SecretAccessKey: "secret"})
	c, err := s.Retrieve(context.Background())
	if err != nil || c.AccessKeyID != "delete" || c.SessionToken != "" {
		t.Fatal("credential not read", err)
	}
	writeOwnerJSON(t, dir, contracts.HubWorkerEvidenceDeleteStorageFile, contracts.OwnerStorageCredential{AccessKeyID: "rotated", SecretAccessKey: "secret", SessionToken: "session"})
	if _, err = s.Retrieve(context.Background()); err == nil {
		t.Fatal("session token accepted")
	}
}

type deadlineObserverFunc func(context.Context, int) (int64, error)

func (f deadlineObserverFunc) ObserveOverdueContextCaptures(ctx context.Context, limit int) (int64, error) {
	return f(ctx, limit)
}

// ADR-223: full pages continue within one sweep up to the fixed bound; a
// short page or a failure ends it.
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
}

// The sweep observes deadlines on every pass, including before the cleaner
// can be prepared, and stops with its Lease.
func TestContextDeletionSweepObservesDeadlinesBeforePreparation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	observed, prepared := 0, 0
	d := &contextDeletionWorker{
		deadlines: deadlineObserverFunc(func(context.Context, int) (int64, error) {
			observed++
			return 1, nil
		}),
		prepare: func(context.Context) (*privacyapp.ContextCleaner, []func(), error) {
			prepared++
			cancel()
			return nil, nil, errors.New("synthetic store ID unavailable")
		},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.run(ctx)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("sweep did not stop with its context")
	}
	if observed != 1 || prepared != 1 || d.cleaner != nil {
		t.Fatal("deadline observation did not run independently of deletion", observed, prepared)
	}
}

// The authority audit publisher holds the one authority audit admission slot
// most of each second; the worker configuration and context deletion writers
// share that slot. Calling the admission directly while the publisher holds it
// fails at once (the live `audit.admission (unavailable)` after a second worker
// profile revision); the shared turn waits for the holder to release instead.
func TestAuthorityAuditTurnQueuesWritersBehindTheHolder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	admission, err := fleetapp.NewWorkerRuntimeAdmission(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Close()
	turn := newAuthorityAuditTurn(admission)
	_, release, err := turn.wait(ctx)
	if err != nil {
		t.Fatal("first writer not admitted", err)
	}
	if _, err := admission.WaitAuthorityAudit(ctx); err == nil {
		t.Fatal("the admission admitted a second authority audit while the slot is held")
	}
	time.AfterFunc(200*time.Millisecond, release)
	wait, end := context.WithTimeout(ctx, 3*time.Second)
	defer end()
	started := time.Now()
	_, second, err := turn.wait(wait)
	if err != nil {
		t.Fatal("queued writer failed instead of waiting for the holder", err)
	}
	if time.Since(started) < 150*time.Millisecond {
		t.Fatal("queued writer was admitted while the holder still held the slot")
	}
	second()
	held, release, err := turn.wait(ctx)
	if err != nil || held == nil {
		t.Fatal("turn not returned after release", err)
	}
	release()
	cancelled, stop := context.WithCancel(ctx)
	_, r, _ := turn.wait(ctx)
	stop()
	if _, _, err := turn.wait(cancelled); err == nil {
		t.Fatal("cancelled waiter admitted")
	}
	r()
}
