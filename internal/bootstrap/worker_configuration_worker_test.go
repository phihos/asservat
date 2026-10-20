package bootstrap

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

func permissionInputsFixture() (contracts.PermissionDeployment, contracts.PermissionCredentialManifest) {
	id := func(n string) string { return "20000000-0000-4000-8000-0000000000" + n }
	installation := id("01")
	c := contracts.PermissionDeployment{Format: contracts.PermissionDeploymentFormat, InstallationID: installation, RootID: id("02"), RoleRootUID: id("03"), RoleSetupID: id("04"),
		Control: contracts.PermissionControlDeployment{ClusterID: id("05"), Namespace: contracts.WorkerObjectReference{Name: "asservat-hub", UID: id("06")},
			Guard: contracts.OwnerDeploymentGuard{Name: contracts.PermissionGuardName(installation)}}}
	m := contracts.PermissionCredentialManifest{Format: contracts.PermissionCredentialManifestFormat, Input: contracts.PublicRuntimeRoles{InstallationID: installation}, RootUID: c.RoleRootUID, SetupID: c.RoleSetupID}
	return c, m
}

func workerConfigurationSectionFixture() *contracts.WorkerConfigurationDeployment {
	id := func(n string) string { return "20000000-0000-4000-8000-0000000000" + n }
	return &contracts.WorkerConfigurationDeployment{Namespace: contracts.WorkerObjectReference{Name: "asservat-downloads", UID: id("07")}, Source: contracts.WorkerObjectReference{Name: "worker-profile", UID: id("08")},
		Guard:        contracts.OwnerDeploymentGuard{Name: "worker-profile-guard", PolicyUID: id("09"), PolicyGeneration: 1, BindingUID: id("10"), BindingResourceVersion: "7", Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: "installer"}}},
		AuditTransit: contracts.OwnerPublicTransit{Mount: "transit", Key: "worker-configuration-audit"}}
}

// ADR-204 decision 7: the projection's worker configuration section is
// optional. Without it the hub-worker selects no worker configuration login
// and composes no child; a present section is closed and shape-checked
// before any login opens.
func TestPermissionInputsWorkerConfigurationSectionIsOptionalAndClosed(t *testing.T) {
	read := func(c contracts.PermissionDeployment, m contracts.PermissionCredentialManifest) (contracts.PermissionDeployment, error) {
		dir := t.TempDir()
		writeOwnerJSON(t, dir, contracts.PermissionDeploymentFile, c)
		writeOwnerJSON(t, dir, contracts.PermissionCredentialManifestFile, m)
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		got, _, err := readPermissionWorkerInputs(context.Background(), root)
		return got, err
	}
	c, m := permissionInputsFixture()
	got, err := read(c, m)
	if err != nil || got.WorkerConfiguration != nil {
		t.Fatal("permission inputs without the section", err)
	}
	if purposes := contracts.PermissionProjectionPurposes(got.Retention != nil, got.WorkerConfiguration != nil, got.ContextDeletion); slices.ContainsFunc(purposes, func(p string) bool { return slices.Contains(contracts.PublicRuntimeWorkerConfigurationPurposes(), p) }) {
		t.Fatal("worker configuration login selected without the section", purposes)
	}
	// Absent: no child and no dependency touched, even with none supplied.
	if child, err := openWorkerConfiguration(context.Background(), got, nil, nil, nil, nil); child != nil || err != nil {
		t.Fatal("worker configuration child without the section", err)
	}
	c.WorkerConfiguration = workerConfigurationSectionFixture()
	if got, err = read(c, m); err != nil || got.WorkerConfiguration == nil || got.WorkerConfiguration.Source != c.WorkerConfiguration.Source || got.WorkerConfiguration.AuditTransit != c.WorkerConfiguration.AuditTransit {
		t.Fatal("valid worker configuration section", err)
	}
	// Present but without its logins, admission or audit principal: refused,
	// never a partly composed child.
	if child, err := openWorkerConfiguration(context.Background(), got, nil, nil, nil, nil); child != nil || err == nil {
		t.Fatal("worker configuration child composed without its dependencies")
	}
	for name, mutate := range map[string]func(*contracts.WorkerConfigurationDeployment){
		"hub namespace name":       func(v *contracts.WorkerConfigurationDeployment) { v.Namespace.Name = "asservat-hub" },
		"hub namespace UID":        func(v *contracts.WorkerConfigurationDeployment) { v.Namespace.UID = c.Control.Namespace.UID },
		"namespace not a label":    func(v *contracts.WorkerConfigurationDeployment) { v.Namespace.Name = "downloads.example" },
		"source UID":               func(v *contracts.WorkerConfigurationDeployment) { v.Source.UID = "worker-profile" },
		"guard without admins":     func(v *contracts.WorkerConfigurationDeployment) { v.Guard.Administrators = nil },
		"guard unpinned":           func(v *contracts.WorkerConfigurationDeployment) { v.Guard.PolicyGeneration = 0 },
		"permission guard reused":  func(v *contracts.WorkerConfigurationDeployment) { v.Guard.Name = c.Control.Guard.Name },
		"transit key path":         func(v *contracts.WorkerConfigurationDeployment) { v.AuditTransit.Key = "../records" },
		"transit mount missing":    func(v *contracts.WorkerConfigurationDeployment) { v.AuditTransit.Mount = "" },
		"administrator kind other": func(v *contracts.WorkerConfigurationDeployment) { v.Guard.Administrators[0].Kind = "ServiceAccount" },
	} {
		v := workerConfigurationSectionFixture()
		mutate(v)
		c.WorkerConfiguration = v
		if _, err := read(c, m); err == nil {
			t.Fatal("accepted:", name)
		}
	}
}

type countedObserver struct {
	calls atomic.Int32
	err   error
}

func (o *countedObserver) Observe(ctx context.Context) error {
	o.calls.Add(1)
	return o.err
}

// The child keeps observing after failures, so an accepted revision stays
// fresh, and returns only when the Lease ends: a returning child would tear
// down its siblings.
func TestWorkerConfigurationChildObservesUntilLeaseEnds(t *testing.T) {
	observer := &countedObserver{err: errors.New("synthetic observation failure")}
	w := &workerConfigurationWorker{observer: observer}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for observer.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("child returned before its Lease ended")
	default:
	}
	if observer.calls.Load() < 2 {
		t.Fatal("child stopped observing after a failure")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("child did not stop with its Lease")
	}
}

// The audit writer refuses another installation's revision and an
// unconfigured writer before it waits for any admission.
func TestWorkerConfigurationAuditRefusesForeignRevision(t *testing.T) {
	s := &installedWorkerConfigurationAudit{installation: "20000000-0000-4000-8000-000000000001"}
	if _, err := s.WriteWorkerConfiguration(context.Background(), authorization.DownloadWorkerConfiguration{}); err == nil {
		t.Fatal("unconfigured audit writer accepted a revision")
	}
}
