package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
)

func cleanupTestWorker() *hubWorker {
	return &hubWorker{
		ids: contracts.InstallationIDs{InstallationID: "10000000-0000-4000-8000-000000000001", PermissionRootID: "10000000-0000-4000-8000-000000000002"},
		config: contracts.HubWorkerConfig{Cleanup: &contracts.HubWorkerCleanup{}, Provider: contracts.HubWorkerProvider{
			Roles:                  contracts.HubWorkerProviderRoles{AuditWrap: "w", AuditUnwrap: "u", CleanupWrap: "cw", CleanupOpen: "co", CleanupVerify: "cv", CleanupSign: "cs"},
			ContextDeletionSigning: contracts.OwnerPublicTransit{Mount: "audit", Key: "deletion"},
		}},
	}
}

func TestHubWorkerCleanupSectionSelectsChild(t *testing.T) {
	w := cleanupTestWorker()
	names := func() []string {
		var out []string
		for _, c := range w.children() {
			out = append(out, c.name)
		}
		return out
	}
	if !reflect.DeepEqual(names(), []string{"configuration", "cleanup"}) {
		t.Fatal("cleanup section did not start the child", names())
	}
	w.config.Cleanup = nil
	if !reflect.DeepEqual(names(), []string{"configuration"}) {
		t.Fatal("cleanup child ran without its section", names())
	}
}

func TestHubWorkerCleanupConfigErrorsStopWithoutRetry(t *testing.T) {
	if err := cleanupTestWorker().validCleanupConfig(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*hubWorker){
		"role":    func(w *hubWorker) { w.config.Provider.Roles.CleanupSign = "" },
		"signing": func(w *hubWorker) { w.config.Provider.ContextDeletionSigning = contracts.OwnerPublicTransit{} },
		"ids":     func(w *hubWorker) { w.ids.InstallationID = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			w := cleanupTestWorker()
			change(w)
			call, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			var config *cleanupConfigError
			// A configuration error returns at once instead of retrying.
			if err := w.runCleanup(call); !errors.As(err, &config) || call.Err() != nil {
				t.Fatal("invalid cleanup configuration retried or passed", err)
			}
		})
	}
}

func TestHubWorkerCleanupRequiresWorkerDependencies(t *testing.T) {
	var config *cleanupConfigError
	if _, err := cleanupTestWorker().openCleanup(t.Context()); !errors.As(err, &config) {
		t.Fatal("cleanup opened without the parent's admission/providers/inputs", err)
	}
}

func TestCleanupStorageCredentialReadsItsOwnFileEachTime(t *testing.T) {
	dir := t.TempDir()
	write := func(name, key string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"accessKeyID":"`+key+`","secretAccessKey":"secret","sessionToken":""}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(contracts.HubWorkerCleanupStorageFile, "cleanup")
	write(contracts.HubWorkerCleanupVerifyStorageFile, "verify")
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	in := &providerInputs{files: root}
	for file, want := range map[string]string{contracts.HubWorkerCleanupStorageFile: "cleanup", contracts.HubWorkerCleanupVerifyStorageFile: "verify"} {
		c, err := (cleanupStorageCredential{in, file}).Retrieve(t.Context())
		if err != nil || c.AccessKeyID != want {
			t.Fatal("principal not read from its file", file, err)
		}
	}
	if err := os.Remove(filepath.Join(dir, contracts.HubWorkerCleanupStorageFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := (cleanupStorageCredential{in, contracts.HubWorkerCleanupStorageFile}).Retrieve(t.Context()); err == nil {
		t.Fatal("removed credential served from cache")
	}
}

// Refused refresh stays pending and retains the provider error class.
func TestCleanupRefusedRefreshReportsStage(t *testing.T) {
	d := &hubWorkerCleanupDeployment{providers: &kms.InstalledConfigurationProviderEffects{}}
	attempted, err := d.advanceGroup(t.Context(), []string{"10000000-0000-4000-8000-000000000001"}, nil)
	if attempted != 0 || !errors.Is(err, kms.ErrKeyService) || cleanupRuntimeEvent(err) != "provider-refresh/unavailable" {
		t.Fatalf("pending refresh stage/class changed: %s", cleanupRuntimeEvent(err))
	}
}

type privateCleanupError struct{}

func (privateCleanupError) Error() string     { panic("provider text must not enter diagnostics") }
func (privateCleanupError) FixedStep() string { panic("provider diagnostic must not enter event keys") }

func TestCleanupDiagnosticsKeepOnlyLocalStageAndClass(t *testing.T) {
	private := privateCleanupError{}
	err := &cleanupRuntimeError{"healthy", private}
	var out bytes.Buffer
	report := eventLog(&out, "operation cleanup")
	for range 5 {
		report(cleanupRuntimeEvent(err))
	}
	if !errors.Is(err, private) || out.String() != "operation cleanup: healthy/unavailable (1)\noperation cleanup: healthy/unavailable (2)\noperation cleanup: healthy/unavailable (4)\n" {
		t.Fatal("private diagnostics or repeated pending failure escaped bounded log")
	}
	app := (auditapp.OperationCleanup{}).Advance(t.Context(), "never-selected-row")
	if !errors.Is(app, auditapp.ErrUnavailable) || cleanupRuntimeEvent(&cleanupRuntimeError{"healthy", app}) != "healthy/input/unavailable" {
		t.Fatal("application refusal stage lost")
	}
}

type cleanupHistoryFinalizerFunc func(context.Context, auditvalue.OperationHistoryKey) (auditvalue.OperationHistoryRelease, error)

func (f cleanupHistoryFinalizerFunc) ReleaseOperationHistory(ctx context.Context, key auditvalue.OperationHistoryKey) (auditvalue.OperationHistoryRelease, error) {
	return f(ctx, key)
}

func cleanupHistoryPageKeys() []auditvalue.OperationHistoryKey {
	now := time.Now().UTC().Truncate(time.Microsecond)
	keys := make([]auditvalue.OperationHistoryKey, 16)
	for i := range keys {
		keys[i] = auditvalue.OperationHistoryKey{RootID: "10000000-0000-4000-8000-000000000001", Lane: "normal", PrincipalDigest: artifact.Digest{byte(i + 1)}, ReleaseAt: now.Add(-2 * time.Hour), DeleteBy: now.Add(-time.Hour)}
	}
	return keys
}

func TestCleanupHistoryPageKeepsExactKeysEarlierDeadlineAndFirstFailure(t *testing.T) {
	keys := cleanupHistoryPageKeys()
	outer := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), outer)
	defer cancel()
	first := errors.New("synthetic unknown release")
	var observed []auditvalue.OperationHistoryKey
	finalizer := cleanupHistoryFinalizerFunc(func(call context.Context, key auditvalue.OperationHistoryKey) (auditvalue.OperationHistoryRelease, error) {
		if until, ok := call.Deadline(); !ok || !until.Equal(outer) {
			t.Fatal("history page extended the parent deadline")
		}
		observed = append(observed, key)
		if len(observed) == 2 {
			return auditvalue.OperationHistoryRelease{}, first
		}
		return auditvalue.OperationHistoryRelease{Records: 1}, nil
	})
	attempted, err := releaseCleanupHistoryPage(ctx, outer.Add(time.Hour), keys, finalizer)
	if attempted != 16 || !errors.Is(err, first) || !reflect.DeepEqual(observed, keys) {
		t.Fatal("history page lost first outcome, exact keys or later-key fairness", err, len(observed))
	}
	invalid := append([]auditvalue.OperationHistoryKey{}, keys...)
	invalid[15].RootID = "invalid"
	d := &hubWorkerCleanupDeployment{history: auditapp.OperationHistoryCleanup{Finalizer: finalizer}}
	before := len(observed)
	if attempted, err := d.releaseHistoryPage(t.Context(), invalid); attempted != 0 || cleanupRuntimeEvent(err) != "history-input/unavailable" || len(observed) != before {
		t.Fatal("invalid history page entered admission or released a prefix")
	}
}

func TestCleanupLifecycleGroupStopsOnCancellationAndKeepsCursor(t *testing.T) {
	ids := []string{"10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002"}
	ctx, cancel := context.WithCancel(t.Context())
	var observed []string
	attempted, err := advanceCleanupLifecycleGroup(ctx, time.Now().Add(5*time.Second), ids, func(_ context.Context, id string) error {
		observed = append(observed, id)
		cancel()
		return nil
	})
	if attempted != 1 || !errors.Is(err, context.Canceled) || !reflect.DeepEqual(observed, ids[:1]) {
		t.Fatal("canceled lifecycle group started another ID", attempted)
	}
	if got := cleanupLifecycleCursor("", ids, attempted); got != ids[0] {
		t.Fatal("partial page skipped unattempted IDs", got)
	}
	if got := cleanupLifecycleCursor(ids[0], ids, len(ids)); got != "" {
		t.Fatal("complete short page did not wrap")
	}
	full := make([]string, 16)
	for i := range full {
		full[i] = ids[i%2]
	}
	if got := cleanupLifecycleCursor(ids[0], full, len(full)); got != full[15] {
		t.Fatal("full page wrapped before reading later IDs")
	}
	for _, input := range [][]string{nil, {ids[0], "invalid"}, {ids[0], ids[1], ids[0]}} {
		d := &hubWorkerCleanupDeployment{}
		if attempted, err := d.advanceGroup(t.Context(), input, nil); attempted != 0 || cleanupRuntimeEvent(err) != "lifecycle-group-input/unavailable" {
			t.Fatal("invalid lifecycle group entered credential work", strings.Join(input, ","))
		}
	}
}
