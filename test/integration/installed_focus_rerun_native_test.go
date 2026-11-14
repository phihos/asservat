package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5/pgxpool"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Development-only fast focus loop (docs/development-workflow.md). Keep mode
// leaves one fresh installation running after its focus and records what a
// later focus needs; rerun mode runs only that focus against it. Neither is a
// qualification: the harness marks their reports "qualification": false and
// refuses both under CI. Product checks and assertions are unchanged; the
// rerun only gives each run its own idempotency keys and synthetic source
// names, which an ordinary run never repeats.

func installedKeepMode() bool { return os.Getenv("ASSERVAT_INSTALLED_KEEP") == "1" }

// installedRerunMode reports the rerun's private state file path, or "".
func installedRerunMode() string { return os.Getenv("ASSERVAT_INSTALLED_RERUN") }

// installedRunSuffix is empty in every ordinary run, so qualification inputs
// are unchanged; a rerun gets a fresh suffix per run.
func installedRunSuffix() string {
	if installedRerunMode() == "" {
		return ""
	}
	return "-r" + os.Getenv("ASSERVAT_INSTALLED_RERUN_ID")
}

// installedRerunStartedAt is when a development-only rerun started; zero in
// every ordinary run. Checks of root-wide totals subtract what earlier runs
// on the kept installation charged before it.
var installedRerunStartedAt time.Time

// installedKeptRuns is how many focus runs the operator's synthetic capacity
// funds: the keep run plus the reruns the harness allows (KEPT_INSTALLED_RUNS).
// An ordinary run funds exactly its one focus, unchanged.
func installedKeptRuns() int64 {
	if installedKeepMode() {
		return 4 // the system byte reserve (8 GiB) fits four
	}
	return 1
}

// installedRerunFocus lists the focuses wired for reruns on one kept
// installation (RERUN_FOCUSES in the harness).
func installedRerunFocus(focus string) bool { return focus == "manual-logs" }

// installedKeptState is what the focus reads from the bootstrap and
// continuation; nothing here is product authority or a credential.
type installedKeptState struct {
	Format                                       string
	Focus                                        string
	Installation, RootID, ClusterID              string
	Name, BootstrapNamespace, TargetNamespace    string
	Image                                        string
	Postgres                                     contracts.OwnerPostgresEndpoint
	PublicRoot                                   []byte
	PublicAddress, Origin, ReviewerSubject       string
	RegionalCluster, RegionalNamespace, Workload string
	WrittenAt                                    time.Time
}

const installedKeptStateFormat = "asservat-installed-focus-state/v1"

func (s installedKeptState) desired() contracts.InitialBootstrap {
	return contracts.InitialBootstrap{Name: s.Name, BootstrapNamespace: s.BootstrapNamespace, TargetNamespace: s.TargetNamespace, Image: s.Image, Postgres: s.Postgres}
}

// installedHubDiagnose logs the hub capacity, SQL activity and process state.
func installedHubDiagnose(t *testing.T, ctx context.Context, admin *pgxpool.Pool, api kubernetes.Interface, root, installation, namespace, prefix string) func() {
	return func() {
		installedCapacityCurrentDiagnostics(ctx, admin.QueryRow, root, installation, t.Logf)
		installedSQLActivityDiagnostics(ctx, admin.Query, installation, t.Logf)
		installedProcessDiagnostics(t, ctx, api, namespace, prefix+"-owner", prefix+"-worker", contracts.PublisherName(installation))
		c, end := context.WithTimeout(ctx, 20*time.Second)
		defer end()
		installedPodDiagnostics(t, c, api, contracts.DownloadWorkerNamespaceName(installation), "download-worker", "")
		if installedJourneyFocus() == "manual-mixed" {
			installedPacketSummaryJobDiagnostics(c, api, contracts.DownloadWorkerNamespaceName(installation), t.Logf)
		}
	}
}

// TestInstalledFocusRerunWithKeptInstallation runs one focus against an
// installation a keep run left behind. Development only; never a qualification.
func TestInstalledFocusRerunWithKeptInstallation(t *testing.T) {
	statePath := installedRerunMode()
	if statePath == "" || os.Getenv("ASSERVAT_CONTEXT_FIXTURES") == "" {
		t.Skip("development-only: run scripts/test-context-storage.py --rerun-installed")
	}
	installedRerunStartedAt = time.Now()
	var f fixture
	raw, err := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if err != nil || json.Unmarshal(raw, &f) != nil || len(f.Clusters) != 2 || f.Identity == nil {
		t.Fatal("kept fixture description unavailable", err)
	}
	var s installedKeptState
	if raw, err = os.ReadFile(statePath); err != nil || json.Unmarshal(raw, &s) != nil || s.Format != installedKeptStateFormat {
		t.Fatal("kept installation state unavailable", err)
	}
	if s.Focus != installedJourneyFocus() || !installedRerunFocus(s.Focus) || installedRunSuffix() == "-r" {
		t.Fatal("rerun focus differs from the kept installation's focus or has no run id", s.Focus, installedJourneyFocus())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 17*time.Minute)
	defer cancel()
	adminConfig, err := initialBootstrapAdminPoolConfig(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	hubConfig, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(hubConfig)
	if err != nil {
		t.Fatal(err)
	}
	regionConfig, err := clientcmd.BuildConfigFromFlags("", f.Clusters[1].Config)
	if err != nil {
		t.Fatal(err)
	}
	region, err := kubernetes.NewForConfig(regionConfig)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "asservat-" + strings.ReplaceAll(s.Installation, "-", "")
	desired := s.desired()
	if image := os.Getenv("ASSERVAT_INSTALLED_RELEASE_IMAGE"); image != "" {
		// Sources changed: move the hub to the rebuilt image through the
		// product's own image change (ADR-227), as an operator would.
		record, err := api.CoreV1().ConfigMaps(s.TargetNamespace).Get(ctx, contracts.ReleaseRecordName(s.Installation), meta.GetOptions{})
		if err != nil {
			t.Fatal("release record", err)
		}
		current, err := contracts.DecodeReleaseRecord(bytes.NewBufferString(record.Data[contracts.ReleaseRecordFile]))
		if err != nil {
			t.Fatal("release record", err)
		}
		restarts := installedHubRestarts(t, ctx, api, s.TargetNamespace)
		installedReleaseChange(t, ctx, api, desired, s.Installation, image, current.Revision+1)
		installedHubSettled(t, ctx, api, s.TargetNamespace, restarts)
		t.Log("rerun: hub moved to the rebuilt image at revision " + strconv.FormatInt(current.Revision+1, 10))
	}
	identity := reopenInstalledIdentity(t, f, s.ReviewerSubject)
	installedPolicyTarget = &installedPolicyFixture{region: region, cluster: s.RegionalCluster, namespace: s.RegionalNamespace, workload: s.Workload}
	installedContextStandbyWindow(t, ctx, api, s.TargetNamespace, prefix+"-owner")
	installedPublisherSettled = func(c context.Context) {
		waitInstalledPublisherSettled(t, c, api, s.TargetNamespace, s.Installation)
	}
	diagnose := installedHubDiagnose(t, ctx, admin, api, s.RootID, s.Installation, s.TargetNamespace, prefix)
	t.Logf("rerun: installed focus %q starts on the kept installation", s.Focus)
	t.Run("manual-logs", func(t *testing.T) {
		qualifyInstalledManualLogs(t, ctx, admin, api, s.RootID, identity, s.PublicRoot, s.PublicAddress, s.Origin, f.Clusters[1].Config, s.RegionalCluster, s.RegionalNamespace, s.Workload, diagnose)
	})
}
