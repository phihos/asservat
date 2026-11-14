package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

func installerOperatorStorage(t *testing.T, ctx context.Context, p *initialRuntimeNativeProviders, user string, actions, users []string) []byte {
	t.Helper()
	var native struct {
		Container string `json:"runtimeProviderPairS3Container"`
	}
	raw, err := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if err != nil || json.Unmarshal(raw, &native) != nil || !strings.HasPrefix(native.Container, "asservat-context-") || !strings.HasSuffix(native.Container, "-s3") {
		clear(raw)
		t.Fatal("owned S3 container identity missing", err)
	}
	clear(raw)
	return installerOwnedOperatorStorage(t, ctx, p, native.Container, user, actions, users)
}

// nativeCapacityProfile is the operator's synthetic capacity profile; its
// footprints and sizes mirror the capacity SQL fixture (ADR-190). Processing
// coverage (ADR-146) requires a capture's deletion date (retention plus the
// deletion budget, about 4200 s here) before the processing root's current
// end, which root renewal sets AdmissionSeconds ahead, so the profile uses the
// one-day maximum (local hold 12). Each renewal also spends one lifetime
// processing root transition and one configuration transition; 8 and 100 with
// 60 s renewals expired the root nine minutes after install (local hold 10).
// Every MCP call, including status polls, charges one normal-lane record to the
// same Keycloak MCP principal until its 10000 s retention; the second workload
// cluster's short journey runs as that principal after the full journey, so
// the normal lane holds 128 records rather than 64.
func nativeCapacityProfile() *contracts.InstallerCapacitySettings {
	f := func(row, wal int64) contracts.InstallerCapacityFootprint {
		return contracts.InstallerCapacityFootprint{RowBytes: row, TransitionWALBytes: wal}
	}
	lane := func(accounts, records int64) contracts.InstallerCapacityLane {
		return contracts.InstallerCapacityLane{Accounts: accounts, Records: records, RetainedSeconds: 10000}
	}
	// Several focuses on one installation each get their own funding: the
	// per-focus records and normal-lane records add up (installedEachFocus).
	var records, normal int64
	installedEachFocus(func() {
		r, n := installedFocusCapacityRecords()
		records, normal = records+r, normal+n
	})
	poolSpec, policySpec := installerDeclaredCapacitySpecs()
	profile := &contracts.InstallerCapacitySettings{Pool: "capacity", Policy: "applications", PoolSpec: poolSpec, PolicySpec: policySpec, NamespaceKeys: []string{"team"}, Accounts: 16, Records: records, AdmissionSeconds: 86400,
		Lanes:               contracts.InstallerCapacityLanes{CaptureRetainedSeconds: 10000, Normal: lane(4, normal*installedKeptRuns()), Resolution: lane(4, 8*installedFundedRuns()), Processing: lane(2, 16)},
		StopRetainedSeconds: 10000,
		Backup:              contracts.InstallerCapacityBackup{HorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, BackupCopies: 2, WALCopies: 3},
		Footprints:          contracts.InstallerCapacityFootprints{Capture: f(128<<10, 256<<10), Operation: f(128<<10, 256<<10), Processing: f(128<<10, 256<<10), Native: f(64<<10, 128<<10), Stop: f(128<<10, 256<<10), ProcessingState: f(16<<10, 64<<10)},
		PurgeLeases:         4,
		Processing:          contracts.InstallerCapacityProcessing{MaxRules: 2, MaxRootTransitions: 512},
		Metadata:            contracts.InstallerCapacityMetadata{FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20, RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, ConfigurationTransitions: 4096},
		Envelope:            contracts.InstallerCapacityEnvelope{SystemObjects: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1 << 50}, SQLBytes: 1 << 50, BackupBytes: 1 << 50, WALBytes: 1 << 50, KeyAttempts: 1 << 50},
		Backends:            []contracts.InstallerCapacityBackend{{StorageProfile: "dedicated", Usable: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1000000000}}}}
	if installedJourneyFocus() == "share-retirement" {
		// Selected before installation/admission: exercise original finite
		// bounds, never rewrite a running operation to make cleanup due.
		profile.Backup.HorizonSeconds = 2
		// The ten-second cohort did not qualify healthy native retirement.
		// Select thirty seconds before installation for serial native checks
		// and cold provider work; retention and proof requirements stay fixed.
		// This moves original purge 60s earlier and live removal 20s earlier.
		profile.Backup.CleanupBudgetSeconds, profile.Backup.ProofWindowSeconds = 30, 10
		profile.Lanes.Normal.RetainedSeconds = 240
		profile.Lanes.Resolution.RetainedSeconds = 240
		profile.Lanes.CaptureRetainedSeconds = 300
	}
	return profile
}

// installedFocusCapacityRecords is the current focus' records per account
// and normal-lane records (before the keep run's multiplier).
func installedFocusCapacityRecords() (records, normal int64) {
	// The manual profile journey reserves 48 evidence objects for four captures
	// plus history, deriving 12 protocol records. Qualify those records upfront;
	// its single pprof summary still charges ten conservative read-work units.
	records = int64(8)
	if installedLogsFocus() {
		records = installedLogsQueryUnits * installedKeptRuns() // one focus run; a keep run funds its reruns
	}
	if installedJourneyFocus() == "manual-raw" {
		// Two summaries (4 units) plus two independently paid packet queries
		// (8 units) fit an originally accepted sixteen-record backing.
		records = 16
	}
	if installedJourneyFocus() == "manual-profile" {
		records = 12
	}
	if installedJourneyFocus() == "profile-comparison" {
		records = installedProfileComparisonQueries * query.ProfileComparisonQueryUnits
	}
	// The saved-syscall journey performs five distinct paid queries, including
	// the changed-filter cursor refusal. Retiring a worker never refunds a
	// query unit. Arguments additionally funds two four-unit raw queries; the
	// metadata-only focus retains five two-unit source reads.
	if installedJourneyFocus() == "manual-syscall" || installedJourneyFocus() == "manual-arguments" {
		records = installedSyscallProjectionQueries * query.SyscallProjectionQueryUnits
		if installedJourneyFocus() == "manual-arguments" {
			records = installedArgumentQueryUnits
		}
	}
	// Every live list/open/read/update/close is one audited normal-lane
	// operation for the same human; six episodes poll roughly once a second.
	normal = 128
	if installedJourneyFocus() == "live-observation" {
		normal = 512
	}
	return records, normal
}

// installedProcessDiagnostics logs each named Deployment's Pod restarts, last
// termination and log tails. The products print fixed step names and error
// classes only, never projected file contents.
func installedProcessDiagnostics(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace string, deployments ...string) {
	t.Helper()
	c, end := context.WithTimeout(ctx, 20*time.Second)
	defer end()
	for _, name := range deployments {
		d, e := api.AppsV1().Deployments(namespace).Get(c, name, meta.GetOptions{})
		if e != nil {
			t.Log("diagnostics: deployment", name, e)
			continue
		}
		installedPodDiagnostics(t, c, api, namespace, name, meta.FormatLabelSelector(d.Spec.Selector))
	}
}

// installedPodDiagnostics logs the status and recent logs of every Pod that
// selector matches in namespace (an empty selector matches all of them).
func installedPodDiagnostics(t *testing.T, c context.Context, api kubernetes.Interface, namespace, name, selector string) {
	t.Helper()
	pods, e := api.CoreV1().Pods(namespace).List(c, meta.ListOptions{LabelSelector: selector})
	if e != nil {
		t.Log("diagnostics: pods", name, e)
		return
	}
	for _, pod := range pods.Items {
		t.Logf("diagnostics: %s pod %s phase %s", name, pod.Name, pod.Status.Phase)
		for _, s := range pod.Status.ContainerStatuses {
			reason, exit := "", int32(0)
			if x := s.LastTerminationState.Terminated; x != nil {
				reason, exit = x.Reason, x.ExitCode
			}
			currentTermination := "unobserved"
			if x := s.State.Terminated; x != nil {
				currentTermination = fmt.Sprintf("reason=%q exit=%d", x.Reason, x.ExitCode)
			}
			t.Logf("diagnostics: %s pod %s container %s ready %v restarts %d last %q exit %d current termination %s", name, pod.Name, s.Name, s.Ready, s.RestartCount, reason, exit, currentTermination)
			for _, previous := range []bool{true, false} {
				logs, e := api.CoreV1().Pods(namespace).GetLogs(pod.Name, &core.PodLogOptions{Container: s.Name, Previous: previous, Timestamps: true, TailLines: ptr.To(int64(400)), LimitBytes: ptr.To(int64(65536))}).DoRaw(c)
				if e == nil && len(logs) > 0 {
					t.Logf("diagnostics: %s previous=%v log:\n%s", pod.Name, previous, logs)
				}
			}
		}
	}
}

// installedHubRestarts returns each running hub container's restart count
// and whether all of them are Ready.
func installedHubContainers(ctx context.Context, api kubernetes.Interface, namespace string) (map[string]int32, bool, error) {
	pods, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{})
	if err != nil {
		return nil, false, err
	}
	out, ready := map[string]int32{}, true
	for _, pod := range pods.Items {
		if pod.Status.Phase == core.PodSucceeded || pod.Status.Phase == core.PodFailed {
			continue
		}
		for _, c := range pod.Status.ContainerStatuses {
			out[pod.Name+"/"+c.Name] = c.RestartCount
			ready = ready && c.Ready
		}
	}
	return out, ready && len(out) > 0, nil
}

// installedContextStandbyWindow waits until the hub-api container has run for
// 35 s since its last start. A regional connector whose context standby was
// refused at TLS by the replaced process reopens 30 s later (openingRetry), so
// before that the hub has no idle standby to route a preview to. The full
// chain's minutes of discovery cover this; the fast fixture's enrollment
// returns within seconds of the join's hub-api restart.
func installedContextStandbyWindow(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, deployment string) {
	t.Helper()
	d, err := api.AppsV1().Deployments(namespace).Get(ctx, deployment, meta.GetOptions{})
	if err != nil {
		t.Fatal("hub-api deployment", err)
	}
	for until := time.Now().Add(2 * time.Minute); ; time.Sleep(installedPoll) {
		pods, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: meta.FormatLabelSelector(d.Spec.Selector)})
		var started time.Time
		if err == nil && len(pods.Items) == 1 && len(pods.Items[0].Status.ContainerStatuses) == 1 {
			if r := pods.Items[0].Status.ContainerStatuses[0].State.Running; r != nil && pods.Items[0].Status.ContainerStatuses[0].Ready {
				started = r.StartedAt.Time
			}
		}
		if !started.IsZero() && time.Since(started) >= 35*time.Second {
			t.Logf("hub-api running %s since its last start; the regional context standby had its reopening interval", time.Since(started).Round(time.Second))
			return
		}
		if time.Now().After(until) {
			t.Fatal("hub-api did not stay running for the context standby's reopening interval", err)
		}
	}
}

func installedHubRestarts(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace string) map[string]int32 {
	t.Helper()
	before, _, err := installedHubContainers(ctx, api, namespace)
	if err != nil {
		t.Fatal("hub Pods", err)
	}
	return before
}

// installedHubSettled waits until every hub container has been Ready for
// 20 s without another restart, and logs which ones restarted since before.
func installedHubSettled(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace string, before map[string]int32) {
	t.Helper()
	var since time.Time
	var last map[string]int32
	start := time.Now()
	for until := start.Add(5 * time.Minute); ; time.Sleep(installedPoll) {
		current, ready, err := installedHubContainers(ctx, api, namespace)
		if err != nil || !ready || !maps.Equal(current, last) {
			since = time.Time{}
		} else if since.IsZero() {
			since = time.Now()
		}
		last = current
		if !since.IsZero() && time.Since(since) >= 20*time.Second {
			var restarted []string
			for name, n := range current {
				if n != before[name] {
					restarted = append(restarted, fmt.Sprintf("%s +%d", name, n-before[name]))
				}
			}
			sort.Strings(restarted)
			t.Logf("installed journey: hub processes settled %s after re-activation (Ready for the last 20 s); restarted: %v", time.Since(start).Round(time.Second), restarted)
			return
		}
		if time.Now().After(until) {
			t.Fatal("hub processes did not settle after the PostgreSQL restart", err)
		}
	}
}

// waitInstalledPublisherSettled waits until the publisher's running container
// started after the cluster catalog's last change, so no catalog restart is
// pending.
func waitInstalledPublisherSettled(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, installation string) {
	t.Helper()
	for until := time.Now().Add(2 * time.Minute); ; time.Sleep(installedPoll) {
		changed := time.Time{}
		if cm, err := api.CoreV1().ConfigMaps(namespace).Get(ctx, contracts.OwnerClusterCatalogName(installation), meta.GetOptions{}); err == nil {
			changed = cm.CreationTimestamp.Time
			for _, m := range cm.ManagedFields {
				if m.Time != nil && m.Time.After(changed) {
					changed = m.Time.Time
				}
			}
		}
		pods, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{})
		if err == nil && !changed.IsZero() {
			for _, p := range pods.Items {
				if p.DeletionTimestamp != nil || !strings.HasPrefix(p.Name, contracts.PublisherName(installation)+"-") {
					continue
				}
				for _, c := range p.Status.ContainerStatuses {
					if c.Ready && c.State.Running != nil && c.State.Running.StartedAt.After(changed) {
						return
					}
				}
			}
		}
		if time.Now().After(until) {
			// An unchanged-content catalog write restarts nothing.
			t.Log("publisher started before the last catalog write; continuing", changed)
			return
		}
	}
}
