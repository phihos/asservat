package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Order constraints within one run. These focuses leave the installation in
// a state no later focus may start from: the policy focuses scale the
// workload and break its readiness probe, policy-recording disables its
// creator in Keycloak, and live-observation enables live reads and
// re-enrolls the owner. The first-only focuses check installation-wide
// counts (journey's capture count, browser's grant state, share's
// list_shares lengths), so they run before any other focus.
//
// At most one focus per run may add an automation AccessBinding for the
// workload: WorkloadDelegation (FindAutomationBases) counts every recorded
// automation basis of the workload, including those of deleted bindings
// whose assignments are retired, and denies activation when it finds two
// (measured: native runs 42490633243 and 42490635112, which reached the
// teardown with a retired binding still counted).
var (
	installedLastFoci       = []string{"policy", "alert", "logresource", "policy-recording", "live-observation"}
	installedFirstFoci      = []string{"journey", "browser", "share"}
	installedAutomationFoci = []string{"policy", "alert", "logresource", "policy-recording", "policy-arguments", "policy-profile", "live-observation", "ongoing-save", "ongoing-save-disk", "ongoing-incident", "ongoing-syscall", "ongoing-mixed"}
)

// Several installed focuses in one run (ASSERVAT_JOURNEY_FOCUS=a,b,c): one
// bootstrap, then each focus in sequence as its own subtest of
// installer-continuation, on the same installation. Every focus keeps its own
// checks; only the bootstrap is shared, so the listed focuses must configure
// the same bootstrap (installedFocusBootstrapSignature). The capacity and
// identity budgets that each focus sizes for itself add up, so no focus runs
// on what an earlier one left of its budget. A later focus does not start
// after a failure: the installation may hold the failed focus' state.

// installedJourneyFoci is ASSERVAT_JOURNEY_FOCUS in run order.
func installedJourneyFoci() []string {
	value := os.Getenv("ASSERVAT_JOURNEY_FOCUS")
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

// installedFocusCurrent is the focus whose subtest is running (or which
// installedEachFocus evaluates); empty otherwise.
var installedFocusCurrent string

// installedProcessingInitialized records that this test process initialized
// processing (ADR-210: once per installation).
var installedProcessingInitialized bool

// installedFocusCount is the number of listed focuses, at least one.
func installedFocusCount() int64 {
	return max(1, int64(len(installedJourneyFoci())))
}

// installedFundedRuns is how many focus runs the synthetic identity and
// resolution budgets fund: every listed focus, times the keep run's reruns.
func installedFundedRuns() int64 { return installedKeptRuns() * installedFocusCount() }

// installedEachFocus calls fn once per listed focus with that focus current
// (once with the single focus otherwise).
func installedEachFocus(fn func()) {
	foci := installedJourneyFoci()
	if len(foci) <= 1 {
		fn()
		return
	}
	saved := installedFocusCurrent
	defer func() { installedFocusCurrent = saved }()
	for _, focus := range foci {
		installedFocusCurrent = focus
		fn()
	}
}

// installedAnyFocus reports whether focus is listed.
func installedAnyFocus(focus string) bool {
	return installedAnyFocusMatch(func() bool { return installedJourneyFocus() == focus })
}

// installedAnyFocusMatch reports whether match holds for any listed focus.
func installedAnyFocusMatch(match func() bool) bool {
	any := false
	installedEachFocus(func() { any = any || match() })
	return any
}

// installedFocusBootstrap is everything the shared bootstrap derives from the
// focus and keeps for the whole installation. Fields here must be equal for
// every listed focus. Not compared: the per-focus budgets that add up
// (nativeCapacityProfile, installedRegionalContextReserve, identity limits)
// and the additive fixture parts installed when any focus needs them, which
// change nothing another focus checks: the in-cluster Alertmanager (alert),
// metrics-server and the idle signal workload command (logresource), the
// second release image (upgrade), the hub-worker crash before the regional
// install (restart), the evidence-owner role (share, browser; a policy focus'
// automation binding grants it anyway), the CPU profile workload and its
// endpoints (policy-profile; packet focuses mark closed ports, not the
// application), and the collector's ring disk (ongoing-save-disk) and live
// processing values (live-observation and ongoing-incident).
type installedFocusBootstrap struct {
	FastFixture, RegionalInstallerChecks bool
	Clusters                             int
	Recording, Logs, NativePaced         bool
	TLSProfile                           bool
	Approvals                            *contracts.IdentityApprovals
	ConsoleScopes                        []string
	SystemObjects, BurstObjects          int64
	PoolObjects                          int64
}

func installedFocusBootstrapSignature() string {
	system, burst := installedCapacityObjectPartitions()
	signature, _ := json.Marshal(installedFocusBootstrap{
		FastFixture: installedFastFixture(), RegionalInstallerChecks: installedRegionalInstallerChecks(1),
		Clusters: installedClusterCount(), Recording: installedRecordingFocus(), Logs: installedLogsFocus(),
		NativePaced: installedJourneyFocus() == "native-paced", TLSProfile: installedProfileFocus() && installedTLSProfileTransport(),
		Approvals: installedIdentityApprovals(), ConsoleScopes: installedConsoleScopes(),
		SystemObjects: system, BurstObjects: burst, PoolObjects: installedPoolCapacityObjects()})
	return string(signature)
}

// installedFocusGroupError names the first listed focus whose bootstrap
// differs from the first focus' bootstrap, or the focus that never shares.
func installedFocusGroupError() error {
	foci := installedJourneyFoci()
	if len(foci) <= 1 {
		return nil
	}
	seen := map[string]bool{}
	var first string
	var failure error
	index, automation := -1, ""
	installedEachFocus(func() {
		focus := installedJourneyFocus()
		index++
		switch {
		case failure != nil:
		case slices.Contains(installedAutomationFoci, focus) && automation != "":
			failure = fmt.Errorf("focus %q and %q both add an automation binding for the workload", automation, focus)
		case seen[focus]:
			failure = fmt.Errorf("focus %q listed twice", focus)
		case focus == "chain" || focus == "clusters" || focus == "share-retirement" || focus == "":
			failure = fmt.Errorf("focus %q needs its own installation", focus)
		case slices.Contains(installedLastFoci, focus) && index != len(foci)-1:
			failure = fmt.Errorf("focus %q must run last", focus)
		case slices.Contains(installedFirstFoci, focus) && index != 0:
			failure = fmt.Errorf("focus %q must run first", focus)
		case first == "":
			first = installedFocusBootstrapSignature()
		case installedFocusBootstrapSignature() != first:
			failure = fmt.Errorf("focus %q needs another bootstrap than %q: %s, not %s", focus, foci[0], installedFocusBootstrapSignature(), first)
		}
		seen[focus] = true
		if slices.Contains(installedAutomationFoci, focus) {
			automation = focus
		}
	})
	return failure
}

// installedIdentityApprovals is the installation's approval setting for the
// current focus.
func installedIdentityApprovals() *contracts.IdentityApprovals {
	if !installedRecordingFocus() && !installedLogsFocus() {
		return nil
	}
	// Real fresh password authentication at the reference provider's LoA1;
	// this fixture does not configure or claim MFA/LoA2.
	return &contracts.IdentityApprovals{RequireRecordingApproval: installedJourneyFocus() != "policy-recording" && installedJourneyFocus() != "policy-arguments" && installedJourneyFocus() != "policy-profile" && !installedOngoingFocus(), StepUp: &contracts.IdentityStepUp{ACRValues: []string{"1"}, MaxAgeSeconds: 300}}
}

// installedFocusIsolation is what the teardown between two focuses needs:
// the installation's SQL and root, the runner's hub access (the actor that
// created the focus' AccessBindings), the developer's MCP access and the
// shared regional workload.
type installedFocusIsolation struct {
	SQL                 *pgxpool.Pool
	Root                string
	Hub                 rest.Interface
	Base                string
	Identity            *installedIdentity
	PublicRoot          []byte
	Address, Origin     string
	Region              kubernetes.Interface
	Namespace, Workload string
}

// installedFocusObjects are the hub namespace's AccessBindings by name.
type installedFocusObjects map[string]bool
