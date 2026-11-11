package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/capture"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// installedFocusKeySuffix keeps a fixed idempotency key or result file name
// of a code path that several listed focuses share apart: empty for a single
// focus (inputs unchanged), "-<focus>" in a multi-focus run.
func installedFocusKeySuffix() string {
	if len(installedJourneyFoci()) <= 1 {
		return ""
	}
	return "-" + installedJourneyFocus()
}

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

// installedRunFoci runs body once for the single focus, or once per listed
// focus, each as its own subtest named after it with its own watchdog. It
// stops after the first failed focus. Between focuses it removes the
// policies and automation bindings the finished focus added
// (installedFocusTeardown).
func installedRunFoci(t *testing.T, ctx context.Context, iso installedFocusIsolation, body func(*testing.T)) {
	t.Helper()
	foci := installedJourneyFoci()
	if len(foci) <= 1 {
		body(t)
		return
	}
	for i, focus := range foci {
		var before installedFocusObjects
		if i+1 < len(foci) {
			before, _ = installedFocusBindings(t, ctx, iso)
		}
		installedFocusCurrent = focus
		started := time.Now()
		passed := t.Run(focus, func(t *testing.T) {
			installedFocusHangWatchdog(t, focus)
			body(t)
		})
		installedFocusCurrent = ""
		t.Logf("installed focus %q (%d of %d) %s in %s", focus, i+1, len(foci), map[bool]string{true: "passed", false: "failed"}[passed], time.Since(started).Round(time.Second))
		if !passed {
			if rest := foci[i+1:]; len(rest) > 0 {
				t.Logf("installed focuses %v not run: %q failed and may have left its state behind", rest, focus)
			}
			return
		}
		if i+1 < len(foci) {
			installedFocusTeardown(t, ctx, iso, before, focus, foci[i+1])
		}
	}
}

// installedFocusTriggerNeed is how many shared workload trigger tokens a
// focus spends at most: its automation binding's maxExecutions for the
// finite policy focuses, one HTTP Save for live-observation's policy
// episodes and none for its manual ones, the full burst otherwise.
func installedFocusTriggerNeed(focus string) int {
	switch focus {
	case "live-observation":
		if os.Getenv("ASSERVAT_LIVE_EPISODES") == "manual" {
			return 0
		}
		return 1
	case "policy-arguments", "policy-profile":
		return 1
	}
	return capture.WorkloadTriggerBurst
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

func installedFocusBindings(t *testing.T, ctx context.Context, iso installedFocusIsolation) (installedFocusObjects, map[string]string) {
	t.Helper()
	raw, err := iso.Hub.Get().AbsPath(iso.Base + "accessbindings").DoRaw(ctx)
	var list struct {
		Items []struct {
			Metadata struct{ Name, UID string } `json:"metadata"`
		} `json:"items"`
	}
	if err != nil || json.Unmarshal(raw, &list) != nil {
		t.Fatal("multi-focus binding list", err)
	}
	names, uids := installedFocusObjects{}, map[string]string{}
	for _, item := range list.Items {
		names[item.Metadata.Name] = true
		uids[item.Metadata.Name] = item.Metadata.UID
	}
	return names, uids
}

// installedFocusTeardown returns the installation to the state a fresh
// focus starts from, as far as one focus can change it for the next: the
// policies it activated are deactivated (the product admits one automation
// binding per workload and one expensive action at a time), every recording
// source has ended and released its slot, the AccessBindings it added are
// gone from the accepted permission projection, the workload's shared
// trigger budget is full again and the workload is available. Evidence,
// audit and spend stay, as they would in any installation.
func installedFocusTeardown(t *testing.T, ctx context.Context, iso installedFocusIsolation, before installedFocusObjects, after, next string) {
	t.Helper()
	started := time.Now()
	wait := func(what string, limit time.Duration, done func(context.Context) (bool, error)) {
		t.Helper()
		call, stop := context.WithTimeout(ctx, limit)
		defer stop()
		var last error
		for {
			ok, err := done(call)
			if ok && err == nil {
				return
			}
			last = err
			if installedJourneyPause(call, time.Second) != nil {
				t.Fatalf("multi-focus teardown after %q: %s not reached in %s (%v)", after, what, limit, last)
			}
		}
	}
	// 1. Deactivate the active policies through the product, as their user.
	var active []string
	rows, err := iso.SQL.Query(ctx, `SELECT s.name FROM policy_source s JOIN policy_acceptance a ON a.id=s.active_id AND a.root_id=s.root_id
WHERE s.root_id=$1 AND NOT s.deleted AND (a.record#>>'{Authority,NotAfter}')::timestamptz>clock_timestamp() ORDER BY s.name`, iso.Root)
	if err == nil {
		for rows.Next() {
			var name string
			if err = rows.Scan(&name); err != nil {
				break
			}
			active = append(active, name)
		}
		rows.Close()
		err = errors.Join(err, rows.Err())
	}
	if err != nil {
		t.Fatal("multi-focus active policies", err)
	}
	if len(active) > 0 {
		installedFocusDeactivate(t, ctx, iso, active, after)
	}
	// 2. Every recording source ended and released its expensive slot.
	wait("ended recording sources", 3*time.Minute, func(c context.Context) (bool, error) {
		var open int
		err := iso.SQL.QueryRow(c, `SELECT count(*) FROM policy_recording_source WHERE root_id=$1 AND (ended_at IS NULL OR slot_released_at IS NULL)`, iso.Root).Scan(&open)
		return open == 0, err
	})
	// 3. The focus' AccessBindings are gone from the API and the projection.
	current, uids := installedFocusBindings(t, ctx, iso)
	var removed, removedUIDs []string
	for name := range current {
		if before[name] {
			continue
		}
		if err := iso.Hub.Delete().AbsPath(iso.Base + "accessbindings/" + name).Do(ctx).Error(); err != nil {
			t.Fatal("multi-focus binding removal", name, err)
		}
		removed, removedUIDs = append(removed, name), append(removedUIDs, uids[name])
	}
	if len(removedUIDs) > 0 {
		// Basis rows stay as history; the removal retires their assignments.
		wait("removed bindings retired", 2*time.Minute, func(c context.Context) (bool, error) {
			var left int
			err := iso.SQL.QueryRow(c, `SELECT count(*) FROM permission_assignment a JOIN permission_basis b ON a.stream_id=b.stream_id AND a.basis_key=b.basis_key
WHERE b.uid=ANY($1) AND a.retired_at IS NULL`, removedUIDs).Scan(&left)
			return left == 0, err
		})
	}
	// 4. The workload's shared policy trigger budget (one occurrence per
	// five minutes, burst two; policy_uid '') holds what the next focus
	// spends, as on a fresh installation.
	need := installedFocusTriggerNeed(next)
	slack := time.Duration(capture.WorkloadTriggerBurst-need) * capture.WorkloadTriggerInterval
	wait(fmt.Sprintf("%d trigger budget tokens", need), 11*time.Minute, func(c context.Context) (bool, error) {
		var available bool
		err := iso.SQL.QueryRow(c, `SELECT coalesce(max(tat),clock_timestamp())<=clock_timestamp()+make_interval(secs=>$2) FROM policy_workload_window WHERE root_id=$1 AND policy_uid=''`, iso.Root, slack.Seconds()).Scan(&available)
		return available, err
	})
	// 5. The shared workload is available again (a focus may restart it).
	wait("available workload", 2*time.Minute, func(c context.Context) (bool, error) {
		d, err := iso.Region.AppsV1().Deployments(iso.Namespace).Get(c, iso.Workload, meta.GetOptions{})
		if err != nil {
			return false, err
		}
		want := int32(1)
		if d.Spec.Replicas != nil {
			want = *d.Spec.Replicas
		}
		return d.Status.ObservedGeneration >= d.Generation && d.Status.UpdatedReplicas == want && d.Status.AvailableReplicas == want && d.Status.Replicas == want, nil
	})
	t.Logf("multi-focus teardown after %q in %s: deactivated policies %v, removed bindings %v", after, time.Since(started).Round(time.Second), active, removed)
}

// installedFocusDeactivate deactivates the named policies over MCP as the
// developer; deactivate_policy is idempotent.
func installedFocusDeactivate(t *testing.T, ctx context.Context, iso installedFocusIsolation, names []string, after string) {
	t.Helper()
	if iso.Identity == nil {
		t.Fatal("multi-focus teardown needs the harness identity provider")
	}
	cert, err := x509.ParseCertificate(iso.PublicRoot)
	if err != nil {
		t.Fatal("public listener root", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	dial := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DialContext: func(c context.Context, network, _ string) (net.Conn, error) {
		return dial.DialContext(c, network, iso.Address)
	}}
	defer transport.CloseIdleConnections()
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "multi-focus-teardown", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(iso.Origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, iso.Identity.mcpTokenSource(iso.Origin).Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal("multi-focus teardown MCP", err)
	}
	defer session.Close()
	for _, name := range names {
		arguments := map[string]string{"policy_name": name, "idempotency_key": "multi-focus-teardown-" + name}
		var failure error
		for attempt := 1; attempt <= 4; attempt++ {
			result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "deactivate_policy", Arguments: arguments})
			if err == nil {
				var reply installedJourneyEnvelope
				var code string
				if reply, code, err = installedJourneyReplyCode(wire, "deactivate_policy", result); err == nil {
					var stopped struct {
						State string `json:"state"`
					}
					if code == "" && reply.Status == "ok" && json.Unmarshal(reply.Data, &stopped) == nil && stopped.State == "deactivated" {
						failure = nil
						break
					}
					err = fmt.Errorf("status %q code %q", reply.Status, code)
				}
			}
			failure = err
			if installedJourneyPause(ctx, 2*time.Second) != nil {
				break
			}
		}
		if failure != nil {
			t.Fatalf("multi-focus teardown after %q: deactivate %s: %v", after, name, failure)
		}
	}
}
