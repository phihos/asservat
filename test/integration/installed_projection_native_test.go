package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func installedApprovedScopes(scope string) bool {
	scopes := strings.Fields(scope)
	return slices.Contains(scopes, "evidence:read") && !slices.Contains(scopes, "evidence:download") && !slices.Contains(scopes, "evidence:capture")
}

type installedProjectionCheck func(artifactID string) func(queryID, operationID string) func()

// Operator-only readback proves that the approved path did not create a dummy
// native session, used one original query worker and consumed actual key slots.
// It supplies no runtime input, grants or product authority.
func installedProjectionSQLCheck(t *testing.T, ctx context.Context, admin *pgxpool.Pool, api kubernetes.Interface, root string) installedProjectionCheck {
	return func(artifact string) func(string, string) func() {
		t.Helper()
		countDownloads := func() int {
			t.Helper()
			var n int
			if err := admin.QueryRow(ctx, "SELECT count(*) FROM artifact_download WHERE root_id=$1 AND artifact_id=$2", root, artifact).Scan(&n); err != nil {
				t.Fatal("approved-only download count", err)
			}
			return n
		}
		before := countDownloads()
		return func(handle, operation string) func() {
			t.Helper()
			if countDownloads() != before {
				t.Fatal("read-only approved workflow created a native download session")
			}
			if operation == "" {
				return nil
			} // acknowledged scoped denial, before query admission
			limit, stop := context.WithTimeout(ctx, 10*time.Second)
			defer stop()
			for limit.Err() == nil {
				var id, worker string
				var polls, batches, workers, keys, closed int
				var active, uncertain bool
				err := admin.QueryRow(limit, `SELECT q.id::text,q.worker_id::text,q.polls,q.generation,q.active_batch IS NOT NULL,q.uncertain,
     (SELECT count(*) FROM download_worker w WHERE w.query_id=q.id AND w.session_id IS NULL AND w.id=q.worker_id AND w.binding_json IS NOT NULL),
     (SELECT count(*) FROM context_query_key_binding k WHERE k.query_id=q.id AND k.used_roles=7),
     (SELECT count(*) FROM context_query_batch b WHERE b.query_id=q.id AND b.closed AND b.native_closed)
     FROM context_query q WHERE q.root_id=$1 AND q.operation_id=$2 AND q.query->'Scope'->>'ArtifactID'=$3`, root, operation, artifact).Scan(&id, &worker, &polls, &batches, &active, &uncertain, &workers, &keys, &closed)
				if err == nil && (handle == "" || id == handle) && worker != "" && workers == 1 && polls <= 4 && batches >= 1 && batches <= 2 && keys == batches && closed == batches && !active && !uncertain {
					t.Logf("installed approved query: one exact shared worker, %d paid poll(s), %d joined batch(es), three consumed key roles per batch; no native session", polls, batches)
					var intent query.ContextProjectionWorkerIntent
					var observed value.AcquisitionWorker
					var rawIntent, rawJob, rawBinding []byte
					err = admin.QueryRow(limit, `SELECT intent_json,job_json,binding_json FROM download_worker WHERE root_id=$1 AND query_id=$2 AND id=$3 AND session_id IS NULL`, root, id, worker).Scan(&rawIntent, &rawJob, &rawBinding)
					if err != nil || json.Unmarshal(rawIntent, &intent) != nil || !intent.Valid() || intent.Query.ID != id || intent.Worker.ID != worker ||
						json.Unmarshal(rawJob, &observed.Job) != nil || json.Unmarshal(rawBinding, &observed.Binding) != nil {
						t.Fatal("approved query worker identity readback", err)
					}
					observed.Intent = intent.Worker
					if !observed.Valid() {
						t.Fatal("approved query worker binding unavailable")
					}
					// The next two native sessions share the unchanged two-worker
					// limit. Wait for this original worker to end (exit or Job
					// deadline kill) before their demand cleanup; no fixture
					// mutation releases its slot.
					if err = installedProjectionWaitTerminal(ctx, api, observed); err != nil {
						t.Fatal("approved query worker did not terminate", err)
					}
					return func() {
						t.Helper()
						read, end := context.WithTimeout(ctx, 5*time.Second)
						defer end()
						var retired bool
						err := admin.QueryRow(read, `SELECT termination_json IS NOT NULL AND retired_proof_json IS NOT NULL AND abandoned_at IS NULL FROM download_worker WHERE root_id=$1 AND query_id=$2 AND id=$3 AND session_id IS NULL`, root, id, worker).Scan(&retired)
						if err != nil || !retired {
							t.Fatal("native preparation did not retain positive query-worker retirement", err)
						}
						t.Log("installed query worker: original lifetime ended, exact Job/Pod terminated, product demand cleanup retained positive retirement before Stop")
					}
				}
				if installedJourneyPause(limit, 100*time.Millisecond) != nil {
					break
				}
			}
			t.Fatal("approved response lacked exact joined SQL worker/key/batch readback")
			return nil
		}
	}
}

// This adds at most six audited normal operations: one scoped denial, one
// get_file_excerpt and four already-budgeted result polls. Existing normal64 /
// resolution8 fixture allocations are unchanged; no unknown call is replayed.
func installedApprovedProjection(t *testing.T, ctx context.Context, identity *installedIdentity, transport http.RoundTripper, origin, caseID, artifactID, pod string, expires time.Time, check installedProjectionCheck) (query.ContextExcerpt, func()) {
	t.Helper()
	if check == nil {
		t.Fatal("approved projection requires independent SQL readback")
	}
	verify := check(artifactID)
	source := identity.approvedTokenSource(origin)
	if _, err := source.Token(ctx); err != nil {
		t.Fatal("real approved-only OAuth session", err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-approved-journey", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, source.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal("approved-only MCP session", err)
	}
	defer session.Close()
	call := func(name string, args any) installedJourneyEnvelope {
		t.Helper()
		result, e := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if e != nil {
			t.Fatal("approved operation outcome unavailable; no replay", name, e)
		}
		var out installedJourneyEnvelope
		raw, e := json.Marshal(result.StructuredContent)
		if e != nil || wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil || result.IsError != (out.Status == "error") {
			t.Fatal("approved operation response contract", name)
		}
		return out
	}
	denied := call("prepare_artifact_download", map[string]string{"artifact_id": artifactID, "idempotency_key": "approved-only-download-denied"})
	if denied.Status != "error" {
		t.Fatal("read-only OAuth session obtained download preparation")
	}
	verify("", "")
	result := call("get_file_excerpt", map[string]any{"case_id": caseID, "artifact_id": artifactID, "line_start": 1, "max_lines": 14})
	originalOperation := result.RequestID
	originalHandle := ""
	var firstObserved, until time.Time
	for poll := 0; result.Status == "pending"; poll++ {
		var pending struct {
			Handle   string    `json:"query_handle"`
			Retry    int       `json:"retry_after_seconds"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
		}
		if installedJourneyDecode(result.Data, &pending) != nil || pending.Handle == "" || pending.Retry < 1 || pending.Observed.IsZero() || pending.Expires.IsZero() || pending.Expires.After(expires) {
			t.Fatal("invalid pending approved query")
		}
		if poll == 0 {
			originalHandle, firstObserved, until = pending.Handle, pending.Observed, pending.Expires
		}
		if pending.Handle != originalHandle || !pending.Expires.Equal(until) || poll >= 4 {
			t.Fatal("approved query changed identity/lifetime or exhausted original poll allowance")
		}
		next, err := installedProjectionPollTime(firstObserved, until, time.Now(), time.Duration(pending.Retry)*time.Second, poll)
		if err != nil {
			t.Fatal(err)
		}
		if installedJourneyPause(ctx, time.Until(next)) != nil {
			t.Fatal("approved poll canceled", ctx.Err())
		}
		result = call("get_query_result", map[string]string{"query_handle": originalHandle})
	}
	if result.Status != "ok" {
		t.Fatal("approved query did not return content", result.Status)
	}
	var excerpt query.ContextExcerpt
	if originalHandle != "" {
		var resolved struct {
			Handle string                   `json:"query_handle"`
			Tool   string                   `json:"tool_name"`
			Result installedJourneyEnvelope `json:"result"`
		}
		if installedJourneyDecode(result.Data, &resolved) != nil || resolved.Handle != originalHandle || resolved.Tool != "get_file_excerpt" || resolved.Result.Status != "ok" || installedJourneyDecode(resolved.Result.Data, &excerpt) != nil {
			t.Fatal("approved result changed original handle/tool")
		}
	} else if installedJourneyDecode(result.Data, &excerpt) != nil {
		t.Fatal("immediate approved result")
	}
	quoted, _ := json.Marshal(pod)
	if excerpt.LogicalPath != query.ContextLogicalPath || excerpt.LineStart != 1 || len(excerpt.Lines) != 14 || excerpt.Lines[2] != "podUID: "+string(quoted) {
		t.Fatal("approved result is not the exact selected Pod's fixed projection")
	}
	retired := verify(originalHandle, originalOperation)
	if retired == nil {
		t.Fatal("approved query lacks its exact worker retirement check")
	}
	t.Log("installed journey: real read-only OAuth scope received approved pod-status content through shared acquisition; native-download scope was absent and preparation refused")
	return excerpt, retired
}

// This fixture wait observes exact admitted objects only. Product cleanup still
// constructs and persists its own termination and deletion proofs afterward.
func installedProjectionWaitTerminal(ctx context.Context, api kubernetes.Interface, w value.AcquisitionWorker) error {
	if ctx == nil || api == nil || !w.Valid() {
		return errors.New("invalid approved worker observation")
	}
	wait, end := context.WithDeadline(ctx, w.Intent.RunUntil.Add(30*time.Second))
	defer end()
	if err := installedJourneyPause(wait, time.Until(w.Intent.RunUntil)); err != nil {
		return err
	}
	for wait.Err() == nil {
		job, err := api.BatchV1().Jobs(w.Binding.Namespace).Get(wait, w.Binding.Job, meta.GetOptions{})
		jobGone := apierrors.IsNotFound(err)
		if err != nil && !jobGone {
			return err
		}
		pod, err := api.CoreV1().Pods(w.Binding.Namespace).Get(wait, w.Binding.Pod, meta.GetOptions{})
		podGone := apierrors.IsNotFound(err)
		if err != nil && !podGone {
			return err
		}
		if podGone {
			pod = nil
		}
		if err = wait.Err(); err != nil {
			return err
		}
		// Both objects gone means product cleanup already retired the worker;
		// the caller's SQL readback still requires its positive retirement.
		// A Job deleted while its Pod remains is not terminal evidence.
		if jobGone && podGone {
			return nil
		}
		if !jobGone && installedProjectionWorkerTerminal(w, job, pod, time.Now()) {
			return nil
		}
		if err := installedJourneyPause(wait, 250*time.Millisecond); err != nil {
			return err
		}
	}
	return wait.Err()
}

// A nil Pod means NotFound: the Job controller removed it (native90:
// activeDeadlineSeconds). Only the exact Job's accounted terminal record, as
// product termination requires, makes that absence terminal.
func installedProjectionWorkerTerminal(w value.AcquisitionWorker, job *batch.Job, pod *core.Pod, now time.Time) bool {
	if job == nil || now.Before(w.Intent.RunUntil) || job.Namespace != w.Binding.Namespace || job.Name != w.Binding.Job || string(job.UID) != w.Binding.JobUID {
		return false
	}
	if pod == nil {
		return kube.WorkerJobReleasedPods(job)
	}
	if pod.Namespace != w.Binding.Namespace || pod.Name != w.Binding.Pod || string(pod.UID) != w.Binding.PodUID ||
		(pod.Status.Phase != core.PodSucceeded && pod.Status.Phase != core.PodFailed) || len(pod.Status.ContainerStatuses) != 1 {
		return false
	}
	owner := meta.GetControllerOf(pod)
	if owner == nil || owner.APIVersion != "batch/v1" || owner.Kind != "Job" || owner.Name != job.Name || owner.UID != job.UID {
		return false
	}
	terminal := false
	for _, c := range job.Status.Conditions {
		terminal = terminal || (c.Type == batch.JobComplete || c.Type == batch.JobFailed) && c.Status == core.ConditionTrue
	}
	status := pod.Status.ContainerStatuses[0]
	finished := status.State.Terminated
	return terminal && status.Name == "acquisition" && finished != nil && !finished.FinishedAt.IsZero() && !finished.FinishedAt.After(now) && finished.ContainerID != "" && finished.Reason != "ContainerStatusUnknown" && finished.Reason != "NodeLost"
}

// Spread the original four paid polls across the fixed query lifetime instead
// of spending them immediately while a cold Pod starts. Server not-before wins;
// an expired or incompatible schedule refuses, never renews the query.
func installedProjectionPollTime(start, until, now time.Time, retry time.Duration, poll int) (time.Time, error) {
	if start.IsZero() || !start.Before(until) || now.Before(start) || !now.Before(until) || retry <= 0 || poll < 0 || poll >= 4 {
		return time.Time{}, errors.New("invalid approved query poll bound")
	}
	next := start.Add(until.Sub(start) * time.Duration(poll+1) / 5)
	if floor := now.Add(retry); floor.After(next) {
		next = floor
	}
	if !next.Before(until) {
		return time.Time{}, errors.New("approved poll cannot fit original query lifetime")
	}
	return next, nil
}

func installedProjectionMatchesNative(excerpt query.ContextExcerpt, native []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(native, &fields) != nil {
		return errors.New("invalid native context")
	}
	names := []string{"format", "namespaceUID", "podUID", "resourceVersion", "observedAt", "phase", "ready", "initialized", "scheduled", "runtimeInstances", "running", "waiting", "terminated", "restarts"}
	if len(fields) != len(names) {
		return errors.New("native context field set changed")
	}
	expected := make([]string, 0, len(names))
	for _, name := range names {
		raw, ok := fields[name]
		if !ok {
			return errors.New("native context lacks fixed field")
		}
		var decoded any
		if json.Unmarshal(raw, &decoded) != nil {
			return errors.New("native context field invalid")
		}
		if name == "observedAt" {
			var observed time.Time
			if json.Unmarshal(raw, &observed) != nil {
				return errors.New("native observation invalid")
			}
			decoded = observed.UTC().Format(time.RFC3339Nano)
		}
		encoded, err := json.Marshal(decoded)
		if err != nil {
			return err
		}
		expected = append(expected, fmt.Sprintf("%s: %s", name, encoded))
	}
	if excerpt.LogicalPath != query.ContextLogicalPath || excerpt.LineStart != 1 || !reflect.DeepEqual(excerpt.Lines, expected) {
		return errors.New("approved content differs from the exact native evidence")
	}
	return nil
}
