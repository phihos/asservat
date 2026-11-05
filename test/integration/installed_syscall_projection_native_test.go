package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/client-go/rest"
)

const installedSyscallProjectionQueries = 5

// The existing worker pool admits two workers. RPCs still run sequentially and
// join their native responses; only independent terminal-lifetime inspection is
// deferred so the two original worker periods can overlap. No charge is freed
// by this bookkeeping. The next cohort's real admissions perform cleanup.
type installedSyscallProofCohort struct {
	pending                  []func() func()
	retirement               []func()
	queries, joined, retired int
}

func (c *installedSyscallProofCohort) add(t *testing.T, verify func() func()) {
	t.Helper()
	if verify == nil || len(c.pending) >= 2 || c.queries >= installedSyscallProjectionQueries {
		t.Fatal("syscall fixture exceeded its two-worker cohort or funded query count")
	}
	c.pending = append(c.pending, verify)
	c.queries++
}

func (c *installedSyscallProofCohort) flush(t *testing.T) {
	t.Helper()
	if len(c.pending) == 0 {
		return
	}
	pending, previous := c.pending, c.retirement
	c.pending = nil
	next := make([]func(), len(pending))
	defer func() { c.retirement = next }()
	// Register each proof separately: even a failing assertion/Goexit must
	// attempt the remaining known worker joins, including deferred cleanup.
	for i := len(previous) - 1; i >= 0; i-- {
		if previous[i] == nil {
			continue
		}
		defer func(check func()) { check(); c.retired++ }(previous[i])
	}
	for i := len(pending) - 1; i >= 0; i-- {
		defer func(index int, verify func() func()) {
			retirement := verify()
			if retirement == nil {
				t.Fatal("syscall query lacks joined SQL/worker/key evidence")
			}
			next[index] = retirement
			c.joined++
		}(i, pending[i])
	}
}

// This read-only observer never authorizes a worker launch or mutates a Job.
// Historical termination inspection intentionally does not consume this guard.
type installedTerminationOnlyConfiguration struct{}

func (installedTerminationOnlyConfiguration) CurrentWorkerConfiguration(context.Context, value.DownloadWorkerProfile) (time.Time, error) {
	return time.Time{}, artifact.ErrDownloadUnavailable
}

type installedStoppedDownloadCheck func(downloadID string) func()

func finishInstalledSyscallNativeDownload(downloadID string, invoke func(string, any) (installedJourneyEnvelope, string), closed installedStoppedDownloadCheck) (func(), error) {
	if !value.UUID(downloadID) || invoke == nil || closed == nil {
		return nil, errors.New("missing original native-download close composition")
	}
	reply, code := invoke("cancel_artifact_download", map[string]string{"download_id": downloadID, "idempotency_key": "syscall-native-complete-" + downloadID})
	var receipt installedJourneyStopReceipt
	if code != "" || reply.Status != "ok" || installedJourneyDecode(reply.Data, &receipt) != nil || receipt.DownloadID != downloadID || (receipt.State != "Cancelled" && receipt.State != "AlreadyTerminal") || (receipt.AuditState != "pending" && receipt.AuditState != "recorded" && receipt.AuditState != "overdue") {
		return nil, errors.New("completed native-download close was not acknowledged; no replay")
	}
	retirement := closed(downloadID)
	if retirement == nil {
		return nil, errors.New("original native-download worker has no terminal proof")
	}
	return retirement, nil
}

// Operator-only SQL/API readback observes the original download worker after a
// public Close. It changes no session, lifetime, charge or workload object. The
// next real query admission must record positive product retirement itself.
func installedStoppedDownloadSQLCheck(t *testing.T, ctx context.Context, admin *pgxpool.Pool, api *rest.Config, root, cluster string) installedStoppedDownloadCheck {
	return func(downloadID string) func() {
		t.Helper()
		var worker value.DownloadWorker
		var rawIntent, rawJob, rawBinding []byte
		var state string
		var workers int
		err := admin.QueryRow(ctx, `SELECT w.intent_json,w.job_json,w.binding_json,d.state,count(*) OVER () FROM download_worker w JOIN artifact_download d ON d.id=w.session_id AND d.root_id=w.root_id
	 WHERE w.root_id=$1 AND w.session_id=$2 AND w.query_id IS NULL AND w.retired_proof_json IS NULL`, root, downloadID).Scan(&rawIntent, &rawJob, &rawBinding, &state, &workers)
		if err != nil || workers != 1 || (state != "Cancelled" && state != "Completed") || json.Unmarshal(rawIntent, &worker.Intent) != nil || json.Unmarshal(rawJob, &worker.Job) != nil || json.Unmarshal(rawBinding, &worker.Binding) != nil || !worker.Valid() || worker.Intent.SessionID != downloadID || worker.Intent.Profile.ClusterID != cluster {
			t.Fatal("original completed native worker was not retained after public Close", err, state)
		}
		profile := worker.Intent.Profile
		client, err := kube.NewPermissionClient(api, cluster, configuration.NamespaceRef{Name: profile.Namespace, UID: profile.NamespaceUID}, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		jobs, err := kube.NewDownloadWorkerJobs(client, profile, installedTerminationOnlyConfiguration{})
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		limit, end := context.WithTimeout(ctx, 30*time.Second)
		defer end()
		for limit.Err() == nil {
			proof, err := jobs.ObserveDownloadWorkerTermination(limit, worker)
			if err == nil && proof.Valid(time.Now()) && proof.Worker == worker {
				t.Logf("installed native download Close: exact original Job/Pod terminal observed after %s; original RunUntil=%s retained, no fixture refund", time.Since(started), worker.Intent.RunUntil.UTC().Format(time.RFC3339Nano))
				return func() {
					t.Helper()
					var termination, retirement []byte
					var abandoned bool
					err := admin.QueryRow(ctx, `SELECT termination_json,retired_proof_json,abandoned_at IS NOT NULL FROM download_worker WHERE root_id=$1 AND id=$2 AND session_id=$3 AND query_id IS NULL`, root, worker.Intent.ID, downloadID).Scan(&termination, &retirement, &abandoned)
					var term value.DownloadWorkerTermination
					var retired value.DownloadWorkerRetirement
					if err != nil || abandoned || json.Unmarshal(termination, &term) != nil || json.Unmarshal(retirement, &retired) != nil || !term.Valid(term.ObservedAt) || !retired.Valid(retired.ObservedAt) || term.Worker != worker || retired.Termination.Worker != worker || !reflect.DeepEqual(term, retired.Termination) {
						t.Fatal("real query admission did not retain original native-worker positive retirement", err)
					}
					t.Log("installed native download Close: first real query admission persisted exact termination and retirement; both query-worker slots now available")
				}
			}
			if installedJourneyPause(limit, 250*time.Millisecond) != nil {
				break
			}
		}
		t.Fatal("original native-download Job/Pod did not terminate after acknowledged public Close", limit.Err())
		return nil
	}
}

// The native file already passed independent download hash and capture-source
// checks at each caller. This independent oracle does not call the production
// approved projector, and none of its values supply product authority.
func installedSyscallExpected(native []byte, nativeType, pod string) ([]artifact.SyscallMetadataEvent, []query.SyscallCount, query.SyscallRecordCounts, error) {
	var counts query.SyscallRecordCounts
	if len(native) == 0 || native[len(native)-1] != '\n' {
		return nil, nil, counts, errors.New("native syscall file is incomplete")
	}
	lines := bytes.Split(bytes.TrimSuffix(native, []byte{'\n'}), []byte{'\n'})
	if nativeType == artifact.SyscallArgumentsArtifact {
		if len(lines) < 3 {
			return nil, nil, counts, errors.New("missing native argument records")
		}
		var header artifact.ArgumentHeader
		var footer artifact.ArgumentFooter
		if json.Unmarshal(lines[0], &header) != nil || json.Unmarshal(lines[len(lines)-1], &footer) != nil || header.Record != "header" || header.PodUID != pod || footer.Record != "footer" || footer.Retained != uint64(len(lines)-2) {
			return nil, nil, counts, errors.New("native argument framing differs")
		}
		lines = lines[1 : len(lines)-1]
	} else if nativeType != artifact.SyscallRecordsArtifact {
		return nil, nil, counts, errors.New("unsupported syscall source")
	}
	events := make([]artifact.SyscallMetadataEvent, 0, len(lines))
	byName := map[string]query.SyscallCount{}
	for _, line := range lines {
		var event artifact.SyscallMetadataEvent
		if nativeType == artifact.SyscallArgumentsArtifact {
			var raw artifact.ArgumentEventLine
			if json.Unmarshal(line, &raw) != nil || raw.Record != "event" {
				return nil, nil, counts, errors.New("invalid raw native event")
			}
			e := raw.Event
			event = artifact.SyscallMetadataEvent{Identity: artifact.SyscallMetadataIdentity{ProcessRef: e.Identity.ProcessRef, ThreadRef: e.Identity.ThreadRef, PodUID: e.Identity.PodUID}, Syscall: e.Syscall, ABI: e.ABI, Timestamp: e.Timestamp, DurationNS: e.DurationNS, Outcome: e.Outcome, Errno: e.Errno}
		} else if json.Unmarshal(line, &event) != nil {
			return nil, nil, counts, errors.New("invalid metadata native event")
		}
		if !event.WellFormed() || event.Identity.PodUID != pod {
			return nil, nil, counts, errors.New("native metadata identity/shape differs")
		}
		events = append(events, event)
		counts.RecordCount++
		switch event.Outcome {
		case "unmatched":
			counts.UnmatchedEvents++
		case "unfinished":
			counts.UnfinishedEvents++
		case "unknown":
			counts.UnknownEvents++
		}
		row := byName[event.Syscall]
		row.Syscall, row.Count = event.Syscall, row.Count+1
		if event.Outcome == "error" {
			row.Errors++
		}
		if event.DurationNS != nil {
			row.PairedCount++
			row.TotalDurationNS += *event.DurationNS
		}
		byName[event.Syscall] = row
	}
	rows := make([]query.SyscallCount, 0, len(byName))
	for _, row := range byName {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Syscall < rows[j].Syscall })
	return events, rows, counts, nil
}

type installedSyscallReply struct {
	installedJourneyEnvelope
	DataClass  string `json:"data_class"`
	Next       string `json:"next_cursor"`
	Provenance []struct {
		ArtifactID string `json:"artifactID"`
		Digest     string `json:"digest"`
	} `json:"provenance"`
}

func installedSyscallFailureCode(reply installedSyscallReply) string {
	if reply.Status != "error" {
		return ""
	}
	var failure struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(reply.Data, &failure) != nil {
		return ""
	}
	return failure.Code
}

// Captured buffers can include a trailing newline or another bounded suffix.
// Forbid their actual encoding, rather than assuming base64(marker) appears
// unchanged inside base64(marker+suffix).
func installedSyscallForbidden(native []byte, marker string) ([]string, error) {
	if marker == "" {
		return nil, nil
	}
	forbidden := []string{marker, base64.StdEncoding.EncodeToString([]byte(marker))}
	found := false
	for _, line := range bytes.Split(native, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var record artifact.ArgumentEventLine
		if json.Unmarshal(line, &record) != nil {
			return nil, errors.New("invalid native argument record")
		}
		if record.Record != "event" {
			continue
		}
		for _, argument := range record.Event.Arguments {
			if !strings.HasPrefix(argument.Value, "base64:") {
				continue
			}
			encoded := strings.TrimPrefix(argument.Value, "base64:")
			decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil {
				return nil, err
			}
			if bytes.Contains(decoded, []byte(marker)) {
				found = true
				forbidden = append(forbidden, encoded, argument.Value)
			}
			clear(decoded)
		}
	}
	if !found {
		return nil, errors.New("native argument file lacks the synthetic sensitive buffer")
	}
	return forbidden, nil
}

type installedSyscallPage struct {
	Kind     string                          `json:"kind"`
	Rows     []query.SyscallCount            `json:"rows"`
	Events   []artifact.SyscallMetadataEvent `json:"events"`
	Coverage struct {
		Dropped    *uint64  `json:"dropped_events"`
		Unmatched  uint64   `json:"unmatched_events"`
		Unfinished uint64   `json:"unfinished_events"`
		Unknown    uint64   `json:"unknown_events"`
		Records    uint64   `json:"record_count"`
		Truncated  *bool    `json:"truncated"`
		Gaps       []string `json:"gaps"`
	} `json:"coverage"`
	Observed time.Time `json:"query_observed_at"`
	Expires  time.Time `json:"query_expires_at"`
}

func qualifyInstalledSyscallProjections(t *testing.T, ctx context.Context, identity *installedIdentity, transport http.RoundTripper, origin, caseID, artifactID, version, nativeType, pod string, native []byte, expires time.Time, marker string, check installedProjectionCheck, downloadRetirement func(), continuation ...installedSyscallQueryContinuation) {
	t.Helper()
	if check == nil || downloadRetirement == nil {
		t.Fatal("syscall projections require independent SQL readback")
	}
	expectedEvents, expectedRows, expectedCounts, err := installedSyscallExpected(native, nativeType, pod)
	if err != nil || len(expectedEvents) < 2 || len(expectedRows) == 0 {
		t.Fatal("native syscall oracle", err)
	}
	forbidden, err := installedSyscallForbidden(native, marker)
	if err != nil {
		t.Fatal(err)
	}
	source := identity.approvedTokenSource(origin)
	if _, err := source.Token(ctx); err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-saved-syscalls", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, source.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	call := func(name string, args any) installedSyscallReply {
		t.Helper()
		began := time.Now()
		response, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal("syscall operation outcome unavailable; no replay", name, err)
		}
		raw, err := json.Marshal(response.StructuredContent)
		var out installedSyscallReply
		if err != nil || wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil || response.IsError != (out.Status == "error") || len(raw) > query.ContextResultBytes {
			t.Fatal("syscall public response contract", name)
		}
		if marker != "" {
			for _, sensitive := range forbidden {
				if bytes.Contains(raw, []byte(sensitive)) {
					t.Fatal("synthetic credential escaped approved response", name)
				}
			}
		}
		t.Logf("installed saved syscall %s status=%s elapsed=%s", name, out.Status, time.Since(began))
		return out
	}
	deniedCheck := check(artifactID)
	if denied := call("prepare_artifact_download", map[string]string{"artifact_id": artifactID, "idempotency_key": "syscall-read-only-denied"}); denied.Status != "error" {
		t.Fatal("read-only syscall session obtained native download")
	}
	deniedCheck("", "")
	// Every worker retains its original period and conservative charge. Read
	// back terminal proofs in cohorts 1+2, 3+4 and 5 rather than serially waiting
	// one full worker lifetime after each already-joined response.
	var proofs installedSyscallProofCohort
	defer proofs.flush(t)
	if len(continuation) > 1 {
		t.Fatal("ambiguous raw syscall continuation")
	}
	rolling := len(continuation) == 1
	if rolling && (continuation[0].BeforeQuery == nil || continuation[0].RawQueries == nil) {
		t.Fatal("raw syscall continuation lacks owned pipeline")
	}
	var oldRetirements []func()
	retiredOld := 0
	retireNext := func() {
		if retiredOld >= len(oldRetirements) {
			t.Fatal("missing original fixed-view retirement")
		}
		oldRetirements[retiredOld]()
		retiredOld++
	}
	run := func(tool string, args map[string]any, wantError string) (installedSyscallReply, installedSyscallPage) {
		t.Helper()
		if proofs.queries >= installedSyscallProjectionQueries || rolling && len(oldRetirements) >= installedSyscallProjectionQueries {
			t.Fatal("syscall fixture has no prepaid query unit for another call")
		}
		if rolling {
			continuation[0].BeforeQuery()
		}
		verify := check(artifactID)
		out := call(tool, args)
		operation, handle := out.RequestID, ""
		// Queue as soon as the immutable operation is known, so a later poll or
		// assertion failure still attempts this known worker's independent join.
		if rolling {
			defer func() {
				retirement := verify(handle, operation)
				if retirement == nil {
					t.Fatal("fixed syscall result lacks live proof")
				}
				oldRetirements = append(oldRetirements, retirement)
				if len(oldRetirements) > 2 {
					retireNext()
				}
			}()
		} else {
			proofs.add(t, func() func() { return verify(handle, operation) })
			defer func() {
				if len(proofs.pending) == 2 {
					proofs.flush(t)
				}
			}()
		}
		var observed, until time.Time
		for poll := 0; out.Status == "pending"; poll++ {
			var pending struct {
				Handle   string    `json:"query_handle"`
				Retry    int       `json:"retry_after_seconds"`
				Observed time.Time `json:"query_observed_at"`
				Expires  time.Time `json:"query_expires_at"`
			}
			if json.Unmarshal(out.Data, &pending) != nil || pending.Handle == "" || pending.Retry < 1 || pending.Observed.IsZero() || !pending.Expires.After(pending.Observed) || pending.Expires.After(expires) {
				t.Fatal("invalid pending syscall query")
			}
			if poll == 0 {
				handle, observed, until = pending.Handle, pending.Observed, pending.Expires
			}
			if pending.Handle != handle || !pending.Expires.Equal(until) || poll >= 4 {
				t.Fatal("syscall query renewed original identity/deadline or polls")
			}
			next, err := installedProjectionPollTime(observed, until, time.Now(), time.Duration(pending.Retry)*time.Second, poll)
			if err != nil {
				t.Fatal(err)
			}
			if installedJourneyPause(ctx, time.Until(next)) != nil {
				t.Fatal(ctx.Err())
			}
			out = call("get_query_result", map[string]string{"query_handle": handle})
		}
		if handle != "" && out.Status == "ok" {
			var nested struct {
				Handle  string                `json:"query_handle"`
				Tool    string                `json:"tool_name"`
				Result  installedSyscallReply `json:"result"`
				Expires time.Time             `json:"query_expires_at"`
			}
			if json.Unmarshal(out.Data, &nested) != nil || nested.Handle != handle || nested.Tool != tool || nested.Result.RequestID != out.RequestID || !nested.Expires.Equal(until) {
				t.Fatal("syscall poll changed its exact result association")
			}
			out = nested.Result
		}
		if wantError != "" {
			if out.Status != "error" || installedSyscallFailureCode(out) != wantError {
				t.Fatal("changed syscall cursor was accepted", out.Status, installedSyscallFailureCode(out))
			}
		} else if out.Status != "ok" || out.DataClass != "extract" || len(out.Provenance) != 1 || out.Provenance[0].ArtifactID != artifactID || out.Provenance[0].Digest != version {
			t.Fatal("syscall result changed source/class", out.Status, installedSyscallFailureCode(out))
		}
		var page installedSyscallPage
		if wantError != "" {
			return out, page
		}
		decoder := json.NewDecoder(bytes.NewReader(out.Data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&page) != nil || page.Observed.IsZero() || !page.Expires.After(page.Observed) || page.Expires.After(expires) || !until.IsZero() && !page.Expires.Equal(until) {
			t.Fatal("syscall page lost original dates or closed metadata fields")
		}
		if tool == "get_syscall_summary" && (page.Kind != "syscallSummary" || page.Events != nil) || tool == "get_syscall_events" && (page.Kind != "syscallEvents" || page.Rows != nil) {
			t.Fatal("syscall result changed its selected view")
		}
		c := page.Coverage
		if c.Dropped != nil || c.Truncated != nil || len(c.Gaps) == 0 || !strings.Contains(strings.ToLower(strings.Join(c.Gaps, " ")), "unknown") || c.Records != expectedCounts.RecordCount || c.Unmatched != expectedCounts.UnmatchedEvents || c.Unfinished != expectedCounts.UnfinishedEvents || c.Unknown != expectedCounts.UnknownEvents {
			t.Fatal("syscall projection invented coverage or changed full-file counters", c, expectedCounts)
		}
		return out, page
	}
	base := func() map[string]any {
		return map[string]any{"case_id": caseID, "artifact_id": artifactID, "limit": 100}
	}
	_, summary := run("get_syscall_summary", base(), "")
	downloadRetirement()
	if summary.Kind != "syscallSummary" || len(summary.Events) != 0 || len(summary.Rows) == 0 || len(summary.Rows) > min(100, len(expectedRows)) || !reflect.DeepEqual(summary.Rows, expectedRows[:len(summary.Rows)]) {
		t.Fatal("summary differs from independently counted downloaded native events")
	}
	// Pick a name actually repeated in the source; a one-record prefix must
	// continue at the next matching native event, independent of other names.
	name := ""
	for _, row := range expectedRows {
		if row.Count >= 2 {
			name = row.Syscall
			break
		}
	}
	if name == "" {
		t.Fatal("captured fixture lacks a repeatable syscall for continuation")
	}
	var filtered []artifact.SyscallMetadataEvent
	var errorsOnly []artifact.SyscallMetadataEvent
	for _, event := range expectedEvents {
		if event.Syscall == name {
			filtered = append(filtered, event)
			if event.Outcome == "error" {
				errorsOnly = append(errorsOnly, event)
			}
		}
	}
	args := base()
	args["limit"], args["syscall_names"] = 1, []string{name}
	first, page := run("get_syscall_events", args, "")
	if page.Kind != "syscallEvents" || len(page.Rows) != 0 || len(page.Events) != 1 || !reflect.DeepEqual(page.Events, filtered[:1]) || first.Next == "" {
		t.Fatal("filtered first native event/cursor differs")
	}
	args = base()
	args["syscall_names"], args["cursor"] = []string{name}, first.Next
	_, page = run("get_syscall_events", args, "")
	if len(page.Events) == 0 || len(page.Events) > min(100, len(filtered)-1) || !reflect.DeepEqual(page.Events, filtered[1:1+len(page.Events)]) {
		t.Fatal("cursor skipped or substituted a native matching event")
	}
	args = base()
	args["syscall_names"], args["errors_only"] = []string{name}, true
	_, page = run("get_syscall_events", args, "")
	if len(page.Events) != min(100, len(errorsOnly)) || len(page.Events) > 0 && !reflect.DeepEqual(page.Events, errorsOnly[:len(page.Events)]) {
		t.Fatal("error display filter differs from native outcomes")
	}
	args = base()
	args["cursor"], args["syscall_names"], args["errors_only"] = first.Next, []string{name}, true
	run("get_syscall_events", args, "InvalidCursor")
	if rolling {
		if len(oldRetirements) != installedSyscallProjectionQueries || retiredOld != 3 || continuation[0].RawQueries == nil {
			t.Fatal("five fixed views did not retain immediate proof before raw queries")
		}
		continuation[0].RawQueries(retireNext)
		if retiredOld != installedSyscallProjectionQueries {
			t.Fatal("later raw admissions did not retire all original fixed views")
		}
		t.Log("five original fixed views retained all assertions and positive later retirement; two raw queries use the same native original with immediate live proofs and rolling two-slot terminal ownership")
		return
	}
	proofs.flush(t)
	if proofs.queries != installedSyscallProjectionQueries || proofs.joined != installedSyscallProjectionQueries || proofs.retired != installedSyscallProjectionQueries-1 {
		t.Fatal("syscall fixture did not observe all five joins and first four product retirements", proofs.queries, proofs.joined, proofs.retired)
	}
	// All five workers reached joined closure and their original terminal
	// lifetime. The last retains its conservative charge until ordinary cleanup;
	// this fixture does not claim a final retirement/refund it did not observe.
	t.Logf("installed saved syscalls: source=%s recorded=%d names=%d, read-only OAuth, exact native summary/events/filter/continuation, changed-filter refusal, unknown acquisition coverage and no sensitive marker; five one-batch queries with independent SQL/key/Pod readback", nativeType, len(expectedEvents), len(expectedRows))
}

func TestInstalledSyscallNativeOracleKeepsOnlyMetadata(t *testing.T) {
	duration := uint64(7)
	event := artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{PodUID: "pod", ProcessRef: "process", ThreadRef: "thread"}, Syscall: "write", ABI: "x86_64", Timestamp: "2026-11-03T10:00:00Z", DurationNS: &duration, Outcome: "error", Errno: "EIO", Arguments: []artifact.ArgumentValue{{Name: "buffer", Value: "base64:" + base64.StdEncoding.EncodeToString([]byte(manualArgumentsMarker+"\n"))}}}
	var native bytes.Buffer
	for _, v := range []any{artifact.ArgumentHeader{Record: "header", PodUID: "pod"}, artifact.ArgumentEventLine{Record: "event", Event: event}, artifact.ArgumentFooter{Record: "footer", Retained: 1}} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(&native, string(b))
	}
	events, rows, counts, err := installedSyscallExpected(native.Bytes(), artifact.SyscallArgumentsArtifact, "pod")
	if err != nil || len(events) != 1 || counts.RecordCount != 1 || len(rows) != 1 || rows[0] != (query.SyscallCount{Syscall: "write", Count: 1, Errors: 1, PairedCount: 1, TotalDurationNS: 7}) {
		t.Fatal(events, rows, counts, err)
	}
	body, _ := json.Marshal(events)
	if bytes.Contains(body, []byte(manualArgumentsMarker)) || bytes.Contains(body, []byte("arguments")) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString([]byte(manualArgumentsMarker)))) {
		t.Fatal("raw fields entered expected metadata")
	}
	if _, _, _, err := installedSyscallExpected(native.Bytes()[:native.Len()-1], artifact.SyscallArgumentsArtifact, "pod"); err == nil {
		t.Fatal("partial native file accepted")
	}
	forbidden, err := installedSyscallForbidden(native.Bytes(), manualArgumentsMarker)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range forbidden {
		if s == base64.StdEncoding.EncodeToString([]byte(manualArgumentsMarker+"\n")) {
			found = true
		}
	}
	if !found {
		t.Fatal("actual captured buffer encoding with newline was not forbidden")
	}
}

func TestInstalledSyscallFailureUsesEnvelopeData(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"schema_version": "mcp-result/v1", "request_id": "11111111-1111-4111-8111-111111111111", "data_class": "metadata", "status": "error", "truncated": false, "next_cursor": nil, "narrowing_hint": nil, "data": map[string]any{"code": "InvalidCursor", "message": "Start again without a cursor.", "retryable": false}, "warnings": []string{}, "provenance": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"get_syscall_events", "get_query_result"} {
		if err := wire.ValidateOutput(tool, body); err != nil {
			t.Fatal(tool, err)
		}
		var reply installedSyscallReply
		if json.Unmarshal(body, &reply) != nil || installedSyscallFailureCode(reply) != "InvalidCursor" {
			t.Fatal("typed refusal did not decode from envelope data")
		}
		reply.Status = "ok"
		if installedSyscallFailureCode(reply) != "" {
			t.Fatal("successful data became a refusal")
		}
	}
}
