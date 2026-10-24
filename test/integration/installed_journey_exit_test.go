package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// S-02 exit checks of the installed journey (docs/architecture/
// implementation-slices.md "S-02 exit in detail"). The SQL reads are an
// operator-only readback in a READ ONLY transaction; they supply no runtime
// input or authority.

func installedJourneyReadOnly(t *testing.T, ctx context.Context, admin *pgxpool.Pool, read func(pgx.Tx) error) {
	t.Helper()
	bounded, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	tx, err := admin.BeginTx(bounded, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("installed read-only SQL", err)
	}
	defer tx.Rollback(bounded)
	if err = read(tx); err != nil {
		t.Fatal("installed read-only SQL", err)
	}
}

// installedJourneyCaptures returns the root's admitted capture rows and
// requires exactly one with the accepted ID. Each row owns one custody attempt
// (attempt_id is UNIQUE), so an unchanged count is an unchanged admission.
func installedJourneyCaptures(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root, captureID string) int64 {
	t.Helper()
	var total, exact int64
	installedJourneyReadOnly(t, ctx, admin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE id=$2::uuid) FROM context_capture WHERE root_id=$1::uuid`, root, captureID).Scan(&total, &exact)
	})
	if exact != 1 {
		t.Fatal("installed accepted capture has no single admission row", exact)
	}
	return total
}

// Exit 1: an exact duplicate (same preview and key) replays the original
// operation; the same key with different content is Conflict (specs/mcp.md
// request_capture). Neither adds an admission row.
func installedJourneyIdempotency(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root, captureID string, original map[string]any, request func(map[string]any) string) {
	t.Helper()
	before := installedJourneyCaptures(t, ctx, admin, root, captureID)
	submit := func(arguments map[string]any) string {
		code := ""
		for attempt := 1; attempt <= 3; attempt++ {
			// request remembers a successful reply's capture ID and fails the
			// test if it differs from the original accepted capture.
			if code = request(arguments); code != "OutcomeUnknown" {
				break
			}
			if installedJourneyPause(ctx, 2*time.Second) != nil {
				break
			}
		}
		return code
	}
	if code := submit(map[string]any{"preview_id": original["preview_id"], "idempotency_key": original["idempotency_key"]}); code != "" {
		t.Fatal("installed duplicate request_capture did not replay the original operation", code)
	}
	if code := submit(map[string]any{"preview_id": uuid.NewString(), "idempotency_key": original["idempotency_key"]}); code != "Conflict" {
		t.Fatal("installed request_capture reusing the key with different content was not Conflict", code)
	}
	if after := installedJourneyCaptures(t, ctx, admin, root, captureID); after != before {
		t.Fatal("installed duplicate/conflicting request changed the admitted captures", before, after)
	}
	t.Log("installed journey: an exact duplicate request_capture replayed the original capture and a changed request under the same key was Conflict, with one admission row")
}

// Exit 3: no catalog-tier row for the published artifact holds the native
// evidence. bytea columns render as hex in row_to_json, so both forms are
// checked, plus a field name only the native pod-status format carries.
func installedJourneyCatalogMinimized(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root, artifactID string, native []byte) {
	t.Helper()
	var rows string
	installedJourneyReadOnly(t, ctx, admin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
SELECT concat_ws(' ', row_to_json(c)::text, row_to_json(v)::text, row_to_json(k)::text, row_to_json(a)::text)
FROM context_catalog c
JOIN context_verification v ON v.capture_id=c.capture_id AND v.root_id=c.root_id
JOIN context_capture k ON k.id=c.capture_id AND k.root_id=c.root_id
JOIN custody_attempt a ON a.id=k.attempt_id
WHERE c.root_id=$1::uuid AND c.artifact_id=$2::uuid`, root, artifactID).Scan(&rows)
	})
	if !strings.Contains(rows, artifactID) {
		t.Fatal("installed catalog readback did not select the published artifact")
	}
	lower := strings.ToLower(rows)
	for _, fragment := range []string{string(native), `"runtimeInstances"`} {
		if strings.Contains(rows, fragment) || strings.Contains(lower, hex.EncodeToString([]byte(fragment))) {
			t.Fatal("installed SQL catalog contains native evidence text")
		}
	}
	t.Log("installed journey: the SQL catalog, verification, capture and custody rows of the published artifact contain no native evidence text")
}

func installedJourneyContent(t *testing.T, ctx context.Context, client *http.Client, url, token string, header map[string]string) *http.Response {
	t.Helper()
	get, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	get.Header.Set("Authorization", "Bearer "+token)
	for k, v := range header {
		get.Header.Set(k, v)
	}
	response, err := client.Do(get)
	if err != nil {
		t.Fatal("installed download content", err)
	}
	return response
}

// installedJourneyPartial reads one 206 response and checks its Content-Range.
func installedJourneyPartial(response *http.Response, offset, length, size int64) ([]byte, string, error) {
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, artifact.MaxContextBytes+1))
	want := "bytes " + strconv.FormatInt(offset, 10) + "-" + strconv.FormatInt(offset+length-1, 10) + "/" + strconv.FormatInt(size, 10)
	etag := response.Header.Get("ETag")
	if err != nil || response.StatusCode != http.StatusPartialContent || response.Header.Get("Content-Range") != want || int64(len(body)) != length || etag == "" || strings.HasPrefix(etag, "W/") {
		return nil, "", fmt.Errorf("partial response %d %q (%d bytes)", response.StatusCode, response.Header.Get("Content-Range"), len(body))
	}
	return body, etag, nil
}

// Exit 4 (bounded resume), before the full GET: a session that has delivered
// the whole file is Completed and terminal, so it offers no resume. The first
// half is fetched, then the rest under If-Range with the returned strong ETag.
func installedJourneyResume(t *testing.T, ctx context.Context, client *http.Client, url, token string, size int64) (head, tail []byte) {
	t.Helper()
	if size < 2 {
		t.Fatal("installed native file too small to resume", size)
	}
	half := size / 2
	head, etag, err := installedJourneyPartial(installedJourneyContent(t, ctx, client, url, token, map[string]string{"Range": fmt.Sprintf("bytes=0-%d", half-1)}), 0, half, size)
	if err != nil {
		t.Fatal("installed first range", err)
	}
	tail, resumed, err := installedJourneyPartial(installedJourneyContent(t, ctx, client, url, token, map[string]string{"Range": fmt.Sprintf("bytes=%d-", half), "If-Range": etag}), half, size-half, size)
	if err != nil || resumed != etag {
		t.Fatal("installed If-Range resume", err)
	}
	return head, tail
}

// After the full GET the session is Completed: a further range is a bounded
// unavailable problem, and SQL retains every charge (one preparation plus
// three responses at the fixed read work, two file lengths of output) with no
// refund or refill.
func installedJourneyResumeSpent(t *testing.T, ctx context.Context, admin *pgxpool.Pool, client *http.Client, root, downloadID, url, token string, size int64) {
	t.Helper()
	if err := installedJourneyStoppedContent(installedJourneyContent(t, ctx, client, url, token, map[string]string{"Range": "bytes=0-0"})); err != nil {
		t.Fatal("installed completed download offered another range", err)
	}
	var state string
	var output, read, emitted int64
	installedJourneyReadOnly(t, ctx, admin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, charged_output, charged_read, emitted_bytes FROM artifact_download WHERE root_id=$1::uuid AND id=$2::uuid`, root, downloadID).Scan(&state, &output, &read, &emitted)
	})
	if state != string(artifact.DownloadCompleted) || output != 2*size || emitted != output || read != 4*evidence.ContextDownloadReadWork {
		t.Fatal("installed resumed download charges", state, output, emitted, read)
	}
	t.Logf("installed journey: range plus If-Range resume matched the full native file; the Completed session refused another range and kept its charges (%d output, %d read bytes)", output, read)
}

// Exit (unrelated principal): an eligible user named by no AccessBinding signs
// in through MCP. Every call about the opted-in workload and its evidence is a
// schema-valid error identical to the same call about an absent counterpart,
// so the reply discloses neither existence nor detail (specs/mcp.md: uniform
// not-found/not-authorized projection before access is established).
func installedJourneyUnrelated(t *testing.T, ctx context.Context, wire *contracts.InvestigationContracts, outsider *installedIdentity, transport http.RoundTripper, origin string, target map[string]string, previewID, caseID, artifactID string) {
	t.Helper()
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-unrelated", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, outsider.mcpTokenSource(origin).Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal("installed unrelated MCP session", err)
	}
	defer session.Close()
	refusal := func(name string, arguments any) (map[string]any, error) {
		result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: arguments})
		if err != nil {
			return nil, err
		}
		reply, code, err := installedJourneyReplyCode(wire, name, result)
		if err != nil {
			return nil, err
		}
		if code == "" {
			return nil, errors.New("operation succeeded")
		}
		var data map[string]any
		if json.Unmarshal(reply.Data, &data) != nil || bytes.Contains(reply.Data, []byte(target["name"])) {
			return nil, errors.New("refusal data echoes the request")
		}
		return data, nil
	}
	absent := map[string]string{"cluster_id": target["cluster_id"], "namespace": target["namespace"], "kind": target["kind"], "name": "absent-" + uuid.NewString()[:8]}
	preset := map[string]string{"name": "pod-status", "version": "v1"}
	key := "installed-unrelated-" + uuid.NewString()
	for _, c := range []struct {
		name        string
		real, other any
	}{
		{"list_diagnostics", map[string]any{"target_ref": target}, map[string]any{"target_ref": absent}},
		{"preview_capture", map[string]any{"target_ref": target, "preset_ref": preset, "requested_retention_seconds": installedJourneyRetention}, map[string]any{"target_ref": absent, "preset_ref": preset, "requested_retention_seconds": installedJourneyRetention}},
		{"request_capture", map[string]string{"preview_id": previewID, "idempotency_key": key}, map[string]string{"preview_id": uuid.NewString(), "idempotency_key": key + "-absent"}},
		{"get_case", map[string]string{"case_id": caseID}, map[string]string{"case_id": uuid.NewString()}},
		{"prepare_artifact_download", map[string]string{"artifact_id": artifactID, "idempotency_key": key}, map[string]string{"artifact_id": uuid.NewString(), "idempotency_key": key + "-absent"}},
	} {
		var failure error
		for attempt := 1; attempt <= 3; attempt++ {
			var real, other map[string]any
			if real, failure = refusal(c.name, c.real); failure == nil {
				if other, failure = refusal(c.name, c.other); failure == nil && !reflect.DeepEqual(real, other) {
					failure = fmt.Errorf("refusal %v differs from absent %v", real, other)
				}
			}
			if failure == nil || installedJourneyPause(ctx, 2*time.Second) != nil {
				break
			}
		}
		if failure != nil {
			t.Fatalf("installed unrelated principal %s: %v", c.name, failure)
		}
	}
	t.Log("installed journey: an unrelated eligible Keycloak user was refused on MCP diagnostics, preview, request, case and download preparation exactly as for absent objects")
}
