package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
	"unicode/utf8"

	logcodec "asservat.local/asservat/internal/adapters/logs"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"k8s.io/client-go/kubernetes"
)

const installedLogsQueries = 2
const installedLogsQueryUnits = installedLogsQueries * query.LogQueryUnits
const installedLogsNativeLimit = 1 << 20

func installedLogsFocus() bool { return installedJourneyFocus() == "manual-logs" }
func manualLogsArguments(cluster, namespace, workload string, stop bool) map[string]any {
	after, timeout := "2s", "15s"
	if stop {
		after, timeout = "30s", "40s"
	}
	return map[string]any{"target_ref": map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload}, "requested_retention_seconds": 600, "profile_composition": map[string]any{"components": []any{map[string]any{"id": "logs", "profileRef": map[string]string{"catalog": "builtin", "name": "finite-logs", "version": "v1"}, "overrides": []any{map[string]any{"actionID": "logs", "field": "logBefore", "value": "1h"}, map[string]any{"actionID": "logs", "field": "logAfter", "value": after}, map[string]any{"actionID": "logs", "field": "actionTimeout", "value": timeout}, map[string]any{"actionID": "logs", "field": "actionMaxBytes", "value": installedLogsNativeLimit}}}}, "maxTotalBytes": installedLogsNativeLimit, "maxDuration": timeout}}
}

type installedLogsEntry struct {
	Origin struct {
		OriginID      uint16  `json:"origin_id"`
		ContainerKind string  `json:"container_kind"`
		ContainerName string  `json:"container_name"`
		Source        string  `json:"source"`
		Stream        string  `json:"stream"`
		RuntimeID     *string `json:"runtime_id"`
		RestartCount  *uint32 `json:"restart_count"`
	} `json:"origin"`
	Fragment     uint64  `json:"fragment"`
	Line         uint64  `json:"line"`
	Offset       uint64  `json:"offset"`
	LineOffset   uint64  `json:"line_offset"`
	Continuation bool    `json:"continuation"`
	EndLine      bool    `json:"end_line"`
	SourceTime   *string `json:"source_time"`
	Text         *string `json:"text"`
	BytesBase64  *string `json:"bytes_base64"`
}
type installedLogsPage struct {
	Kind        string               `json:"kind"`
	PodUID      string               `json:"pod_uid"`
	WindowStart time.Time            `json:"window_start"`
	WindowEnd   time.Time            `json:"window_end"`
	Entries     []installedLogsEntry `json:"entries"`
	Coverage    struct {
		Origins     uint16 `json:"origins"`
		Complete    uint16 `json:"complete_origins"`
		Partial     uint16 `json:"partial_origins"`
		Unavailable uint16 `json:"unavailable_origins"`
		Unknown     uint16 `json:"unknown_timestamp_origins"`
		Gapped      uint16 `json:"gapped_origins"`
		SourceBytes uint64 `json:"source_bytes"`
		Fragments   uint64 `json:"total_fragments"`
	} `json:"coverage"`
	Observed time.Time `json:"query_observed_at"`
	Expires  time.Time `json:"query_expires_at"`
}

func installedLogsRequest(s savedLogsBrowserSource, key string) map[string]any {
	return map[string]any{"case_id": s.CaseID, "artifact_id": s.ArtifactID, "grant_id": s.GrantID, "idempotency_key": key, "limit": 100}
}

// Go owns scheduling and paid polls; Chromium uses the same bounded protocol.
// A same-key Begin is always replayed for MCP, including an immediate page.
func queryInstalledLogsWithCall(t *testing.T, ctx context.Context, s savedLogsBrowserSource, request map[string]any, call func(string, any) installedComparisonReply, verify func(string, string) func(), replay bool) installedLogsPage {
	t.Helper()
	out := call("get_logs", request)
	operation, handle := out.RequestID, ""
	checked := false
	defer func() {
		if !checked && operation != "" {
			verify(handle, operation)
		}
	}()
	var firstExpiry time.Time
	parseTimes := func(r installedComparisonReply) (string, time.Time, time.Time, int) {
		var p struct {
			Handle   string    `json:"query_handle"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
			Retry    int       `json:"retry_after_seconds"`
		}
		if json.Unmarshal(r.Data, &p) != nil || p.Observed.IsZero() || !p.Expires.After(p.Observed) || p.Expires.After(s.Expires) {
			t.Fatal("logs response original interval")
		}
		if firstExpiry.IsZero() {
			firstExpiry = p.Expires
		} else if !p.Expires.Equal(firstExpiry) {
			t.Fatal("logs query renewed original expiry")
		}
		return p.Handle, p.Observed, p.Expires, p.Retry
	}
	if out.Status != "pending" && out.Status != "ok" {
		t.Fatal("initial saved logs unavailable", out.Status)
	}
	originalHandle, initialObserved, _, _ := parseTimes(out)
	if replay {
		again := call("get_logs", request)
		h, _, _, _ := parseTimes(again)
		if again.Status != "pending" || h == "" || originalHandle != "" && h != originalHandle {
			t.Fatal("same-key logs replay replaced lineage/disclosed page")
		}
		handle = h
	}
	for attempts := 0; out.Status == "pending"; attempts++ {
		h, _, _, retry := parseTimes(out)
		if h == "" || handle != "" && h != handle || retry < 1 || retry > 60 || attempts >= 4 {
			t.Fatal("logs bounded original pending lineage")
		}
		handle = h
		target, err := installedProjectionPollTime(initialObserved, firstExpiry, time.Now(), time.Duration(retry)*time.Second, attempts)
		if err != nil {
			t.Fatal(err)
		}
		if err = installedJourneyPause(ctx, time.Until(target)); err != nil {
			t.Fatal(err)
		}
		out = call("get_query_result", map[string]any{"query_handle": handle})
	}
	var inner installedComparisonReply
	outerObserved, outerExpires := time.Time{}, time.Time{}
	if len(out.Provenance) == 0 {
		var nested struct {
			Tool     string                   `json:"tool_name"`
			QueryID  string                   `json:"query_handle"`
			Result   installedComparisonReply `json:"result"`
			Observed time.Time                `json:"query_observed_at"`
			Expires  time.Time                `json:"query_expires_at"`
		}
		if json.Unmarshal(out.Data, &nested) != nil || nested.Tool != "get_logs" || nested.QueryID != handle {
			t.Fatal("nested logs association")
		}
		inner = nested.Result
		outerObserved, outerExpires = nested.Observed, nested.Expires
	} else {
		inner = out
	}
	var page installedLogsPage
	if out.Status != "ok" || inner.Status != "ok" || out.DataClass != "raw" || inner.DataClass != "raw" || len(inner.Provenance) != 1 || inner.Provenance[0].ArtifactID != s.ArtifactID || inner.Provenance[0].Digest != s.Version || json.Unmarshal(inner.Data, &page) != nil || page.Kind != "logs" || page.PodUID != s.PodUID || page.Entries == nil || page.WindowEnd.Before(page.WindowStart) || !page.Expires.Equal(firstExpiry) || !page.Expires.After(page.Observed) {
		t.Fatal("logs raw page lost exact source/times")
	}
	if !outerObserved.IsZero() && (!page.Observed.Equal(outerObserved) || !page.Expires.Equal(outerExpires)) {
		t.Fatal("inner/outer logs clocks differ in same response")
	}
	if verify(handle, operation) == nil {
		t.Fatal("logs missing SQL/key/worker proof")
	}
	checked = true
	return page
}

// Native parity is independently walked over the authenticated downloaded JSONL.
// Returned pages must preserve exact saved bytes, origin identities and offsets.
func checkInstalledLogsParity(native []byte, pod string, pages ...installedLogsPage) (artifact.LogFooter, error) {
	var header artifact.LogHeader
	var origin artifact.LogOrigin
	var origins []artifact.LogOrigin
	var fragments []artifact.LogFragment
	var coverage []artifact.LogCoverage
	footer, err := logcodec.Walk(context.Background(), bytes.NewReader(native), installedLogsNativeLimit, logcodec.Visitor{Header: func(h artifact.LogHeader) error { header = h; return nil }, Origin: func(o artifact.LogOrigin) error { origin = o; origins = append(origins, origin); return nil }, Fragment: func(f artifact.LogFragment) error { fragments = append(fragments, f); return nil }, Coverage: func(c artifact.LogCoverage) error { coverage = append(coverage, c); return nil }})
	if err != nil || header.PodUID != pod {
		return footer, fmt.Errorf("original logs native: %w", err)
	}
	for _, p := range pages {
		if p.PodUID != pod || !p.WindowStart.Equal(header.WindowStart) || !p.WindowEnd.Equal(header.WindowEnd) || p.Coverage.Origins != header.Origins || p.Coverage.SourceBytes != footer.SourceBytes || p.Coverage.Fragments != footer.Fragments {
			return footer, fmt.Errorf("logs page changed original native coverage")
		}
		var complete, partial, unavailable, unknown, gapped uint16
		for _, c := range coverage {
			switch c.FetchOutcome {
			case "complete":
				complete++
			case "partial":
				partial++
			case "unavailable":
				unavailable++
			}
			if len(c.Gaps) > 0 {
				gapped++
			}
			for _, g := range c.Gaps {
				if g == "timestampUnknown" {
					unknown++
				}
			}
		}
		if p.Coverage.Complete != complete || p.Coverage.Partial != partial || p.Coverage.Unavailable != unavailable || p.Coverage.Unknown != unknown || p.Coverage.Gapped != gapped {
			return footer, fmt.Errorf("logs page changed known/unknown native coverage")
		}
		for _, e := range p.Entries {
			if e.Fragment >= uint64(len(fragments)) || (e.Text == nil) == (e.BytesBase64 == nil) {
				return footer, fmt.Errorf("logs page invalid fragment/encoding")
			}
			f := fragments[e.Fragment]
			o := origins[f.OriginID]
			raw, _ := f.Bytes()
			var b []byte
			if e.Text != nil {
				b = []byte(*e.Text)
				if !utf8.Valid(b) {
					return footer, fmt.Errorf("invalid bytes rewritten as text")
				}
			} else {
				b, err = base64.StdEncoding.Strict().DecodeString(*e.BytesBase64)
				if err != nil {
					return footer, err
				}
			}
			offset := int64(e.Offset) - int64(f.Offset)
			if offset < 0 || offset+int64(len(b)) > int64(len(raw)) || !bytes.Equal(b, raw[offset:offset+int64(len(b))]) || e.Line != f.Line || e.LineOffset != f.LineOffset+uint64(offset) || e.Continuation != (e.LineOffset > 0) || e.EndLine != (f.EndLine && offset+int64(len(b)) == int64(len(raw))) || !reflect.DeepEqual(e.SourceTime, f.SourceTime) || e.Origin.OriginID != o.OriginID || e.Origin.ContainerKind != o.ContainerKind || e.Origin.ContainerName != o.ContainerName || e.Origin.Source != o.Source || e.Origin.Stream != "combined" || !reflect.DeepEqual(e.Origin.RuntimeID, o.RuntimeID) || !reflect.DeepEqual(e.Origin.RestartCount, o.RestartCount) {
				return footer, fmt.Errorf("logs page bytes/provenance differ from native")
			}
		}
	}
	return footer, nil
}

// This focused journey uses the provisioned API-only connector. Administrator
// Kubernetes/SQL reads set up synthetic bytes and verify outcomes; they never
// provide capture, query, approval or key authority to the installed product.
func installedLogsListenerReady(ctx context.Context, region kubernetes.Interface, namespace, podName string) bool {
	_, err := region.CoreV1().RESTClient().Get().Namespace(namespace).Resource("pods").Name(podName+":8080").SubResource("proxy").Suffix("traffic").Param("records", "1").DoRaw(ctx)
	return err == nil
}
