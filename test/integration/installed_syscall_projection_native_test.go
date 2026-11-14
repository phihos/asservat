package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
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
