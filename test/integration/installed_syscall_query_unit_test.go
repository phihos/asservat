package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// Synthetic advancing-clock scheduling only. Durations are rounded observed
// installed read times; no SQL, runtime authority or throughput claim follows.
func TestInstalledRawSyscallRollingOriginalTwoSlots(t *testing.T) {
	reads := []int{26, 28, 25, 26, 25, 26, 34}
	now, active, peak, snapshots := 0, 0, 0, 0
	var starts, joins []int
	p := &installedPacketTerminalPipeline{limit: 7}
	deadlines := map[int]int{}
	for i, read := range reads {
		if len(p.pending) == 2 {
			p.drain(t)
		}
		if active >= 2 {
			t.Fatal("third worker before joined original")
		}
		id := i + 1
		starts = append(starts, now)
		original := now + 60
		deadlines[id] = original
		active++
		if active > peak {
			peak = active
		}
		now += read
		snapshots++ // live SQL/key/Pod assertions belong here, before wait.
		p.add(t, func() {
			if deadlines[id] != original {
				t.Fatal("original worker end changed")
			}
			if now < original {
				now = original
			}
			active--
			joins = append(joins, id)
		})
	}
	p.finish(t)
	if !reflect.DeepEqual(starts, []int{0, 26, 60, 86, 120, 146, 180}) || !reflect.DeepEqual(joins, []int{1, 2, 3, 4, 5, 6, 7}) || p.admitted != 7 || p.joined != 7 || snapshots != 7 || peak != 2 || active != 0 || now != 240 {
		t.Fatal("rolling ownership/read timing changed", starts, joins, p, now, peak, active)
	}
	// The old cohort barrier waits for both members, despite the first already
	// being terminal. Preserve five old views, then add two raw reads serially.
	old := 0
	for i := 0; i < 5; {
		first := old
		old += reads[i]
		i++
		if i < 5 {
			second := old
			old += reads[i]
			i++
			old = max(old, first+60, second+60)
		} else {
			old = max(old, first+60)
		}
	}
	first := old
	old += reads[5]
	second := old
	old += reads[6]
	old = max(old, first+60, second+60)
	if old != 317 || now >= old {
		t.Fatal("model did not expose old serial cohort idle", old, now)
	}
	t.Logf("advancing-clock fixture model: all seven original60s workers joined/max2; old five-barrier+two=%ds rollingseven=%ds; not a measured hosted saving", old, now)
}
func TestInstalledRawSyscallOriginalNativeOracle(t *testing.T) {
	zero := uint64(0)
	event := artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{PodUID: "pod", ProcessRef: "p", ThreadRef: "t"}, Syscall: "write", ABI: "x86_64", Timestamp: "2026-11-05T12:00:00Z", DurationNS: &zero, Outcome: "success", Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:0"}, {Name: "buffer", Value: "base64:" + base64.StdEncoding.EncodeToString([]byte(manualArgumentsMarker+"\n")), Truncated: true}, {Name: "path", Value: "unavailable:fault"}}}
	var b bytes.Buffer
	for _, v := range []any{artifact.ArgumentHeader{Record: "header", PodUID: "pod"}, artifact.ArgumentEventLine{Record: "event", Event: event}, artifact.ArgumentFooter{Record: "footer", Retained: 1}} {
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	actual, e := installedRawSyscallOracle(b.Bytes(), "pod")
	if e != nil || !reflect.DeepEqual(actual, []artifact.RawArgumentEvent{event}) {
		t.Fatal("raw values/order/zero/truncation changed", e)
	}
	for name, body := range map[string][]byte{"partial": b.Bytes()[:b.Len()-1], "trailing": append(bytes.Clone(b.Bytes()), []byte("{}\n")...), "noncanonical-scalar": bytes.ReplaceAll(b.Bytes(), []byte("decimal:0"), []byte("decimal:00")), "invalid-base64": bytes.ReplaceAll(b.Bytes(), []byte("base64:"), []byte("base64:!"))} {
		if _, e := installedRawSyscallOracle(body, "pod"); e == nil {
			t.Fatal("invalid original tail/value accepted", name)
		}
	}
	if _, e := installedRawSyscallOracle(b.Bytes(), "other-pod"); e == nil {
		t.Fatal("replacement Pod accepted")
	}
}
func TestInstalledRawSyscallSameKeyReplayReadyAndPending(t *testing.T) {
	for _, direct := range []bool{false, true} {
		t.Run(map[bool]string{true: "ready", false: "pending"}[direct], func(t *testing.T) {
			source := installedSyscallQueryBrowserSource{CaseID: consoleCaptureID(1), ArtifactID: consoleCaptureID(2), Version: "09" + string(bytes.Repeat([]byte{'0'}, 62)), PodUID: "pod", GrantID: consoleCaptureID(3), Expires: time.Now().Add(time.Hour)}
			at := time.Now().UTC().Add(-2 * time.Second)
			until := at.Add(20 * time.Second)
			duration := uint64(0)
			ready := installedComparisonReply{}
			ready.RequestID, ready.DataClass, ready.Status = consoleCaptureID(4), "raw", "ok"
			ready.Provenance = append(ready.Provenance, struct {
				ArtifactID string `json:"artifactID"`
				Digest     string `json:"digest"`
			}{source.ArtifactID, source.Version})
			raw, _ := json.Marshal(installedSyscallArgumentPage{Kind: "syscallQuery", Events: []artifact.RawArgumentEvent{{Identity: artifact.ArgumentIdentity{PodUID: "pod", ProcessRef: "p", ThreadRef: "t"}, Syscall: "write", ABI: "x86_64", Timestamp: at.Format(time.RFC3339Nano), DurationNS: &duration, Outcome: "success", Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:0"}}}}, Observed: at, Expires: until})
			ready.Data = raw
			pendingData, _ := json.Marshal(map[string]any{"query_handle": consoleCaptureID(5), "retry_after_seconds": 1, "query_observed_at": at, "query_expires_at": until})
			pending := installedComparisonReply{}
			pending.RequestID, pending.Status, pending.DataClass, pending.Data = consoleCaptureID(4), "pending", "metadata", pendingData
			calls, proof := 0, 0
			request := installedRawSyscallRequest(source, "same-original-key")
			call := func(name string, args any) installedComparisonReply {
				calls++
				if calls == 1 {
					if name != "syscall_query" {
						t.Fatal(name)
					}
					if direct {
						return ready
					}
					return pending
				}
				if calls == 2 {
					if name != "syscall_query" || !reflect.DeepEqual(args, request) {
						t.Fatal("replay input changed")
					}
					return pending
				}
				if direct || name != "get_query_result" {
					t.Fatal("extra paid read after originalReady")
				}
				inner, _ := json.Marshal(ready)
				outer, _ := json.Marshal(map[string]any{"query_handle": consoleCaptureID(5), "tool_name": "syscall_query", "result": json.RawMessage(inner), "query_observed_at": at, "query_expires_at": until})
				out := installedComparisonReply{}
				out.RequestID, out.Status, out.DataClass, out.Data = ready.RequestID, "ok", "raw", outer
				return out
			}
			_ = queryInstalledRawSyscallsWithCall(t, context.Background(), source, request, call, func(handle, op string) func() {
				proof++
				if handle != consoleCaptureID(5) || op != consoleCaptureID(4) {
					t.Fatal("original query/operation changed")
				}
				return func() {}
			}, true)
			if proof != 1 || calls != map[bool]int{true: 2, false: 3}[direct] {
				t.Fatal("replay paid another page", calls, proof)
			}
		})
	}
}
func TestInstalledArgumentQueryInitialFunding(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-arguments")
	if installedArgumentQueryUnits != 18 || installedRawSyscallQueries != 2 || nativeCapacityProfile().Records != 18 || query.SyscallQueryQueryUnits != 4 {
		t.Fatal("seven queries are not originally funded")
	}
}

func TestInstalledArgumentQueryConsoleScope(t *testing.T) {
	for _, focus := range []string{"manual-arguments", "manual-raw", "manual-syscall", "manual-profile", "browser"} {
		t.Run(focus, func(t *testing.T) {
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", focus)
			want := []string{"basic", "evidence:read", "evidence:download", "evidence:capture", "evidence:share"}
			if focus == "manual-raw" || focus == "manual-arguments" {
				want = append(want, "evidence:raw")
			}
			if focus != "browser" {
				want = append(want, "acr")
			}
			if got := installedConsoleScopes(); !reflect.DeepEqual(got, want) {
				t.Fatal("actual console client scope input changed", got, want)
			}
		})
	}
}
