package integration

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
)

// Read the actual operator-installation producer used by the native fixture.
// A cursor refusal is still a full paid source read, and terminal worker proof
// does not replenish any of these ten retained query units.
func TestInstalledSyscallProjectionsFundEveryPaidQuery(t *testing.T) {
	for _, focus := range []string{"manual-syscall", "manual-arguments"} {
		t.Setenv("ASSERVAT_JOURNEY_FOCUS", focus)
		profile := nativeCapacityProfile()
		want := int64(installedSyscallProjectionQueries * query.SyscallProjectionQueryUnits)
		if focus == "manual-arguments" {
			want = installedArgumentQueryUnits
		}
		if installedSyscallProjectionQueries != 5 || query.SyscallProjectionQueryUnits != 2 || profile.Records != want || focus == "manual-syscall" && want != 10 || focus == "manual-arguments" && want != 18 {
			t.Fatal("installed syscall producer does not fund five conservative source reads", focus, profile.Records, want)
		}
	}
	for _, focus := range []string{"approved-recording", "manual-http", "policy-arguments", "journey"} {
		t.Setenv("ASSERVAT_JOURNEY_FOCUS", focus)
		if got := nativeCapacityProfile(); got.Records != 8 {
			t.Fatal("unrelated fixture funding changed", focus, got.Records)
		}
	}
}

// Synthetic callbacks verify only scheduling, not authority/SQL/Pod proof.
// Every callback stands for the unchanged installedProjectionSQLCheck.
func TestInstalledSyscallCohortsJoinAllFiveAndRetireFirstFour(t *testing.T) {
	var proofs installedSyscallProofCohort
	var order []string
	for id := 1; id <= installedSyscallProjectionQueries; id++ {
		proofs.add(t, func() func() {
			order = append(order, fmt.Sprintf("join-%d", id))
			return func() { order = append(order, fmt.Sprintf("retire-%d", id)) }
		})
		if len(proofs.pending) == 2 {
			proofs.flush(t)
		}
	}
	proofs.flush(t)
	proofs.flush(t) // no later real admission: never invent final retirement
	want := []string{"join-1", "join-2", "join-3", "join-4", "retire-1", "retire-2", "join-5", "retire-3", "retire-4"}
	if !reflect.DeepEqual(order, want) || proofs.queries != 5 || proofs.joined != 5 || proofs.retired != 4 || len(proofs.pending) != 0 || len(proofs.retirement) != 1 {
		t.Fatal("original worker terminal and later product retirement boundaries changed", order, proofs)
	}
}

func TestInstalledSyscallCohortAttemptsOtherKnownJoinsAfterFailure(t *testing.T) {
	var proofs installedSyscallProofCohort
	var order []int
	proofs.add(t, func() func() { order = append(order, 1); panic("synthetic join failure") })
	proofs.add(t, func() func() { order = append(order, 2); return func() {} })
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("fixture failure was hidden")
			}
		}()
		proofs.flush(t)
	}()
	if !reflect.DeepEqual(order, []int{1, 2}) || len(proofs.pending) != 0 || proofs.joined != 1 {
		t.Fatal("one failed proof abandoned another known worker", order, proofs)
	}
}

func TestInstalledSyscallNativeCloseBindsOriginalSessionAndAcknowledgement(t *testing.T) {
	const download = "11111111-1111-4111-8111-111111111111"
	for _, mode := range []string{"cancelled", "already-terminal", "uncertain", "pending", "wrong-session", "wrong-state", "wrong-audit", "no-terminal-proof"} {
		t.Run(mode, func(t *testing.T) {
			calls, observations, retirements := 0, 0, 0
			invoke := func(name string, input any) (installedJourneyEnvelope, string) {
				calls++
				args, ok := input.(map[string]string)
				if !ok || name != "cancel_artifact_download" || args["download_id"] != download || args["idempotency_key"] != "syscall-native-complete-"+download || len(args) != 2 {
					t.Fatal("close changed original session or operation", name, input)
				}
				receipt := installedJourneyStopReceipt{DownloadID: download, State: "Cancelled", AuditState: "recorded"}
				status, code := "ok", ""
				switch mode {
				case "already-terminal":
					receipt.State = "AlreadyTerminal"
				case "uncertain":
					code = "OutcomeUnknown"
				case "pending":
					status = "pending"
				case "wrong-session":
					receipt.DownloadID = "22222222-2222-4222-8222-222222222222"
				case "wrong-state":
					receipt.State = "Ready"
				case "wrong-audit":
					receipt.AuditState = "missing"
				}
				body, err := json.Marshal(receipt)
				if err != nil {
					t.Fatal(err)
				}
				return installedJourneyEnvelope{Status: status, Data: body}, code
			}
			closed := func(id string) func() {
				observations++
				if id != download {
					t.Fatal("worker observer selected replacement session")
				}
				if mode == "no-terminal-proof" {
					return nil
				}
				return func() { retirements++ }
			}
			retire, err := finishInstalledSyscallNativeDownload(download, invoke, closed)
			if mode == "cancelled" || mode == "already-terminal" {
				if err != nil || retire == nil || calls != 1 || observations != 1 || retirements != 0 {
					t.Fatal("close/terminal/retirement boundaries changed", err, calls, observations, retirements)
				}
				retire()
				if retirements != 1 {
					t.Fatal("missing later real-demand retirement check")
				}
			} else if err == nil || retire != nil || calls != 1 || retirements != 0 || mode != "no-terminal-proof" && observations != 0 {
				t.Fatal("unacknowledged or substituted close was retried/used as worker proof", mode, err, calls, observations, retirements)
			}
		})
	}
}
