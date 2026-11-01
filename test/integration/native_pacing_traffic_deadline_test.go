package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func nativePartialTrafficFixture() nativeTrafficResult {
	return nativeTrafficResult{Batches: 7, Records: 28672, Bytes: 1863232, Elapsed: nativeTrafficPhase + 6*time.Millisecond, Failure: "deadline", LastStatus: 200, LastBodyBytes: 28224, ClientElapsed: 8449 * time.Millisecond, ClientWaitElapsed: time.Millisecond, ClientWorkElapsed: 8448 * time.Millisecond, ReceiptValid: true}
}

func TestNativePacingRecordedDeadlineRequiresParentProofAndRealTraffic(t *testing.T) {
	exitOne := exec.Command("/bin/sh", "-c", "exit 1").Run()
	exitTwo := exec.Command("/bin/sh", "-c", "exit 2").Run()
	killed := exec.Command("/bin/sleep", "10")
	if err := killed.Start(); err != nil {
		t.Fatal(err)
	}
	if err := killed.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	signalExit := killed.Wait()
	if exitOne == nil || exitTwo == nil || signalExit == nil {
		t.Fatal("missing real owned process exit evidence")
	}
	for _, mode := range []string{"eligible-partial", "eligible-header-wait", "headers-extra-body", "headers-false-ack", "headers-extra-bytes", "headers-all-acks", "headers-request", "headers-status", "headers-missing-receipt", "headers-live-phase", "headers-exit-two", "headers-parent-cancel", "eligible-last-ack", "eligible-all-acks-deadline", "parent-cancel", "parent-deadline", "phase-live", "zero-deadline", "short-phase", "late-phase", "not-joined", "signal", "wait-delay", "joined-error", "exit-two", "exit-zero", "no-receipt", "no-acks", "zero-bytes", "status", "request", "acknowledgement", "receipt-error", "records", "bytes", "last-body", "oversized-body", "false-ack", "all-acks-plus-partial", "no-client-wall", "no-work", "negative-wait", "overlapping-time"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			until := now
			ctx := context.Background()
			r := nativePartialTrafficFixture()
			processErr := exitOne
			if strings.HasPrefix(mode, "headers-") || mode == "eligible-header-wait" {
				r.LastStatus = 0
				r.LastBodyBytes = 0
				r.LastAcknowledged = false
				r.Bytes = r.Batches * nativeTrafficRecordsPerBatch * nativeTrafficRecordBytes
			}
			switch mode {
			case "headers-extra-body":
				r.LastBodyBytes = 1
				r.Bytes++
			case "headers-false-ack":
				r.LastAcknowledged = true
			case "headers-extra-bytes":
				r.Bytes++
			case "headers-all-acks":
				r.Batches = nativeTrafficBatches
				r.Records = nativeTrafficRecords
				r.Bytes = nativeTrafficPayload
			case "eligible-last-ack":
				r.LastAcknowledged = true
				r.LastBodyBytes = nativeTrafficRecordsPerBatch * nativeTrafficRecordBytes
				r.Bytes = r.Batches * r.LastBodyBytes
			case "eligible-all-acks-deadline":
				r.Batches = nativeTrafficBatches
				r.Records = nativeTrafficRecords
				r.Bytes = nativeTrafficPayload
				r.LastAcknowledged = true
				r.LastBodyBytes = nativeTrafficRecordsPerBatch * nativeTrafficRecordBytes
			case "parent-cancel", "headers-parent-cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "parent-deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, now.Add(-time.Second))
				defer cancel()
			case "phase-live", "headers-live-phase":
				until = now.Add(time.Nanosecond)
			case "zero-deadline":
				until = time.Time{}
			case "short-phase":
				r.Elapsed = nativeTrafficPhase - time.Nanosecond
			case "late-phase":
				r.Elapsed = nativeTrafficPhase + 250*time.Millisecond + time.Nanosecond
			case "not-joined":
				processErr = errors.New("unknown process failure")
			case "signal":
				processErr = signalExit
			case "wait-delay":
				processErr = exec.ErrWaitDelay
			case "joined-error":
				processErr = errors.Join(exitOne, exec.ErrWaitDelay)
			case "exit-two", "headers-exit-two":
				processErr = exitTwo
			case "exit-zero":
				processErr = nil
			case "no-receipt", "headers-missing-receipt":
				r.ReceiptValid = false
			case "no-acks":
				r.Batches = 0
				r.Records = 0
				r.Bytes = r.LastBodyBytes
			case "zero-bytes":
				r.Bytes = 0
				r.LastBodyBytes = 0
			case "status", "headers-status":
				r.LastStatus = 503
			case "request", "headers-request":
				r.Failure = "request"
			case "acknowledgement":
				r.Failure = "acknowledgement"
			case "receipt-error":
				r.Failure = "receipt_shape"
			case "records":
				r.Records++
			case "bytes":
				r.Bytes++
			case "last-body":
				r.LastBodyBytes = 0
			case "oversized-body":
				r.LastBodyBytes = nativeTrafficRecordsPerBatch*nativeTrafficRecordBytes + 1
				r.Bytes = r.Batches*nativeTrafficRecordsPerBatch*nativeTrafficRecordBytes + r.LastBodyBytes
			case "false-ack":
				r.LastAcknowledged = true
			case "all-acks-plus-partial":
				r.Batches = nativeTrafficBatches
				r.Records = nativeTrafficRecords
			case "no-client-wall":
				r.ClientElapsed = 0
			case "no-work":
				r.ClientWorkElapsed = 0
			case "negative-wait":
				r.ClientWaitElapsed = -1
			case "overlapping-time":
				r.ClientWorkElapsed = r.ClientElapsed
			}
			want := mode == "eligible-header-wait" || mode == "eligible-partial" || mode == "eligible-last-ack" || mode == "eligible-all-acks-deadline"
			if got := nativeTrafficRecordedDeadline(ctx, r, processErr, until, now); got != want {
				t.Fatal("deadline eligibility", mode, got, want)
			}
		})
	}
}

// Execute the actual parent helper with one bounded synthetic local command;
// no Docker operation, network request, packet or collector runs in this test.
func TestNativePacingRecordedDeadlineRemainsIncompleteAndSmallArtifactFails(t *testing.T) {
	work := t.TempDir()
	script := "#!/bin/sh\n/bin/cat >/dev/null\nprintf '%s\\n' \"$ASSERVAT_DEADLINE_RECEIPT\"\nexit 1\n"
	if err := os.WriteFile(filepath.Join(work, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	r := nativePartialTrafficFixture()
	raw, err := json.Marshal(nativeTrafficReceipt{Batches: r.Batches, Records: r.Records, Bytes: r.Bytes, Elapsed: r.ClientElapsed, WaitElapsed: r.ClientWaitElapsed, WorkElapsed: r.ClientWorkElapsed, Failure: r.Failure, LastStatus: r.LastStatus, LastBodyBytes: r.LastBodyBytes, LastAcknowledged: r.LastAcknowledged})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", work)
	t.Setenv("ASSERVAT_DEADLINE_RECEIPT", string(raw))
	ctx, cancel := context.WithTimeout(t.Context(), nativeTrafficPhase+time.Second)
	defer cancel()
	got, err := nativePacingNodeTraffic(ctx, nativeTrafficHelper{Cluster: "owned", SHA256: strings.Repeat("1", 64), Nodes: []string{"owned-worker"}}, "owned-worker", "10.0.0.2")
	if err == nil || !errors.Is(err, errNativeTrafficRecordedDeadline) || got.Failure != "deadline" || got.Batches != 7 || got.Records != 28672 || got.Bytes != 1863232 || !got.ReceiptValid || got.LastAcknowledged {
		t.Fatal("incomplete result was erased or not classified", got, err)
	}
	// The installed caller proceeds only to its existing independently measured
	// artifact gate. Real bytes in a small local file cannot become near8MiB.
	path := filepath.Join(work, "small.pcapng")
	if err := os.WriteFile(path, make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if nativePacingRequireNearFullRecording(info.Size()) == nil {
		t.Fatal("eligible traffic relabeled small actual bytes as near-full")
	}
	if nativePacingRequireNearFullRecording(artifact.RecordingNativeLimit-nativePacingWindow) != nil {
		t.Fatal("original near-full boundary changed")
	}
}

func TestNativePacingTrafficOutputCopyCannotBypassBound(t *testing.T) {
	var output nativeTrafficOutput
	// os/exec falls back to io.Copy with a plain reader; an embedded Buffer's
	// promoted ReadFrom must not bypass the fixture's 2048-byte Write bound.
	_, err := io.Copy(&output, struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 2049))})
	if err == nil || !output.exceeded || output.Len() > 2048 {
		t.Fatal("stream copy bypassed output bound", output.Len(), output.exceeded, err)
	}
	var exact nativeTrafficOutput
	if _, err := io.Copy(&exact, struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 2048))}); err != nil || exact.Len() != 2048 || exact.exceeded {
		t.Fatal("exact traffic output bound changed", exact.Len(), err)
	}
}

func TestNativePacingNonzeroCommandCannotHideReceiptOverflow(t *testing.T) {
	work := t.TempDir()
	receipt := filepath.Join(work, "receipt")
	extra := filepath.Join(work, "extra")
	r := nativePartialTrafficFixture()
	raw, err := json.Marshal(nativeTrafficReceipt{Batches: r.Batches, Records: r.Records, Bytes: r.Bytes, Elapsed: r.ClientElapsed, WaitElapsed: r.ClientWaitElapsed, WorkElapsed: r.ClientWorkElapsed, Failure: r.Failure, LastStatus: r.LastStatus, LastBodyBytes: r.LastBodyBytes})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(receipt, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(extra, []byte(strings.Repeat("x", 2049)), 0600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n/bin/cat \"$ASSERVAT_RECEIPT_PREFIX\"\n/bin/sleep 0.01\n/bin/cat \"$ASSERVAT_RECEIPT_EXTRA\"\nexit 1\n"
	if err = os.WriteFile(filepath.Join(work, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", work)
	t.Setenv("ASSERVAT_RECEIPT_PREFIX", receipt)
	t.Setenv("ASSERVAT_RECEIPT_EXTRA", extra)
	got, err := nativePacingNodeTraffic(t.Context(), nativeTrafficHelper{Cluster: "owned", SHA256: strings.Repeat("1", 64), Nodes: []string{"owned-worker"}}, "owned-worker", "10.0.0.2")
	if err == nil || errors.Is(err, errNativeTrafficRecordedDeadline) || got.ReceiptValid || got.Failure != "receipt_size" {
		t.Fatal("exit1 hid a bounded-reader failure", got, err)
	}
}
