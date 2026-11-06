package artifact

import (
	"testing"
	"time"
)

func TestLogCaptureOriginalWindowAndIndependentHistoricalBound(t *testing.T) {
	l := &LogCapture{ActionID: "a0123456789abcdef01234567", BeforeMillis: int64(time.Hour / time.Millisecond), AfterMillis: 1000, Streams: "combined", TimeoutMillis: 10000, MaxNativeBytes: LogNativeLimit}
	anchor := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	start, end, err := l.Window(anchor)
	if err != nil || !start.Equal(anchor.Add(-time.Hour)) || !end.Equal(anchor.Add(time.Second)) {
		t.Fatal("historical window was rebased or treated as capture runtime", err)
	}
	for _, mode := range []string{"stdout", "stderr", "both", ""} {
		copy := *l
		copy.Streams = mode
		if copy.Valid() {
			t.Fatal("unsupported exact stream or authored alias became accepted provenance", mode)
		}
	}
	if _, _, err := l.Window(time.Time{}); err == nil {
		t.Fatal("missing anchor replaced with now")
	}
}

func TestLogsExpectationIsDistinctRawAPIAction(t *testing.T) {
	e := typedExpectation(t, LogsArtifact, LogNativeLimit)
	e.ExecutionClass, e.NodeUID, e.NodeBootID, e.DataClass = ContextAPIExecution, "", "", "raw"
	e.Logs = &LogCapture{ActionID: e.ActionID, BeforeMillis: 3600000, AfterMillis: 1000, Streams: "combined", TimeoutMillis: 10000, MaxNativeBytes: e.Registration.NativeLimit}
	if e.Validate() != nil || !e.ServedClass() {
		t.Fatal("accepted logs action refused", e.Validate())
	}
	for _, change := range []string{"missing", "pod-status", "wrong-cap", "late-window", "recording", "profile", "node-class", "metadata"} {
		x := e
		logs := *e.Logs
		x.Logs = &logs
		switch change {
		case "missing":
			x.Logs = nil
		case "pod-status":
			x.NativeType = PodStatusArtifact
		case "wrong-cap":
			x.Logs.MaxNativeBytes--
		case "late-window":
			x.TriggeredAt = x.Registration.WriteUntil
		case "recording":
			x.Recording = &Recording{}
		case "profile":
			x.Profile = &GoProfileAcquisition{}
		case "node-class":
			x.ExecutionClass, x.NodeUID, x.NodeBootID = ContextNodeExecution, "node", "10000000-0000-4000-8000-000000000008"
		case "metadata":
			x.DataClass = "metadata"
		}
		if x.Validate() == nil {
			t.Fatal("logs field escaped exact source/action branch", change)
		}
	}
}
