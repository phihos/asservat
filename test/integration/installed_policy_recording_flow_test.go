package integration

import (
	"fmt"
	"strings"

	"asservat.local/asservat/internal/domain/collector"
)

func policyRecordingCreditRefusal(logs []byte, captureID string) bool {
	expected := "node collector: capture " + captureID + " stopped: " + collector.ErrObservationBudgetExhausted.Error()
	for _, line := range strings.Split(string(logs), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), expected) {
			return true
		}
	}
	return false
}

// The offline regression and actual installed read use identical field options.
func policyRecordingFieldArgs(file string) []string {
	return []string{"-r", file, "-T", "fields", "-E", "occurrence=f", "-e", "frame.number", "-e", "tcp.flags.ack", "-e", "tcp.payload"}
}

// Keep the trailing empty payload column; TrimSpace would silently discard a
// valid last packet or hide malformed decoder output during expensive native work.
func policyRecordingPacketFields(out []byte) (int, error) {
	count := 0
	for row, line := range strings.Split(strings.TrimRight(string(out), "\r\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		// The actual maintained tshark fields exporter emits True/False for
		// this boolean, rather than the numeric spelling assumed by the old
		// synthetic rows. Keep a strict ACK-true and empty-payload predicate.
		class := ""
		switch {
		case len(fields) != 3:
			class = "columns"
		case fields[0] == "":
			class = "frame-number"
		case fields[1] != "True":
			class = "ack"
		case fields[2] != "":
			class = "payload"
		}
		if class != "" {
			return 0, fmt.Errorf("native packet violates ACK-only header projection: row %d (%s)", row+1, class)
		}
		count++
	}
	return count, nil
}
