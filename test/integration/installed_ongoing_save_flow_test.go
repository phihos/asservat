package integration

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Authored inputs only: the builtin ongoing networkHeaders recorder (30s ring,
// 30s history) with a reviewed Save opt-in. Three header-visible destination
// ports separate outside-window, retained pre-T0 and post-T0 traffic.
const (
	installedOngoingSaveName   = "regional-ongoing-packets"
	installedOngoingSaveFilter = "tcp portrange 9101-9103"
	ongoingSaveOutsidePort     = 9101
	ongoingSaveRetainedPort    = 9102
	ongoingSaveAfterPort       = 9103
	ongoingSaveBefore          = 15 * time.Second
	ongoingSaveLifetime        = 300
	// ongoingSaveDiskBytes is the ongoing-save-disk focus's collector ring
	// volume (ADR-278): room for the one 4 x 4 MiB sealed ring with headroom.
	ongoingSaveDiskBytes = 64 << 20
)

// installedOngoingFocus selects the installed ongoing packet source flow:
// Save qualification or the automatic incident snapshot.
func installedOngoingFocus() bool {
	f := installedJourneyFocus()
	return f == "ongoing-save" || f == "ongoing-save-disk" || f == "ongoing-incident" || f == "ongoing-syscall" || f == "ongoing-mixed" || f == "live-observation"
}

// ongoingSavePackets requires retained pre-T0 marker headers inside the
// requested window and rejects outside-window, post-T0 and payload bytes.
func ongoingSavePackets(out []byte, t0 time.Time, before time.Duration) (int, error) {
	retained := 0
	for row, line := range strings.Split(strings.TrimRight(string(out), "\r\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return 0, fmt.Errorf("row %d: columns", row+1)
		}
		if fields[3] != "" {
			return 0, fmt.Errorf("row %d: payload in header-only capture", row+1)
		}
		seconds, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return 0, fmt.Errorf("row %d: time", row+1)
		}
		whole, frac := math.Modf(seconds)
		at := time.Unix(int64(whole), int64(frac*1e9))
		if at.After(t0) || at.Before(t0.Add(-before)) {
			return 0, fmt.Errorf("row %d: packet at %s outside [T0-%s, T0=%s]", row+1, at.Format(time.RFC3339Nano), before, t0.Format(time.RFC3339Nano))
		}
		ports := fields[1] + "," + fields[2]
		switch {
		case strings.Contains(ports, strconv.Itoa(ongoingSaveOutsidePort)), strings.Contains(ports, strconv.Itoa(ongoingSaveAfterPort)):
			return 0, fmt.Errorf("row %d: excluded marker port present", row+1)
		case strings.Contains(ports, strconv.Itoa(ongoingSaveRetainedPort)):
			retained++
		}
	}
	if retained == 0 {
		return 0, fmt.Errorf("no retained pre-T0 marker packets")
	}
	return retained, nil
}
