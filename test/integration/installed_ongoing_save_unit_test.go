package integration

import (
	"fmt"
	"testing"
	"time"
)

func TestOngoingSavePacketWindow(t *testing.T) {
	t0 := time.Unix(1000, 0)
	row := func(at float64, src, dst int, payload string) string {
		return fmt.Sprintf("%.6f\t%d\t%d\t%s\n", at, src, dst, payload)
	}
	good := row(990, 40000, 9102, "") + row(990.001, 9102, 40000, "")
	if n, err := ongoingSavePackets([]byte(good), t0, 15*time.Second); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	for name, bad := range map[string]string{
		"outside":  good + row(980, 40000, 9101, ""),
		"after":    good + row(1001, 40000, 9103, ""),
		"excluded": good + row(995, 40000, 9101, ""),
		"payload":  row(990, 40000, 9102, "aa"),
		"none":     "",
		"columns":  "990\t1\n",
	} {
		if _, err := ongoingSavePackets([]byte(bad), t0, 15*time.Second); err == nil {
			t.Fatal("accepted", name)
		}
	}
}
