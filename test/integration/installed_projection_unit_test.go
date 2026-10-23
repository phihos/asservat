package integration

import (
	"testing"
	"time"
)

func TestInstalledApprovedScopeSelection(t *testing.T) {
	for _, tc := range []struct {
		scope string
		want  bool
	}{
		{"openid evidence:read", true}, {"evidence:read evidence:download", false}, {"evidence:read evidence:capture", false}, {"openid", false}, {"evidence:read-other", false},
	} {
		if got := installedApprovedScopes(tc.scope); got != tc.want {
			t.Fatal(tc.scope, got)
		}
	}
}
func TestInstalledProjectionPollsStayWithinOneOriginalLifetime(t *testing.T) {
	start := time.Now()
	until := start.Add(time.Minute)
	for poll := 0; poll < 4; poll++ {
		now := start.Add(time.Duration(poll) * 12 * time.Second)
		next, err := installedProjectionPollTime(start, until, now, time.Second, poll)
		if err != nil || !next.Equal(start.Add(time.Duration(poll+1)*12*time.Second)) {
			t.Fatal("cold startup poll spacing", poll, next, err)
		}
	}
	for _, tc := range []struct {
		name  string
		now   time.Time
		retry time.Duration
		poll  int
	}{
		{"expired", until, time.Second, 0}, {"too-late", until.Add(-time.Second), time.Second, 3}, {"exhausted", start, time.Second, 4}, {"clock-rollback", start.Add(-time.Nanosecond), time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := installedProjectionPollTime(start, until, tc.now, tc.retry, tc.poll); err == nil {
				t.Fatal("invalid poll renewed query or spent another slot")
			}
		})
	}
	now := start.Add(20 * time.Second)
	next, err := installedProjectionPollTime(start, until, now, 3*time.Second, 0)
	if err != nil || !next.Equal(now.Add(3*time.Second)) {
		t.Fatal("server not-before was ignored")
	}
}
