package integration

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ciNativeFocusGroups reads the grouped installed suites of
// scripts/ci-native.sh as their ASSERVAT_JOURNEY_FOCUS values.
func ciNativeFocusGroups(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../scripts/ci-native.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	focus := map[string]string{}
	for _, m := range regexp.MustCompile(`\[continuation-([a-z-]+)\]="env ASSERVAT_JOURNEY_FOCUS=([a-z-]+) `).FindAllStringSubmatch(source, -1) {
		focus[m[1]] = m[2]
	}
	block := regexp.MustCompile(`(?s)\ngroups=\((.*?)\n\)`).FindStringSubmatch(source)
	if block == nil {
		t.Fatal("ci-native.sh has no groups")
	}
	groups := map[string]string{}
	for _, m := range regexp.MustCompile(`"([a-z -]+)"`).FindAllStringSubmatch(block[1], -1) {
		var foci []string
		for _, member := range strings.Fields(m[1]) {
			if focus[member] == "" {
				t.Fatal("group member without a focus", member)
			}
			foci = append(foci, focus[member])
		}
		groups[m[1]] = strings.Join(foci, ",")
	}
	if len(groups) < 2 {
		t.Fatal("too few groups parsed", groups)
	}
	return groups
}

func TestInstalledFocusGroupsShareOneBootstrap(t *testing.T) {
	for group, foci := range ciNativeFocusGroups(t) {
		t.Run(group, func(t *testing.T) {
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", foci)
			if err := installedFocusGroupError(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInstalledFocusGroupRefusals(t *testing.T) {
	for foci, want := range map[string]string{
		"journey,manual-logs":              "needs another bootstrap",
		"journey,ongoing-save":             "needs another bootstrap",
		"manual-http,ongoing-save":         "needs another bootstrap",
		"ongoing-save,manual-profile":      "needs another bootstrap",
		"policy,journey":                   "must run last",
		"policy-recording,ongoing-save":    "must run last",
		"restart,browser":                  "must run first",
		"journey,chain":                    "own installation",
		"journey,journey":                  "listed twice",
		"ongoing-save,native-paced":        "needs another bootstrap",
		"live-observation,ongoing-syscall": "must run last",
	} {
		t.Run(foci, func(t *testing.T) {
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", foci)
			if err := installedFocusGroupError(); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want %q", err, want)
			}
		})
	}
}

// Every focus keeps the budget it has alone: the shared installation funds
// the sum, and a single focus is unchanged.
func TestInstalledFocusGroupBudgetsAdd(t *testing.T) {
	type budget struct{ records, normal, resolution, reserveBytes, reserveObjects, logins int64 }
	measure := func(foci string) budget {
		t.Setenv("ASSERVAT_JOURNEY_FOCUS", foci)
		p := nativeCapacityProfile()
		b, o := installedRegionalContextReserve()
		return budget{p.Records, p.Lanes.Normal.Records, p.Lanes.Resolution.Records, b, o, 8 * installedFundedRuns()}
	}
	for _, foci := range ciNativeFocusGroups(t) {
		var want budget
		for _, focus := range strings.Split(foci, ",") {
			one := measure(focus)
			want = budget{want.records + one.records, want.normal + one.normal, want.resolution + one.resolution, want.reserveBytes + one.reserveBytes, want.reserveObjects + one.reserveObjects, want.logins + one.logins}
		}
		if got := measure(foci); got != want {
			t.Fatalf("%s: budget %+v, want the sum %+v", foci, got, want)
		}
	}
	if single := measure("manual-raw"); single.records != 16 || single.normal != 128 || single.resolution != 8 || single.logins != 8 {
		t.Fatal("single focus budget changed", single)
	}
}

// The additive bootstrap parts are installed when any listed focus needs
// them; the focus-time answer stays the current focus'.
func TestInstalledAnyFocus(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "share,logresource")
	if installedJourneyFocus() != "share" || !installedAnyFocus("logresource") || installedAnyFocus("alert") {
		t.Fatal("bootstrap focus or union wrong")
	}
	installedEachFocus(func() {
		if installedJourneyFocus() != "share" && installedJourneyFocus() != "logresource" {
			t.Fatal("each focus", installedJourneyFocus())
		}
	})
	if installedJourneyFocus() != "share" || installedFocusCurrent != "" {
		t.Fatal("installedEachFocus left a current focus")
	}
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-logs")
	if installedJourneyFocus() != "manual-logs" || len(installedJourneyFoci()) != 1 || installedFocusCount() != 1 || installedFocusGroupError() != nil {
		t.Fatal("single focus changed")
	}
}
