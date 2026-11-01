package kubernetes

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

type statsRoundTrip struct{}

func (statsRoundTrip) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

// The opening client counts round trips and limiter waits, then resets.
func TestOpeningStatsCountAndReset(t *testing.T) {
	OpeningStatsLine()
	c := WithOpeningBurst(&rest.Config{Host: "https://example.invalid"})
	rt := c.WrapTransport(statsRoundTrip{})
	for range OpeningBurst + 6 {
		if err := c.RateLimiter.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := rt.RoundTrip(&http.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	slow := measuredLimiter{flowcontrol.NewTokenBucketRateLimiter(5, 1)}
	for range 2 {
		if err := slow.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	line := OpeningStatsLine()
	if !strings.Contains(line, "requests=106 ") || !strings.Contains(line, "limiter-waits>=100ms=1 ") {
		t.Fatal("opening stats", line)
	}
	if OpeningStatsLine() != "" {
		t.Fatal("stats not reset")
	}
}

func TestOpeningRequestKind(t *testing.T) {
	for path, want := range map[string]string{
		"/api/v1/namespaces/app/pods/p-0":                                     "GET pods",
		"/api/v1/namespaces/app":                                              "GET namespaces",
		"/apis/apps/v1/namespaces/app/deployments/d":                          "GET deployments",
		"/apis/authentication.k8s.io/v1/tokenreviews":                         "GET tokenreviews",
		"/api/v1/namespaces/app/serviceaccounts/s/token":                      "GET serviceaccounts/token",
		"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/x": "GET validatingadmissionpolicies",
	} {
		r, _ := http.NewRequest(http.MethodGet, "https://k8s.invalid"+path, nil)
		if got := requestKind(r); got != want {
			t.Fatal(path, got)
		}
	}
}
