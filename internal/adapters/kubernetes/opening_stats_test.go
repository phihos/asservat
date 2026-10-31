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
