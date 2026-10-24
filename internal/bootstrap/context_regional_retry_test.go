package bootstrap

import (
	"errors"
	"testing"
	"time"
)

type openingStepFixture string

func (e openingStepFixture) Error() string     { return "opening" }
func (e openingStepFixture) FixedStep() string { return string(e) }

func TestOpeningRetryBacksOffOnlyAfterTLSRefusal(t *testing.T) {
	if openingRetry(nil) != time.Second || openingRetry(errors.New("x")) != time.Second || openingRetry(openingStepFixture("setup-begin")) != time.Second {
		t.Fatal("ordinary ends retry after one second")
	}
	if openingRetry(errors.Join(errors.New("wrapped"), openingStepFixture("tls"))) != 30*time.Second {
		t.Fatal("a TLS refusal must back off")
	}
}
