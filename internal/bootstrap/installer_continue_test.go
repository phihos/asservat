package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// The operator's stop message names the step and class, never inner text.
func TestInstallerContinuationStopIsFixed(t *testing.T) {
	err := &InstallerContinuationStop{Step: "bridge/probe", Err: errors.Join(cfg.ErrChanged, errors.New("secret-bearing detail"))}
	if err.Error() != "installer continuation stopped at bridge/probe (changed)" || !errors.Is(err, cfg.ErrChanged) {
		t.Fatal(err.Error())
	}
	nested := &InstallerContinuationStop{Step: "worker/roles-provision", Err: &postgres.ProvisionStop{Step: "authenticate:configuration-source", Err: cfg.ErrUnavailable}}
	if nested.Error() != "installer continuation stopped at worker/roles-provision/authenticate:configuration-source (unavailable)" {
		t.Fatal(nested.Error())
	}
}

// A lookup-only replay hides the cause; the stop names the first attempt too.
func TestConvergeStopNamesFirstAttempt(t *testing.T) {
	steps := []error{&postgres.ProvisionStop{Step: "complete:configuration-fleet", Err: cfg.ErrUnavailable}, &postgres.ProvisionStop{Step: "role:configuration-fleet", Err: cfg.ErrChanged}}
	n := 0
	err := converge(context.Background(), time.Minute, func() error { n++; return steps[n-1] })
	stop := &InstallerContinuationStop{Step: "worker/roles-provision", Err: err}
	if want := "installer continuation stopped at worker/roles-provision/role:configuration-fleet after 2 attempts; first complete:configuration-fleet (unavailable) (changed)"; stop.Error() != want || !errors.Is(err, cfg.ErrChanged) {
		t.Fatal(stop.Error())
	}
}
