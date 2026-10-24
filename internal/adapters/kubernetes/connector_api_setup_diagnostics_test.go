package kubernetes

import (
	"errors"
	"strings"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestConnectorAPISetupDiagnosticKeepsOriginalFailureClassification(t *testing.T) {
	private := errors.New("private-token-host-workload")
	until := time.Now().Add(time.Second)
	input := &connectorAPIStepError{phase: "source-close", until: until, step: "source-close@1s private trace", err: private}
	out := connectorAPISetupDiagnostic(errors.Join(cfg.ErrUnavailable, input))
	var metadata interface {
		ContextStartSetupStep() string
		ContextStartSetupUntil() time.Time
	}
	if !errors.Is(out, cfg.ErrUnavailable) || errors.Is(out, private) || !errors.As(out, &metadata) || metadata.ContextStartSetupStep() != "source-close" || !metadata.ContextStartSetupUntil().Equal(until) || strings.Contains(out.Error(), "private") {
		t.Fatal("producer diagnostic changed classification or exposed its dependency", out)
	}
	if connectorAPISetupDiagnostic(private) != cfg.ErrUnavailable || connectorAPISetupDiagnostic(nil) != cfg.ErrUnavailable {
		t.Fatal("unrecognized errors changed the original sentinel")
	}
}

func TestConnectorAPISetupDiagnosticKeepsCompletedMarks(t *testing.T) {
	input := &connectorAPIStepError{phase: "settings-guard", step: "settings-guard@3s after [source-open@20ms owned-process@1.2s]", err: errors.New("private")}
	var fixed interface{ FixedStep() string }
	if out := connectorAPISetupDiagnostic(input); !errors.As(out, &fixed) || fixed.FixedStep() != "setup after [source-open@20ms owned-process@1.2s]" {
		t.Fatal("completed setup marks were dropped", out)
	}
}
