package mtls

import (
	"context"
	"errors"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

type emptyCatalogSources struct{}

func (emptyCatalogSources) ReadConnectorIdentitySource(context.Context) (value.ConnectorIdentitySource, error) {
	return value.ConnectorIdentitySource{}, value.ErrUnavailable
}

// ADR-185/194: a promoted owner with an empty catalog builds an ingress that
// admits no connector; a nil admission list is still refused.
func TestContextStartIngressEmptyCatalogDeniesEveryStart(t *testing.T) {
	const root = "55000000-0000-4000-8000-000000000001"
	owners := &app.OwnerAuthenticator{Now: time.Now}
	if _, err := NewContextStartIngress(root, &OwnerCredentials{}, owners, nil, time.Now); err == nil {
		t.Fatal("nil admission list accepted")
	}
	ingress, err := NewContextStartIngress(root, &OwnerCredentials{}, owners, []ContextStartConnectorAdmission{}, time.Now)
	if err != nil {
		t.Fatal("empty catalog refused", err)
	}
	if _, _, err = ingress.AuthenticateContextStart(context.Background(), nil, contracts.APIContextHello{Format: contracts.APIContextExchangeFormat}, emptyCatalogSources{}); !errors.Is(err, value.ErrDenied) {
		t.Fatal("start admitted without a catalog entry", err)
	}
}
