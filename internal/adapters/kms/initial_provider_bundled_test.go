package kms

import (
	"context"
	"testing"
	"time"
)

func TestDefaultInitialIssuerStillRejectsInheritedEntity(t *testing.T) {
	f := newInitialProviderFixture(t)
	f.parent.Entity = "20000000-0000-4000-8000-000000000012"
	if _, _, err := f.issuer.Check(context.Background(), time.Now().Add(15*time.Minute)); err == nil {
		t.Fatal("default constructor accepted service entity")
	}
}
