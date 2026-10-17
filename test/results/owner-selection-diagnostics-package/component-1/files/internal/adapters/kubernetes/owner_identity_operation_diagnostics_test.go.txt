package kubernetes

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestOwnerOperationDiagnosticsNeverRenderDriverValues(t *testing.T) {
	secret := errors.New("synthetic-private-identity-token-and-password")
	inner := ownerOperationError(ownerNativeRetained, secret)
	outer := ownerOperationError(ownerSelectionInitialNative, inner)
	want := "owner operation: selection.initial-native: native.retained-branch"
	for _, format := range []string{"%s", "%v", "%+v"} {
		if got := fmt.Sprintf(format, outer); got != want || strings.Contains(got, secret.Error()) {
			t.Fatal("diagnostic rendered non-enumerated bytes", got)
		}
	}
	if !errors.Is(outer, secret) || errors.Is(outer, cfg.ErrUnavailable) {
		t.Fatal("pass-through error classification changed")
	}
	normalized := ownerOperationUnavailable(ownerSelectionFinalNative, inner)
	if !errors.Is(normalized, cfg.ErrUnavailable) || errors.Is(normalized, secret) || normalized.Error() != "owner operation: selection.final-native: native.retained-branch" {
		t.Fatal("normalized boundary changed classification or lost fixed detail")
	}
	if got := ownerOperationError(ownerOperationCheck(255), secret).Error(); got != "owner operation: unknown" {
		t.Fatal("unknown enum rendered uncontrolled diagnostic", got)
	}
}

func TestOwnerOriginalDiagnosticKeepsExactFieldsAndFirstDifference(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*ownerIdentityOperationNative)
	}{
		{"input", "original.input", func(v *ownerIdentityOperationNative) { v.input.Namespace.Name = "changed" }},
		{"bridge-uid", "original.bridge", func(v *ownerIdentityOperationNative) { v.retained.bridge.UID = "changed" }},
		{"bridge-version", "original.bridge", func(v *ownerIdentityOperationNative) { v.retained.bridge.ResourceVersion = "changed" }},
		{"bridge-state", "original.bridge", func(v *ownerIdentityOperationNative) { v.retained.bridge.State.SetupID = "changed" }},
		{"resources-uid", "original.resources", func(v *ownerIdentityOperationNative) { v.retained.resources.UID = "changed" }},
		{"resources-version", "original.resources", func(v *ownerIdentityOperationNative) { v.retained.resources.ResourceVersion = "changed" }},
		{"resources-state", "original.resources", func(v *ownerIdentityOperationNative) { v.retained.resources.State.SetupID = "changed" }},
		{"source-proof", "original.source-proof", func(v *ownerIdentityOperationNative) { v.source.proof.observation.NamespaceUID = "changed" }},
		{"source-guards", "original.source-proof", func(v *ownerIdentityOperationNative) { v.source.proof.guards[1] = "changed" }},
		{"fleet-reference", "original.source-configuration", func(v *ownerIdentityOperationNative) { v.source.fleetRef.UID = "changed" }},
		{"owner-reference", "original.source-configuration", func(v *ownerIdentityOperationNative) { v.source.ownerRef.UID = "changed" }},
		{"owner-configuration", "original.source-configuration", func(v *ownerIdentityOperationNative) { v.source.owner.Pool.ServiceUID = "changed" }},
		{"deployment-version", "original.deployment", func(v *ownerIdentityOperationNative) { v.source.deployment.ResourceVersion = "changed" }},
		{"deployment-spec", "original.deployment", func(v *ownerIdentityOperationNative) {
			replicas := int32(1)
			v.source.deployment.Spec.Replicas = &replicas
		}},
		{"source-account", "original.source-accounts", func(v *ownerIdentityOperationNative) { v.source.account.UID = "changed" }},
		{"source-administrator", "original.source-accounts", func(v *ownerIdentityOperationNative) { v.source.administrator.UID = "changed" }},
		{"owner-account", "original.owner-objects", func(v *ownerIdentityOperationNative) { v.account.UID = "changed" }},
		{"owner-service", "original.owner-objects", func(v *ownerIdentityOperationNative) { v.service.UID = "changed" }},
		{"accepted-configuration", "original.accepted-configuration", func(v *ownerIdentityOperationNative) { v.accepted.Configuration.Pool.ServiceUID = "changed" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var a, b ownerIdentityOperationNative
			tc.change(&b)
			if got := ownerIdentityOperationOriginalDifference(a, b).String(); got != tc.want || ownerIdentityOperationOriginalsEqual(a, b) {
				t.Fatal("exact original difference lost or misidentified", got, tc.want)
			}
			// Earlier input mismatch wins over every later independent group.
			b.input.Namespace.Name = "earlier"
			if got := ownerIdentityOperationOriginalDifference(a, b).String(); got != "original.input" {
				t.Fatal("changed original check precedence", got)
			}
		})
	}
}

func TestOwnerOriginalDiagnosticDoesNotCompareObservationDates(t *testing.T) {
	var a, b ownerIdentityOperationNative
	at := time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)
	b.until = at
	b.retained.until = at
	b.retained.bridge.ValidUntil = at
	b.retained.resources.ValidUntil = at
	b.source.proof.observation.ObservedAt = at
	b.source.proof.observation.FreshUntil = at.Add(time.Second)
	b.source.proof.observation.Fleet.ObservedAt = at
	b.source.proof.observation.Fleet.FreshUntil = at.Add(time.Second)
	b.source.proof.observation.Owner.ObservedAt = at
	b.source.proof.observation.Owner.FreshUntil = at.Add(time.Second)
	b.accepted.ObservedAt = at
	b.accepted.FreshUntil = at.Add(time.Second)
	if !ownerIdentityOperationOriginalsEqual(a, b) || ownerIdentityOperationOriginalDifference(a, b) != ownerOperationNoFailure {
		t.Fatal("independent observation dates became identity comparisons")
	}
}
