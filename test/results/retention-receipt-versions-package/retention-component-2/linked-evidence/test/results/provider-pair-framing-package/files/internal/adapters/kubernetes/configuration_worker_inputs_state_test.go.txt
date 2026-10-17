package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// This is public-state shape evidence only. Synthetic original receipts do
// not exercise the retained bridge, current guard, actual SQL role verification
// or provider setup and must never be used as authority by a native fixture.
func configurationWorkerInputStateFixture(t *testing.T) (string, contracts.InitialRuntimeResourceState, time.Time) {
	t.Helper()
	s, state, now := workerProjectionStateFixture(t)
	installation := s.initial.InstallationID
	prefix := strings.ReplaceAll(installation, "-", "")
	state.WorkerLayout, state.OwnerLayout = contracts.HubWorkerProviderInstalledLayout, contracts.OwnerProviderInstalledLayout
	state.WorkerProvider = &contracts.ConfigurationProviderSelection{AuthMount: "configuration-auth", AuthMountAccessor: "auth_kubernetes_original", AuditCredentials: contracts.WorkerObjectReference{Name: runtimeResourceNames(installation).WorkerProviders, UID: ownerID(14900)}}
	state.OwnerProvider = &contracts.OwnerProviderSelection{AuthMount: "owner-auth", AuthMountAccessor: "auth_owner_original", AuditCredentials: contracts.WorkerObjectReference{Name: contracts.OwnerProviderAuditSecretName(installation), UID: ownerID(14999)}}
	state.WorkerInputs = &contracts.ConfigurationWorkerInputClaim{OperationID: ownerID(14901), PublicDigest: strings.Repeat("d", 64),
		ConfigurationRoot:    contracts.WorkerObjectReference{Name: "asservat-configuration-roles-" + prefix, UID: ownerID(14902)},
		ConfigurationSetupID: ownerID(14903), SQLProjection: contracts.WorkerObjectReference{Name: "asservat-configuration-runtime-" + prefix, UID: ownerID(14904)},
		AuditCredentials: state.WorkerProvider.AuditCredentials, ClaimedAt: now.Add(-time.Second), Until: now.Add(time.Second),
		Receipt: &contracts.ConfigurationWorkerInputReceipt{Configuration: contracts.WorkerObjectReference{Name: runtimeResourceNames(installation).WorkerInputs, UID: ownerID(14905)}, ResourceVersion: "42", ObservedAt: now}}
	return installation, state, now
}

func TestConfigurationWorkerInputClaimRetainsOriginalPredecessorsAndExpiry(t *testing.T) {
	installation, state, now := configurationWorkerInputStateFixture(t)
	before, _ := json.Marshal(state)
	if !configurationWorkerInputsStateValid(installation, state, now) || !configurationWorkerInputsStateValid(installation, state, state.Until.Add(time.Hour)) {
		t.Fatal("positive original provenance lost on historical reopen")
	}
	after, _ := json.Marshal(state)
	if string(before) != string(after) {
		t.Fatal("state validation modified original claim or predecessor")
	}
	p := configurationWorkerInputProvenance(state.WorkerInputs)
	if p.OperationID != state.WorkerInputs.OperationID || p.ConfigurationRoot != state.WorkerInputs.ConfigurationRoot || p.ConfigurationSetupID != state.WorkerInputs.ConfigurationSetupID || p.SQLProjection != state.WorkerInputs.SQLProjection {
		t.Fatal("generated document replaced original predecessor")
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), state.WorkerInputs.Receipt.Configuration.UID) || strings.Contains(string(b), state.WorkerInputs.PublicDigest) {
		t.Fatal("self UID or document digest entered its own body")
	}
	state.WorkerInputs.Receipt = nil
	if !configurationWorkerInputsStateValid(installation, state, state.Until.Add(time.Hour)) {
		t.Fatal("unknown original outcome erased after expiry")
	}
}

func TestConfigurationWorkerInputClaimRejectsOtherPurposeAndOriginalIdentityReuse(t *testing.T) {
	for name, change := range map[string]func(*contracts.InitialRuntimeResourceState){
		"legacy":                  func(s *contracts.InitialRuntimeResourceState) { s.WorkerLayout = contracts.HubWorkerInstalledLayout },
		"mixed":                   func(s *contracts.InitialRuntimeResourceState) { s.OwnerLayout = contracts.OwnerInstalledLayout },
		"selection missing":       func(s *contracts.InitialRuntimeResourceState) { s.WorkerProvider = nil },
		"unacknowledged original": func(s *contracts.InitialRuntimeResourceState) { s.Objects[18].Receipt = nil },
		"original setup":          func(s *contracts.InitialRuntimeResourceState) { s.WorkerInputs.OperationID = s.SetupID },
		"original operation":      func(s *contracts.InitialRuntimeResourceState) { s.WorkerInputs.OperationID = s.Objects[1].OperationID },
		"configuration setup": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.OperationID = s.WorkerInputs.ConfigurationSetupID
		},
		"capacity operation": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.OperationID = s.CapacityProjection.OperationID
		},
		"cleanup operation": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.OperationID = s.CleanupProjection.OperationID
		},
		"capacity SQL operation": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.OperationID = s.CapacityProjection.Setup.OperationID
		},
		"capacity SQL setup": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.ConfigurationSetupID = s.CapacityProjection.Setup.RoleSetupID
		},
		"original object UID": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.Receipt.Configuration.UID = s.Objects[1].Receipt.UID
		},
		"SQL root UID": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.Receipt.Configuration.UID = s.WorkerInputs.ConfigurationRoot.UID
		},
		"SQL projection UID": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.Receipt.Configuration.UID = s.WorkerInputs.SQLProjection.UID
		},
		"owner provider missing": func(s *contracts.InitialRuntimeResourceState) { s.OwnerProvider = nil },
		"owner audit UID": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.Receipt.Configuration.UID = s.OwnerProvider.AuditCredentials.UID
		},
		"provider UID": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.Receipt.Configuration.UID = s.WorkerInputs.AuditCredentials.UID
		},
		"capacity UID": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.Receipt.Configuration.UID = s.CapacityProjection.Receipt.Secret.UID
		},
		"cleanup UID": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.Receipt.Configuration.UID = s.CleanupProjection.Receipt.Secret.UID
		},
		"public SQL root UID": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.ConfigurationRoot.UID = s.CapacityProjection.Setup.RoleRootUID
		},
		"unselected provider":    func(s *contracts.InitialRuntimeResourceState) { s.WorkerInputs.AuditCredentials.UID = ownerID(14920) },
		"foreign SQL root":       func(s *contracts.InitialRuntimeResourceState) { s.WorkerInputs.ConfigurationRoot.Name += "-other" },
		"foreign SQL projection": func(s *contracts.InitialRuntimeResourceState) { s.WorkerInputs.SQLProjection.Name += "-other" },
		"foreign ConfigMap":      func(s *contracts.InitialRuntimeResourceState) { s.WorkerInputs.Receipt.Configuration.Name += "-other" },
		"empty digest":           func(s *contracts.InitialRuntimeResourceState) { s.WorkerInputs.PublicDigest = strings.Repeat("0", 64) },
		"extended phase": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.Until = s.WorkerInputs.ClaimedAt.Add(6 * time.Second)
		},
		"late receipt": func(s *contracts.InitialRuntimeResourceState) { s.WorkerInputs.Receipt.ObservedAt = s.Until },
		"non microtime": func(s *contracts.InitialRuntimeResourceState) {
			s.WorkerInputs.ClaimedAt = s.WorkerInputs.ClaimedAt.Add(time.Nanosecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			installation, state, now := configurationWorkerInputStateFixture(t)
			change(&state)
			if configurationWorkerInputsStateValid(installation, state, now) {
				t.Fatal("foreign or extended input claim accepted")
			}
		})
	}
}

func TestConfigurationWorkerInputReservesPendingOwnerChildren(t *testing.T) {
	for _, receipt := range []bool{false, true} {
		installation, state, now := configurationWorkerInputStateFixture(t)
		child := &contracts.OwnerIdentityObjectAttempt{OperationID: ownerID(14950), ClaimedAt: now.Add(-time.Second), Until: now.Add(time.Second)}
		if receipt {
			child.Receipt = &contracts.OwnerIdentityObjectReceipt{Object: contracts.WorkerObjectReference{Name: "original-owner-input", UID: ownerID(14951)}, ResourceVersion: "3", ObservedAt: now}
		}
		state.OwnerIdentity = &contracts.OwnerIdentityProjectionClaim{OperationID: ownerID(14952), RoleRoot: contracts.WorkerObjectReference{Name: "original-owner-root", UID: ownerID(14953)}, RoleSetupID: ownerID(14954), Configuration: child}
		if !configurationWorkerInputsStateValid(installation, state, now) {
			t.Fatal("distinct pending sibling rejected by cross-identity check")
		}
		original := state.WorkerInputs.OperationID
		state.WorkerInputs.OperationID = child.OperationID
		if configurationWorkerInputsStateValid(installation, state, now) {
			t.Fatal("pending owner CREATE attempt reused")
		}
		state.WorkerInputs.OperationID = original
		if receipt {
			state.WorkerInputs.Receipt.Configuration.UID = child.Receipt.Object.UID
			if configurationWorkerInputsStateValid(installation, state, now) {
				t.Fatal("positive child UID reused before joint owner receipt")
			}
		}
	}
}
