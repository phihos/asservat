package kubernetes

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func bootstrapStateFixture(t *testing.T) (contracts.InitialBootstrap, contracts.InitialBootstrapState) {
	t.Helper()
	d := contracts.InitialBootstrap{Name: "install", BootstrapNamespace: "trusted-bootstrap", TargetNamespace: "asservat", Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: "original-administrator"}}}
	n := bootstrapNames(d)
	s := contracts.InitialBootstrapState{Format: contracts.InitialBootstrapStateFormat, DesiredDigest: bootstrapDigest(d), InstallationID: ownerID(1), RequestID: ownerID(2), ClusterID: ownerID(3), IssuerEpoch: ownerID(4), SeedUID: ownerID(5), Creates: []contracts.InitialBootstrapCreate{}, Material: &contracts.InitialBootstrapMaterial{Format: contracts.InitialBootstrapMaterialFormat, IssuerToken: "synthetic-only-issuer", Storage: contracts.OwnerStorageCredential{AccessKeyID: "synthetic-access", SecretAccessKey: "synthetic-private"}, StorageUseUntil: time.Now().UTC().Add(time.Hour)}}
	s.Prelude = contracts.InitialBootstrapPrelude{Namespace: contracts.WorkerObjectReference{Name: d.BootstrapNamespace, UID: ownerID(10)}, Account: contracts.WorkerObjectReference{Name: n.account, UID: ownerID(11)}, Role: contracts.WorkerObjectReference{Name: n.account, UID: ownerID(12)}, Binding: contracts.WorkerObjectReference{Name: n.account, UID: ownerID(13)}, Marker: contracts.WorkerObjectReference{Name: n.marker, UID: ownerID(14)}, ContinuityMarker: contracts.WorkerObjectReference{Name: n.continuityMarker, UID: ownerID(15)}, TokenAnchor: contracts.WorkerObjectReference{Name: n.anchor, UID: ownerID(16)}, Guard: contracts.OwnerDeploymentGuard{Name: n.guard, PolicyUID: ownerID(17), BindingUID: ownerID(18), PolicyGeneration: 1, BindingResourceVersion: "1", Administrators: d.Administrators}}
	for i, p := range []*string{&s.Passwords.Manager, &s.Passwords.Preparation, &s.Passwords.Audit, &s.Passwords.Activation, &s.Passwords.History} {
		*p = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(rune('a'+i)), 32)))
	}
	start := time.Now().UTC().Truncate(time.Microsecond)
	s.Manager = &contracts.InitialBootstrapManager{OperationID: ownerID(20), StartedAt: start, Until: start.Add(30 * time.Minute), DatabaseOID: 42, PostmasterAt: start.Add(-time.Hour), Receipt: &contracts.InitialSQLHistoryManager{Name: "asservat_init_" + strings.ReplaceAll(s.InstallationID, "-", "") + "_manager", OID: 12345}}
	for i, step := range bootstrapSteps {
		s.Creates = append(s.Creates, contracts.InitialBootstrapCreate{Step: step, OperationID: ownerID(30 + i), Receipt: &contracts.InitialPreparationReceipt{UID: ownerID(50 + i), ResourceVersion: "1"}})
	}
	s.Projection = &contracts.WorkerObjectReference{Name: n.projection, UID: s.Creates[len(s.Creates)-1].Receipt.UID}
	if !bootstrapStateValid(d, s) {
		t.Fatal("synthetic valid bootstrap state rejected")
	}
	return d, s
}
func cloneBootstrapState(t *testing.T, s contracts.InitialBootstrapState) contracts.InitialBootstrapState {
	t.Helper()
	b, e := json.Marshal(s)
	if e != nil {
		t.Fatal("fixture clone unavailable")
	}
	defer clear(b)
	var out contracts.InitialBootstrapState
	if json.Unmarshal(b, &out) != nil {
		t.Fatal("fixture clone unavailable")
	}
	return out
}

func TestInitialBootstrapClosingCannotReissueOrRenewOriginalManager(t *testing.T) {
	d, original := bootstrapStateFixture(t)
	closing := cloneBootstrapState(t, original)
	now := original.Manager.StartedAt.Add(time.Second)
	closing.Manager.Closing = &contracts.InitialBootstrapClose{OperationID: ownerID(70), StartedAt: now, Until: now.Add(30 * time.Second)}
	if !bootstrapStateTransition(d, original, closing) {
		t.Fatal("restrictive original close rejected")
	}
	for label, edit := range map[string]func(*contracts.InitialBootstrapState){
		"reopen": func(s *contracts.InitialBootstrapState) { s.Manager.Closing = nil },
		"renew-close": func(s *contracts.InitialBootstrapState) {
			s.Manager.Closing.StartedAt = s.Manager.Closing.StartedAt.Add(time.Second)
			s.Manager.Closing.Until = s.Manager.Closing.Until.Add(time.Second)
		},
		"new-close-id":  func(s *contracts.InitialBootstrapState) { s.Manager.Closing.OperationID = ownerID(71) },
		"new-role":      func(s *contracts.InitialBootstrapState) { s.Manager.Receipt.OID++ },
		"new-role-name": func(s *contracts.InitialBootstrapState) { s.Manager.Receipt.Name = "replacement_manager" },
		"new-password": func(s *contracts.InitialBootstrapState) {
			s.Passwords.Manager = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
		},
		"new-database": func(s *contracts.InitialBootstrapState) { s.Manager.DatabaseOID++ },
		"renew-login": func(s *contracts.InitialBootstrapState) {
			s.Manager.StartedAt = s.Manager.StartedAt.Add(time.Second)
			s.Manager.Until = s.Manager.Until.Add(time.Second)
		},
		"replace-create-receipt": func(s *contracts.InitialBootstrapState) { s.Creates[0].Receipt.UID = ownerID(99) },
	} {
		t.Run(label, func(t *testing.T) {
			next := cloneBootstrapState(t, closing)
			edit(&next)
			if bootstrapStateTransition(d, closing, next) {
				t.Fatal("closed original state gained new authority")
			}
		})
	}
	retired := cloneBootstrapState(t, closing)
	at := now.Add(time.Second)
	retired.Manager.RetiredAt = &at
	if !bootstrapStateTransition(d, closing, retired) {
		t.Fatal("positive original completion rejected")
	}
	cleared := cloneBootstrapState(t, retired)
	cleared.Retired = true
	cleared.Material = nil
	cleared.Passwords = contracts.InitialBootstrapPasswords{History: retired.Passwords.History}
	if !bootstrapStateTransition(d, retired, cleared) {
		t.Fatal("positive closure cannot clear retired private input")
	}
	if cleared.Passwords.History != original.Passwords.History || bootstrapStateTransition(d, cleared, original) {
		t.Fatal("passive history was replaced or effects reopened")
	}
}

func TestInitialBootstrapElapsedTimeCannotCompleteClosure(t *testing.T) {
	d, original := bootstrapStateFixture(t)
	now := original.Manager.StartedAt.Add(time.Second)
	for _, close := range []*contracts.InitialBootstrapClose{nil, {OperationID: ownerID(70), StartedAt: now, Until: now.Add(30 * time.Second)}} {
		s := cloneBootstrapState(t, original)
		s.Manager.Closing = close
		at := now.Add(time.Minute)
		s.Manager.RetiredAt = &at
		if bootstrapStateValid(d, s) || bootstrapStateTransition(d, original, s) {
			t.Fatal("elapsed or absent cleanup claim fabricated completion")
		}
	}
	missing := cloneBootstrapState(t, original)
	missing.Projection = nil
	missing.Creates = nil
	missing.Manager.Closing = &contracts.InitialBootstrapClose{OperationID: ownerID(70), StartedAt: now, Until: now.Add(30 * time.Second)}
	if bootstrapStateValid(d, missing) {
		t.Fatal("unprojected setup accepted completion path")
	}
}

func TestInitialBootstrapPrivateFormattingAndMaterialValidation(t *testing.T) {
	d, s := bootstrapStateFixture(t)
	for _, v := range []any{s, s.Passwords, *s.Material} {
		for _, text := range []string{fmt.Sprint(v), fmt.Sprintf("%#v", v)} {
			if strings.Contains(text, s.Passwords.Manager) || strings.Contains(text, s.Material.IssuerToken) || strings.Contains(text, s.Material.Storage.SecretAccessKey) {
				t.Fatal("private state formatting exposed credential")
			}
		}
	}
	for _, token := range []string{"token\nsecond-line", "token\x00suffix", "token\tvalue", "非ASCII"} {
		bad := cloneBootstrapState(t, s)
		bad.Material.IssuerToken = token
		if bootstrapStateValid(d, bad) {
			t.Fatal("invalid credential reached provider effects")
		}
	}
}
