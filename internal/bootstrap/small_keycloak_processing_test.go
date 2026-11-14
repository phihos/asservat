package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/google/uuid"
)

func TestSmallKeycloakProcessingFalsePreservesOriginalPublicBytes(t *testing.T) {
	s := smallKeycloakTestSettings()
	// These public templates were compared byte-for-byte with the archived
	// pre-opt-in producer. They contain a credential placeholder, never a secret.
	realm, err := smallKeycloakRealm(s, "41414141-4141-4141-8141-414141414141")
	if err != nil {
		t.Fatal(err)
	}
	settings, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(realm)) != "45a880a829c44edaa74322bf3039c10132b03fee29b04c9bd307a4dead29849f" || fmt.Sprintf("%x", sha256.Sum256(settings)) != "76cce1e88b7fe6b644b1fdd161ae269636129d02e92fcd7a8b2ef5bcf02f76ac" {
		t.Fatal("default false changed original public realm or settings bytes")
	}
}

func TestSmallKeycloakProcessingOptInCreatesOnlyDedicatedEmptyGroup(t *testing.T) {
	legacy := smallKeycloakTestSettings()
	enabled := legacy
	enabled.ProcessingOperators = true
	seed := bytes.Repeat([]byte{0x41}, 128)
	before, err := BuildSmallKeycloakMaterial(legacy, bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	after, err := BuildSmallKeycloakMaterial(enabled, bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Data) != 6 || len(after.Data) != 6 {
		t.Fatal("opt-in added private state fields")
	}
	for key, value := range before.Data {
		if key != contracts.SmallKeycloakSettingsFile && key != legacy.Realm+"-realm.json" && !bytes.Equal(value, after.Data[key]) {
			t.Fatal("opt-in regenerated credentials or original identity")
		}
	}
	if bytes.Contains(before.Data[contracts.SmallKeycloakSettingsFile], []byte("processingOperators")) {
		t.Fatal("legacy false wire changed")
	}
	var realm struct {
		Users         []json.RawMessage `json:"users"`
		DefaultGroups []string          `json:"defaultGroups"`
		Groups        []struct {
			ID         string              `json:"id"`
			Name       string              `json:"name"`
			Attributes map[string][]string `json:"attributes"`
		} `json:"groups"`
	}
	if json.Unmarshal(after.Data[enabled.Realm+"-realm.json"], &realm) != nil || len(realm.Groups) != 2 || len(realm.Users) != 0 || len(realm.DefaultGroups) != 0 {
		t.Fatal("opt-in invented users/default memberships")
	}
	users := string(before.Data[contracts.SmallKeycloakUsersGroup])
	derived, err := smallKeycloakProcessingGroup(users)
	if err != nil || derived == users || uuid.MustParse(derived).Version() != 5 {
		t.Fatal("dedicated group identity not stable separate UUIDv5")
	}
	if realm.Groups[0].ID != users || realm.Groups[1].ID != derived || realm.Groups[1].Name != "asservat-processing-operators" || !reflect.DeepEqual(realm.Groups[1].Attributes["asservat_group_id"], []string{derived}) {
		t.Fatal("ordinary users group became a privacy operator")
	}
	replay, err := BuildSmallKeycloakMaterial(enabled, bytes.NewReader(seed))
	if err != nil || !reflect.DeepEqual(replay.Data, after.Data) {
		t.Fatal("same original input changed deterministic result")
	}
	if ValidateSmallKeycloakMaterial(enabled, before) == nil || ValidateSmallKeycloakMaterial(legacy, after) == nil {
		t.Fatal("late adoption of another immutable realm allowed")
	}
}

func assertBundledProcessingGroupEligibility(t *testing.T, public *contracts.InstallerPublicSettings, users, operators string) {
	t.Helper()
	now := time.Now().UTC()
	revision := identity.Revision{UID: "settings", Generation: 1, Digest: [32]byte{1}}
	eligibility := identity.Policy{Revision: revision, Issuer: public.Issuer, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Clients: []identity.Client{{ID: public.ClientID, Kind: identity.Human, ClassQualified: true}}, EligibleGroups: public.EligibleGroups, GroupsAtIssueQualified: true, GroupMaxAge: 5 * time.Minute}
	o := public.ProcessingOperators[0]
	id := "41414141-4141-4141-8141-414141414141"
	policy := privacy.DownloadPolicy{RootID: id, InstallationID: id, RecoveryEpoch: id, Revision: revision, ProtectionDigest: [32]byte{1}, PermittedRegions: []string{}, Paths: []privacy.DownloadPath{}, Clients: []privacy.DownloadClient{}, Operators: []privacy.ProcessingOperator{{ClientID: o.ClientID, Issuer: o.Issuer, Kind: o.Kind, ID: o.ID}}, ObservedAt: now, FreshUntil: now.Add(3 * time.Second)}
	if !policy.Valid(now) {
		t.Fatal("generated operator does not satisfy actual privacy contract")
	}
	claims := identity.Claims{Issuer: public.Issuer, Subject: "human", ClientID: public.ClientID, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), KeyUntil: now.Add(time.Minute)}
	for _, member := range []bool{false, true} {
		claims.Groups = []string{users}
		if member {
			claims.Groups = append(claims.Groups, operators)
		}
		admitted, err := identity.Admit(claims, eligibility, now)
		if err != nil || !reflect.DeepEqual(admitted.Groups, claims.Groups) || policy.Operator(admitted, now) != member {
			t.Fatal("eligibility discarded operator membership or ordinary users gained privacy authority")
		}
	}
	claims.Groups = []string{operators}
	if _, err := identity.Admit(claims, eligibility, now); err == nil {
		t.Fatal("dedicated operator group implicitly bypassed ordinary login eligibility")
	}
}

func TestSmallKeycloakProcessingHelmOptInReachesSecretsPlan(t *testing.T) {
	for _, mode := range []string{"default", "false", "true"} {
		t.Run(mode, func(t *testing.T) {
			values := secretsHelmValues("hub")
			if mode != "default" {
				kc := values["services"].(map[string]any)["identity"].(map[string]any)["keycloak"].(map[string]any)
				kc["processingOperators"] = mode == "true"
			}
			plan, _, _ := renderSecretsHook(t, values)
			if plan.Keycloak == nil || plan.Keycloak.ProcessingOperators != (mode == "true") {
				t.Fatal("secrets plan lost the explicit processing-operator selection")
			}
		})
	}
}
