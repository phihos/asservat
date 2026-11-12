package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
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
func TestBundledProcessingDeclarationRequiresOriginalExplicitOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, explicit := range []bool{false, true} {
			s := smallKeycloakTestSettings()
			s.ProcessingOperators = enabled
			material, err := BuildSmallKeycloakMaterial(s, bytes.NewReader(bytes.Repeat([]byte{0x41}, 128)))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			for key, file := range map[string]string{contracts.SmallKeycloakSettingsFile: bundledKeycloakSettingsFile, contracts.SmallKeycloakUsersGroup: contracts.SmallKeycloakUsersGroup} {
				if err = os.WriteFile(filepath.Join(dir, file), material.Data[key], 0600); err != nil {
					t.Fatal(err)
				}
			}
			files, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			input := contracts.InstallerContinuation{Namespace: s.Namespace, IdentitySource: bundledKeycloakIdentitySource, Public: &contracts.InstallerPublicSettings{Origin: s.Origin, Issuer: s.Hostname + "/realms/" + s.Realm, ClientID: s.ConsoleClientID}}
			provided := []contracts.ProcessingOperator{{ClientID: s.ConsoleClientID, Issuer: input.Public.Issuer, Kind: "User", ID: "explicit-human"}}
			if explicit {
				input.Public.ProcessingOperators = append([]contracts.ProcessingOperator{}, provided...)
			}
			err = resolveInstallerContinuationIdentity(t.Context(), files, &input)
			files.Close()
			if err != nil {
				t.Fatal(err)
			}
			if explicit {
				if !reflect.DeepEqual(input.Public.ProcessingOperators, provided) {
					t.Fatal("explicit operators silently overridden")
				}
				continue
			}
			if !enabled {
				if len(input.Public.ProcessingOperators) != 0 {
					t.Fatal("default false granted processing rights")
				}
				continue
			}
			users := string(material.Data[contracts.SmallKeycloakUsersGroup])
			group, err := smallKeycloakProcessingGroup(users)
			if err != nil {
				t.Fatal(err)
			}
			want := []contracts.ProcessingOperator{{ClientID: s.ConsoleClientID, Issuer: input.Public.Issuer, Kind: "Group", ID: group}}
			if !reflect.DeepEqual(input.Public.ProcessingOperators, want) || !reflect.DeepEqual(input.Public.EligibleGroups, []string{users}) {
				t.Fatal("derived policy source mixed ordinary and processing groups")
			}
			assertBundledProcessingGroupEligibility(t, input.Public, users, group)
		}
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

func TestSmallKeycloakProcessingHelmOptInPreservesDefaultRequirement(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Fatal("Helm is required for the actual producer regression")
	}
	profile, err := os.ReadFile("../../examples/helm/context-trial-profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var reference struct {
		Bootstrap struct {
			Continuation struct {
				Public struct{ Capacity json.RawMessage }
			}
		}
	}
	profileJSON, err := yaml.ToJSON(profile)
	if err != nil || json.Unmarshal(profileJSON, &reference) != nil || len(reference.Bootstrap.Continuation.Public.Capacity) == 0 {
		t.Fatal("reference capacity input missing")
	}
	for _, mode := range []string{"default", "false", "true", "external-true", "explicit", "true-empty"} {
		t.Run(mode, func(t *testing.T) {
			bootstrap := smallServicesHelmBootstrap()
			public := bootstrap["continuation"].(map[string]any)["public"].(map[string]any)
			public["capacity"] = reference.Bootstrap.Continuation.Public.Capacity
			if mode == "explicit" {
				public["processingOperators"] = []contracts.ProcessingOperator{{ClientID: "asservat-console", Issuer: "https://identity.example/realms/asservat", Kind: "User", ID: "declared-human"}}
			}
			if mode == "true-empty" {
				public["processingOperators"] = []contracts.ProcessingOperator{}
			}
			kc := map[string]any{"hostname": "https://identity.example", "tlsSecretName": "identity-tls"}
			if mode != "default" {
				kc["processingOperators"] = mode == "true" || mode == "true-empty" || mode == "external-true"
			}
			provider := "keycloak"
			if mode == "external-true" {
				provider = "external"
			}
			values := map[string]any{"bootstrap": bootstrap, "services": map[string]any{"identity": map[string]any{"provider": provider, "keycloak": kc}, "postgres": map[string]any{"provider": "bundled", "bundled": map[string]any{"image": "registry.example/postgres@sha256:" + strings.Repeat("b", 64)}}}}
			body, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "values.json")
			if err = os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, end := context.WithTimeout(t.Context(), 15*time.Second)
			defer end()
			raw, err := exec.CommandContext(ctx, helm, "template", "trial", "../../charts/asservat", "--namespace", "installation", "--kube-version", "1.35.0", "-f", path).CombinedOutput()
			accepted := mode == "true" || mode == "explicit"
			if !accepted {
				if err == nil || !strings.Contains(string(raw), "processingOperators") {
					t.Fatalf("missing/empty operators accepted or refused for an unrelated reason: %v\n%s", err, raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("actual chart producer: %v\n%s", err, raw)
			}
			decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
			for {
				var config core.ConfigMap
				if err := decoder.Decode(&config); err == io.EOF {
					t.Fatal("preparation ConfigMap missing")
				} else if err != nil {
					t.Fatal(err)
				}
				if config.Kind != "ConfigMap" || config.Name != "trial-services-prepare" {
					continue
				}
				plan, err := contracts.DecodeSmallServicesPreparation(strings.NewReader(config.Data["preparation.json"]))
				if err != nil || plan.Keycloak == nil || plan.Keycloak.ProcessingOperators != (mode == "true") {
					t.Fatal("actual closed preparation input lost explicit selection", err)
				}
				if mode == "explicit" && strings.Contains(config.Data["preparation.json"], "processingOperators") {
					t.Fatal("default preparation wire gained a false field")
				}
				break
			}
		})
	}
}
