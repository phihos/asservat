package kubernetes

import (
	"bytes"
	"errors"
	"maps"
	"strconv"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestMixedInstallerInboxOriginalPhaseAndMode(t *testing.T) {
	for _, mode := range []string{contracts.InstallerProviderBundledKeyService, contracts.InstallerProviderBundledObjectStore} {
		for _, phase := range []int{1, 3} {
			t.Run(mode+strconv.Itoa(phase), func(t *testing.T) {
				f, config, ctx := newBundledInboxFixture(t)
				data := bundledInboxCandidate("a")
				data[contracts.InstallerInboxPhase] = []byte(strconv.Itoa(phase))
				original, err := ReadOrCreateMixedInstallerInbox(ctx, config, "hub", bundledInboxID, bundledInboxDigest, mode, data)
				if err != nil {
					t.Fatal(err)
				}
				defer clearSmallSeaweedData(original.Data)
				if f.creates != 1 || string(original.Data[contracts.InstallerInboxPhase]) != strconv.Itoa(phase) || original.Annotations[InstallerInboxProviderModeAnnotation] != mode {
					t.Fatal("original mode/phase not retained")
				}
				completed, err := CompleteMixedInstallerInbox(ctx, config, "hub", bundledInboxID, bundledInboxDigest, mode, original, []byte("original-inspection"))
				if err != nil {
					t.Fatal(err)
				}
				defer clearSmallSeaweedData(completed.Data)
				retained := maps.Clone(completed.Data)
				delete(retained, contracts.InstallerInboxInspectionToken)
				if !maps.EqualFunc(retained, data, bytes.Equal) || f.puts != 1 {
					t.Fatal("completion changed private inputs")
				}
				again, err := ReadOrCreateMixedInstallerInbox(ctx, config, "hub", bundledInboxID, bundledInboxDigest, mode, data)
				if err != nil {
					t.Fatal(err)
				}
				defer clearSmallSeaweedData(again.Data)
				if !maps.EqualFunc(again.Data, completed.Data, bytes.Equal) || f.creates != 1 {
					t.Fatal("replay replaced original")
				}
				other := contracts.InstallerProviderBundledKeyService
				if mode == other {
					other = contracts.InstallerProviderBundledObjectStore
				}
				if _, err = ReadMixedInstallerInbox(ctx, config, "hub", bundledInboxID, bundledInboxDigest, other); !errors.Is(err, cfg.ErrChanged) {
					t.Fatal("other selected mode adopted carrier", err)
				}
				if _, err = ReadMixedInstallerInbox(ctx, config, "hub", bundledInboxID, strings.Repeat("b", 64), mode); !errors.Is(err, cfg.ErrChanged) {
					t.Fatal("other recipe adopted carrier", err)
				}
			})
		}
	}
}
func TestMixedInstallerInboxKeepsClosedPrivateGroups(t *testing.T) {
	for _, scenario := range []string{"phase1-extra", "phase2", "unknown-mode", "seaweed-session", "external-session", "external-cleanup-session"} {
		t.Run(scenario, func(t *testing.T) {
			f, config, ctx := newBundledInboxFixture(t)
			data := bundledInboxCandidate("a")
			mode := contracts.InstallerProviderBundledKeyService
			switch scenario {
			case "phase1-extra":
				data[contracts.InstallerInboxPhase] = []byte("1")
				data[contracts.OwnerPublicTLSCertificate] = []byte("unused")
			case "phase2":
				data[contracts.InstallerInboxPhase] = []byte("2")
			case "unknown-mode":
				mode = "other"
			case "seaweed-session", "external-session":
				data[contracts.InstallerInboxAuditCredential] = bytes.Replace(data[contracts.InstallerInboxAuditCredential], []byte(`"sessionToken":""`), []byte(`"sessionToken":"bounded-external-session"`), 1)
				if scenario == "seaweed-session" {
					mode = contracts.InstallerProviderBundledObjectStore
				}
			case "external-cleanup-session":
				raw := bytes.Replace(data[contracts.InstallerInboxAuditCredential], []byte(`"sessionToken":""`), []byte(`"sessionToken":"forbidden-cleanup-session"`), 1)
				data[contracts.InstallerInboxCleanupAuditCredential] = raw
				data[contracts.InstallerInboxCleanupVerifyCredential] = raw
			}
			original, err := ReadOrCreateMixedInstallerInbox(ctx, config, "hub", bundledInboxID, bundledInboxDigest, mode, data)
			if scenario == "external-session" {
				if err != nil {
					t.Fatal("external storage session credential refused", err)
				}
				clearSmallSeaweedData(original.Data)
				return
			}
			if err == nil || f.creates != 0 {
				t.Fatal("unselected private fields reached create", err)
			}
		})
	}
}
func TestMixedInstallerInboxUnknownEffectsRecoverOnlyOriginal(t *testing.T) {
	for _, scenario := range []string{"create-unknown", "create-malformed", "put-unknown", "put-malformed", "put-storage-changed"} {
		t.Run(scenario, func(t *testing.T) {
			f, config, ctx := newBundledInboxFixture(t)
			mode := contracts.InstallerProviderBundledObjectStore
			data := bundledInboxCandidate("a")
			data[contracts.InstallerInboxPhase] = []byte("1")
			if strings.HasPrefix(scenario, "create") {
				f.mode = scenario
			}
			original, err := ReadOrCreateMixedInstallerInbox(ctx, config, "hub", bundledInboxID, bundledInboxDigest, mode, data)
			if err != nil {
				t.Fatal(err)
			}
			defer clearSmallSeaweedData(original.Data)
			f.mode = scenario
			completed, err := CompleteMixedInstallerInbox(ctx, config, "hub", bundledInboxID, bundledInboxDigest, mode, original, []byte("inspection"))
			if scenario == "put-storage-changed" {
				if err == nil {
					t.Fatal("changed unknown winner adopted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer clearSmallSeaweedData(completed.Data)
			if f.creates != 1 || f.puts != 1 || !bytes.Equal(data[contracts.InstallerInboxAuditCredential], completed.Data[contracts.InstallerInboxAuditCredential]) {
				t.Fatal("uncertain effect retried or changed retained key")
			}
		})
	}
}
