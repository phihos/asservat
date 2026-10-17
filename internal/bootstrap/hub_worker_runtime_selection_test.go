package bootstrap

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// Only public synthetic input shape is supplied here. No API, SQL, provider,
// original receipt or current runtime authority is established by selection.
func providerWorkerSelectionFixture(t *testing.T) contracts.HubWorkerDeployment {
	t.Helper()
	_, _, in, _, _, _ := captureCleanupInputFixture(t)
	id := func(n int) string { return fmt.Sprintf("91000000-0000-4000-8000-%012d", n) }
	prefix := strings.ReplaceAll(in.InstallationID, "-", "")
	in.Postgres.MaxConnections = 1
	in.Activation.WorkerLayout = contracts.HubWorkerProviderInstalledLayout
	recipe, err := providerconfig.ConfigurationProviderRecipeFor(in, contracts.ConfigurationProviderSelection{
		AuthMount: "configuration-auth", AuthMountAccessor: "auth_kubernetes_original",
		AuditCredentials: contracts.WorkerObjectReference{Name: "asservat-" + prefix + "-worker-providers", UID: id(1)},
	}, in.Activation.ServiceAccount, time.Now())
	if err != nil {
		t.Fatal("synthetic provider recipe", err)
	}
	in.ProviderAuthentication = &recipe.Profile
	in.ProviderInputs = &contracts.ConfigurationWorkerInputProvenance{
		OperationID: id(2), ConfigurationSetupID: id(3),
		ConfigurationRoot: contracts.WorkerObjectReference{Name: "asservat-configuration-roles-" + prefix, UID: id(4)},
		SQLProjection:     contracts.WorkerObjectReference{Name: "asservat-configuration-runtime-" + prefix, UID: id(5)},
	}
	return in
}

func TestHubWorkerCommandSelectsOnlyCompleteOriginalProviderProfile(t *testing.T) {
	for _, mode := range []string{"provider", "legacy", "legacy-installed", "missing-pod", "invalid-pod", "no-activation", "no-auth", "no-provenance", "marker-only", "legacy-with-provider", "unknown-layout", "changed-recipe", "foreign-account", "foreign-sql", "larger-pool", "malformed-provider"} {
		t.Run(mode, func(t *testing.T) {
			in := providerWorkerSelectionFixture(t)
			pod := "91000000-0000-4000-8000-000000000006"
			want := hubWorkerRuntimeUnavailable
			switch mode {
			case "provider":
				want = hubWorkerRuntimeProvider
			case "legacy", "legacy-installed":
				in.ProviderAuthentication, in.ProviderInputs = nil, nil
				in.Activation.WorkerLayout = contracts.HubWorkerInstalledLayout
				if mode == "legacy" {
					in.Activation = nil
				}
				pod = "" // The unchanged legacy component never required this pin.
				want = hubWorkerRuntimeLegacy
			case "missing-pod":
				pod = ""
			case "invalid-pod":
				pod = "current-pod"
			case "no-activation":
				in.Activation = nil
			case "no-auth":
				in.ProviderAuthentication = nil
			case "no-provenance":
				in.ProviderInputs = nil
			case "marker-only":
				in.ProviderAuthentication, in.ProviderInputs = nil, nil
			case "legacy-with-provider":
				in.Activation.WorkerLayout = contracts.HubWorkerInstalledLayout
			case "unknown-layout":
				in.Activation.WorkerLayout = "asservat-hub-worker-installed/v3"
			case "changed-recipe":
				in.ProviderAuthentication.RecipeSHA256 = strings.Repeat("0", 64)
			case "foreign-account":
				in.ProviderAuthentication.ServiceAccount.UID = pod
			case "foreign-sql":
				in.ProviderInputs.SQLProjection.Name += "-replacement"
			case "larger-pool":
				in.Postgres.MaxConnections = 2
			case "malformed-provider":
				in.KeyService.Endpoint = "http://provider.invalid"
			}
			got, err := selectHubWorkerRuntime(in, pod)
			if got != want || (err != nil) != (want == hubWorkerRuntimeUnavailable) {
				t.Fatalf("selection=%d err=%v want=%d", got, err, want)
			}
		})
	}
}

func TestHubWorkerCommandRejectsPartialPublicInput(t *testing.T) {
	for _, mode := range []string{"partial", "extra-field", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			files, dir, _, _, _, _ := captureCleanupInputFixture(t)
			input := providerWorkerSelectionFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "partial":
				input.ProviderAuthentication = nil
				writeOwnerJSON(t, dir, "deployment.json", input)
			case "extra-field":
				writeOwnerJSON(t, dir, "deployment.json", map[string]any{"format": input.Format, "runtimeFallback": true})
			case "canceled":
				writeOwnerJSON(t, dir, "deployment.json", input)
				cancel()
			}
			// No credentials or SQL/provider endpoint response is installed. This
			// invokes the real command's fixed file/selection path, not a factory.
			if runHubWorkerFiles(ctx, files.files, "91000000-0000-4000-8000-000000000006") == nil {
				t.Fatal("unavailable command accepted")
			}
		})
	}
}
