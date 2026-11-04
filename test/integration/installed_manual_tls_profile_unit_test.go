package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"os"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	capacity "asservat.local/asservat/internal/application/capacity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	capture "asservat.local/asservat/internal/domain/capture"
	plan "asservat.local/asservat/internal/domain/planning"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	fake "k8s.io/client-go/kubernetes/fake"
)

func TestInstalledManualProfileTLSSelectsExactTransportAndRejectsMixedVariants(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "cpu")
	for _, transport := range []string{"", "http", "tls"} {
		t.Setenv("ASSERVAT_PROFILE_TRANSPORT", transport)
		want := transport == "tls"
		if installedTLSProfileTransport() != want || installedApprovedRecordingExpiryProof("manual-profile") == want {
			t.Fatal("TLS transport changed existing CPU selection/expiry branch", transport)
		}
		if installedHeapProfileVariant() || nativeCapacityProfile().Records != 12 {
			t.Fatal("TLS changed profile type/backing")
		}
	}
	for _, tc := range []struct{ transport, variant, focus string }{{"typo", "cpu", "manual-profile"}, {"tls", "heap", "manual-profile"}, {"tls", "accepted-heavy", "profile-comparison"}, {"tls", "cpu", "policy-profile"}} {
		t.Run(tc.transport+tc.variant+tc.focus, func(t *testing.T) {
			t.Setenv("ASSERVAT_PROFILE_TRANSPORT", tc.transport)
			t.Setenv("ASSERVAT_PROFILE_VARIANT", tc.variant)
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", tc.focus)
			defer func() {
				if recover() == nil {
					t.Fatal("unknown/incompatible TLS fixture silently selected")
				}
			}()
			installedTLSProfileTransport()
		})
	}
}

func TestInstalledManualProfileTLSPrivateMaterialProtectedDefinitionsAndAppOnlyMount(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "cpu")
	t.Setenv("ASSERVAT_PROFILE_TRANSPORT", "tls")
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	material := manualProfileTLSFixture(t, directory)
	defer clear(material.Key)
	again := manualProfileTLSFixture(t, directory)
	defer clear(again.Key)
	if !bytes.Equal(material.Roots, again.Roots) || !bytes.Equal(material.Certificate, again.Certificate) || !bytes.Equal(material.Key, again.Key) {
		t.Fatal("one installed source changed TLS identity")
	}
	endpoints := manualTLSProfileEndpoints(material.Roots)
	if !kube.ProfileEndpointsValid(endpoints) || len(endpoints) != 2 || endpoints[0].TLS.ServerName != manualProfileTLSServerName || endpoints[1].TLS.ServerName != manualProfileWrongTLSName {
		t.Fatal("protected correct/wrong peer definitions invalid")
	}
	encoded, err := json.Marshal(endpoints)
	if err != nil || bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, []byte("tls.key")) {
		t.Fatal("private app key escaped protected public-root config", err)
	}
	api := fake.NewClientset()
	workload := createRegionalWorkload(t, t.Context(), api, "synthetic-image", "apps-regional", false, directory)
	pod := workload.app.Spec.Template.Spec
	if !bytes.Equal([]byte(pod.Containers[0].Command[1]), []byte("--tls")) || len(pod.Containers) != 1 || len(pod.Volumes) != 1 || len(pod.Containers[0].VolumeMounts) != 1 || pod.Volumes[0].Secret.SecretName != "profile-application-tls" || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Fatal("TLS key escaped original restricted app-only mount")
	}
	secret, err := api.CoreV1().Secrets(workload.ns.Name).Get(t.Context(), "profile-application-tls", meta.GetOptions{})
	if err != nil || secret.Type != core.SecretTypeTLS || secret.Immutable == nil || !*secret.Immutable || len(secret.Data) != 2 {
		t.Fatal("private synthetic app Secret", err)
	}
	if _, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"]); err != nil {
		t.Fatal("mounted app keypair invalid", err)
	}
	for _, path := range []string{"root.pem", "tls.crt", "tls.key"} {
		info, err := os.Stat(directory + "/" + path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("private fixture file mode", path, err)
		}
	}
}

func TestInstalledManualProfileTLSWrongPeerNamespacePlanCompiles(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "cpu")
	t.Setenv("ASSERVAT_PROFILE_TRANSPORT", "tls")
	const cluster = "00000000-0000-4000-8000-000000000001"
	definition := manualWrongTLSProfileDefinition(t)
	document, err := json.Marshal(map[string]any{"name": manualProfileWrongTLSProfile, "version": "v1", "definition": definition})
	if err != nil {
		t.Fatal(err)
	}
	result := checkManualProfilePlan(t, cluster, manualWrongTLSProfileArguments(cluster, "payments", "api"), plan.CatalogProfile{Ref: plan.ProfileRef{Catalog: "namespace", Name: manualProfileWrongTLSProfile, Version: "v1"}, SourceClusterID: cluster, SourceNamespaceUID: "namespace", SourceUID: "tls-wrong-profile", Document: document, Enabled: true})
	action := result.Actions[0]
	if len(result.Actions) != 1 || action.ProfileType != "cpu" || action.ProfileMode != "interval" || action.Duration != "10s" || action.Timeout != "15s" || action.MaxBytes != 16<<20 || action.EndpointDigest == "" || result.Approval == nil || result.Approval.DataClass != "raw" || result.Approval.ObservationLimits != nil {
		t.Fatal("wrong peer qualification lost finite approved CPU semantics", result.Actions, result.Approval)
	}
}

func TestInstalledManualProfileTLSActualPoolCapacity(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "cpu")
	t.Setenv("ASSERVAT_PROFILE_TRANSPORT", "tls")
	registration := artifact.Registration{NativeLimit: 16 << 20}
	stream := artifact.StreamingPlan{Registration: registration}
	history := artifact.Registration{NativeLimit: capture.MaxHistoryParameters}
	// One successful CPU capture and one independently approved FAILED peer
	// capture both retain complete admission+history backing. No refunds counted.
	need := capacity.BudgetAmount{Bytes: 2 * (registration.ReservedBytes() + stream.TemporaryBytes() + history.ReservedBytes()), Objects: 2 * (4 + 1 + int64(stream.PartLimit()) + 4)}
	bytes, objects := installedRegionalContextReserve()
	if need.Bytes != 73924608 || need.Objects != 24 || bytes != 147849216 || objects != 48 || need.Bytes > bytes || need.Objects > objects {
		t.Fatal("TLS attempts/history underfunded or fixture ceilings changed", need, bytes, objects)
	}
	q, source := installedProfileComparisonCapacityFixture(t, *nativeCapacityProfile())
	work, err := capacity.CompileContextProtocolBacking(capacity.BudgetAmount{Bytes: bytes, Objects: objects}, q.RootBacking.ContextHistory)
	if err != nil || work.Records != 12 || work.Records > q.RootBacking.RecordsPerAccount || q.ContextQuery.WorkloadQueries != 12 || query.ProfileSummaryQueryUnits != 10 {
		t.Fatal("TLS source/query exceeds original root", work, err)
	}
	pool, err := capacity.CompileProtectedPoolPlan(source, "capacity")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := capacity.CompileQualifiedRootBacking(q, pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, digest := plan.Canonical()
	root := capacity.RootConfiguration{Format: capacity.RootConfigurationFormat, RootID: q.RootBacking.RootID, AttemptID: custodyID(), PlanDigest: digest, Revision: 1, InitialObservedAt: now, InitialUntil: now.Add(5 * time.Second), RevisionObservedAt: now, RevisionUntil: now.Add(5 * time.Second), PlannedUntil: now.Add(time.Duration(q.RootBacking.AdmissionSeconds) * time.Second), ReservedAt: now, CaptureBackedAt: &now, ReadyAt: &now}
	queries, err := capacity.CompileQueryBacking(q, root, plan, pool, artifact.Digest{1}, custodyID())
	if err != nil {
		t.Fatal(err)
	}
	combined := plan.Totals().SystemObjects.Objects + queries.Reservation.SystemObjects.Objects
	if combined != 6720 || pool.System.Objects != 10000 || pool.Burst.Objects != 40000 || pool.Capacity.Objects != 100000 {
		t.Fatal("TLS changed/exhausted original pool partition", combined, pool)
	}
	t.Logf("TLS funding: 1 successful+1 failed CPU10 plus2history retain %d bytes/%d objects within %d/%d; source root12, one summary10units; system objects%d/10000,burst40000 unchanged; other footprints synthetic", need.Bytes, need.Objects, bytes, objects, combined)
}
