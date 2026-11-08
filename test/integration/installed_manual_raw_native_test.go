package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// ADR-279 manual-raw focus: the namespace CaptureProfile "raw-capture" v1 is
// the builtin network profile republished with rawPackets caps. The default
// prefix is 96 bytes and TCP frames keep up to 200 bytes.
const (
	manualRawProfileName    = "raw-capture"
	manualRawProfileVersion = "v1"
	manualRawTCPCap         = 200
)

// manualRawProfileDefinition copies the builtin network-connections v1
// definition with a rawPackets profile and sensitiveRead impact.
func manualRawProfileDefinition() (map[string]any, error) {
	return builtinNetworkDefinitionWith(map[string]any{"kind": "rawPackets", "snaplen": 96, "protocolSnaplen": []any{map[string]any{"protocol": "tcp", "bytes": manualRawTCPCap}}})
}

// builtinNetworkDefinitionWith copies the builtin network-connections v1
// definition with the given packet profile and sensitiveRead impact.
func builtinNetworkDefinitionWith(profile map[string]any) (map[string]any, error) {
	raw, err := os.ReadFile("../../internal/application/planning/profiles/network-connections-v1.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Definition map[string]any `json:"definition"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	actions, _ := doc.Definition["recipe"].(map[string]any)["actions"].([]any)
	if len(actions) != 1 {
		return nil, fmt.Errorf("builtin network profile has %d actions", len(actions))
	}
	action := actions[0].(map[string]any)
	action["parameters"].(map[string]any)["profile"] = profile
	action["impact"] = "sensitiveRead"
	return doc.Definition, nil
}

// manualRawArguments is the public finite raw request: one on-trigger
// action, no history, five seconds after start, a reviewed filter.
func manualRawArguments(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components": []any{map[string]any{
				"id":         "network",
				"profileRef": map[string]string{"catalog": "namespace", "name": manualRawProfileName, "version": manualRawProfileVersion},
				"overrides": []any{
					map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
					map[string]any{"actionID": "sample", "field": "actionExecutionMode", "value": "onTrigger"},
					map[string]any{"actionID": "sample", "field": "packetBefore", "value": "0s"},
					map[string]any{"actionID": "sample", "field": "packetAfter", "value": "5s"},
					map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "15s"},
				},
			}},
			"maxTotalBytes": 16 << 20,
			"maxDuration":   "15s",
		},
	}
}

// publishManualRawProfile is the workload team's step: publish the namespace
// CaptureProfile in the target namespace of the workload cluster. The chart's
// canonical CRD is applied first, as Helm does from crds/, when the owned
// cluster does not have it yet. The product reads it through the region's
// own namespace catalog query; nothing here is authority.
func publishManualRawProfile(t *testing.T, ctx context.Context, regionalConfig, namespace string) {
	t.Helper()
	definition, err := manualRawProfileDefinition()
	if err != nil {
		t.Fatal(err)
	}
	publishNamespaceCaptureProfile(t, ctx, regionalConfig, namespace, manualRawProfileName, manualRawProfileVersion, definition)
}

// publishNamespaceCaptureProfile publishes one namespace CaptureProfile
// version (applying the chart's CRD first when the cluster lacks it).
func publishNamespaceCaptureProfile(t *testing.T, ctx context.Context, regionalConfig, namespace, name, version string, definition map[string]any) {
	t.Helper()
	cfg, err := clientcmd.BuildConfigFromFlags("", regionalConfig)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../charts/asservat/crds/captureprofiles.yaml")
	if err != nil {
		t.Fatal(err)
	}
	client := api.CoreV1().RESTClient()
	const crds = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	if err := client.Post().AbsPath(crds).MaxRetries(0).Body(data).Do(call).Error(); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal("operator CaptureProfile CRD create", err)
	}
	object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "CaptureProfile",
		"metadata": map[string]any{"name": name + "." + version},
		"spec":     map[string]any{"name": name, "version": version, "definition": definition, "availability": map[string]any{"enabled": true, "deprecated": false}}}}
	resource := objects.Resource(schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "captureprofiles"}).Namespace(namespace)
	// A just-created CRD serves its resource shortly after Established; retry
	// only the not-yet-served NotFound within the bounded call.
	for {
		created, err := resource.Create(call, object, meta.CreateOptions{})
		if err == nil {
			t.Logf("published namespace CaptureProfile %s/%s uid=%s", namespace, created.GetName(), created.GetUID())
			return
		}
		if !apierrors.IsNotFound(err) || installedJourneyPause(call, 500*time.Millisecond) != nil {
			t.Fatal("namespace CaptureProfile publish", err)
		}
	}
}

// manualRawPCAP is the tshark view of the downloaded raw recording.
type manualRawPCAP struct {
	Packets, Payload, MaxCaptured int
}

// checkManualRawFields checks tshark's tcp.port, frame.cap_len and frame.len
// fields: every packet on the reviewed port, every TCP frame within its
// approved cap, and at least one frame kept beyond the header-only prefix.
func checkManualRawFields(out string) (manualRawPCAP, error) {
	var s manualRawPCAP
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return s, fmt.Errorf("packet fields %q", line)
		}
		captured, e1 := strconv.Atoi(fields[1])
		length, e2 := strconv.Atoi(fields[2])
		ports := strings.Split(fields[0], ",")
		if e1 != nil || e2 != nil || len(ports) != 2 || (ports[0] != "8080" && ports[1] != "8080") {
			return s, fmt.Errorf("packet outside the reviewed TCP port: %q", line)
		}
		if captured < 1 || captured > manualRawTCPCap || captured > length {
			return s, fmt.Errorf("TCP frame kept %d of %d bytes over the approved %d-byte cap", captured, length, manualRawTCPCap)
		}
		s.Packets++
		if captured > artifact.RecordingSnaplen {
			s.Payload++
		}
		s.MaxCaptured = max(s.MaxCaptured, captured)
	}
	if s.Packets == 0 {
		return s, fmt.Errorf("no captured packets")
	}
	if s.Payload == 0 {
		return s, fmt.Errorf("no frame kept beyond the %d-byte header-only prefix", artifact.RecordingSnaplen)
	}
	return s, nil
}

// qualifyManualRawPCAP writes the native raw recording and opens it with tshark.
func qualifyManualRawPCAP(t *testing.T, ctx context.Context, native []byte) manualRawPCAP {
	t.Helper()
	path := "../results/manual-raw.pcapng"
	if err := os.WriteFile(path, native, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := installedOutput(ctx, installedLocalToolTimeout, "tshark", "-r", path, "-T", "fields", "-e", "tcp.port", "-e", "frame.cap_len", "-e", "frame.len")
	if err != nil {
		t.Fatal("raw PCAPNG did not open in tshark", err)
	}
	s, err := checkManualRawFields(string(out))
	if err != nil {
		t.Fatal("raw PCAPNG", err)
	}
	return s
}
