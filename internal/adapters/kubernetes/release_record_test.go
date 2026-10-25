package kubernetes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const releaseInstallation = "11111111-1111-4111-8111-111111111111"

// releaseRecordAbsent answers a fixture API server's release record read with
// NotFound (no record: only the original image verifies).
func releaseRecordAbsent(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/configmaps/asservat-release-") {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonNotFound, Code: 404})
	return true
}

var (
	releaseV1 = "example.invalid/connector@sha256:01" + strings.Repeat("0", 62)
	releaseV2 = "example.invalid/connector@sha256:" + strings.Repeat("2", 64)
	releaseV3 = "example.invalid/connector@sha256:" + strings.Repeat("3", 64)
)

// releaseRecordAt is revision 2 to v2 (unsettled unless settled), with the
// hub-api launched at generation 2 and the hub-worker at 3.
func releaseRecordAt(t *testing.T, settled bool) *contracts.ReleaseRecord {
	t.Helper()
	r, err := contracts.NewReleaseRecord(releaseInstallation, releaseV1, 81)
	if err != nil {
		t.Fatal(err)
	}
	if r, err = r.Next(releaseV2, 81, contracts.ReleaseWorkloads{HubAPI: contracts.ReleaseWorkload{Launch: 2}, HubWorker: contracts.ReleaseWorkload{Launch: 3}}); err != nil {
		t.Fatal(err)
	}
	if settled {
		if r, err = r.Settled(); err != nil {
			t.Fatal(err)
		}
	}
	return &r
}

func releaseDeployment(image string, generation int64, revision string) apps.Deployment {
	d, _, _, _ := connectorAPITemplateFixture()
	d.Generation = generation
	d.Annotations = map[string]string{"asservat.io/marker": "x"}
	if revision != "" {
		d.Annotations[deploymentRevisionAnnotation] = revision
	}
	d.Spec.Template.Spec.Containers[0].Image = image
	return d
}

func TestReleaseOriginalMapsCurrentAndPreviousImage(t *testing.T) {
	r := releaseRecordAt(t, false)
	for _, c := range []struct {
		image      string
		generation int64
	}{{releaseV2, 3}, {releaseV1, 2}} {
		out, err := releaseOriginal(releaseDeployment(c.image, c.generation, "2"), r, releaseHubAPI)
		if err != nil {
			t.Fatal(c.image, err)
		}
		if out.Spec.Template.Spec.Containers[0].Image != releaseV1 || out.Generation != 2 || out.Annotations[deploymentRevisionAnnotation] != "1" || out.Annotations["asservat.io/marker"] != "x" {
			t.Fatalf("not the original view: %+v", out.ObjectMeta)
		}
	}
	// The hub-worker's own generations apply.
	if _, err := releaseOriginal(releaseDeployment(releaseV2, 4, ""), r, releaseHubWorker); err != nil {
		t.Fatal(err)
	}
	// The input is not modified.
	d := releaseDeployment(releaseV2, 3, "2")
	if _, err := releaseOriginal(d, r, releaseHubAPI); err != nil || d.Spec.Template.Spec.Containers[0].Image != releaseV2 || d.Generation != 3 {
		t.Fatal("input changed", err)
	}
	// Without a record or at revision 1 nothing is mapped.
	one, _ := contracts.NewReleaseRecord(releaseInstallation, releaseV1, 81)
	for _, rec := range []*contracts.ReleaseRecord{nil, &one} {
		out, err := releaseOriginal(d, rec, releaseHubAPI)
		if err != nil || out.Spec.Template.Spec.Containers[0].Image != releaseV2 || out.Generation != 3 {
			t.Fatal("unexpected mapping without a later revision", err)
		}
	}
}

func TestReleaseOriginalRejectsUnrecordedState(t *testing.T) {
	r := releaseRecordAt(t, false)
	for name, d := range map[string]apps.Deployment{
		"foreign image":           releaseDeployment(releaseV3, 3, "2"),
		"original after leaving":  releaseDeployment(releaseV1, 3, "2"),
		"current at old gen":      releaseDeployment(releaseV2, 2, "2"),
		"previous at current gen": releaseDeployment(releaseV1, 3, "2"),
		"hub-worker generation":   releaseDeployment(releaseV2, 4, "2"),
		"revision not decimal":    releaseDeployment(releaseV2, 3, "two"),
		"revision zero":           releaseDeployment(releaseV2, 3, "0"),
		"revision leading zero":   releaseDeployment(releaseV2, 3, "02"),
	} {
		if _, err := releaseOriginal(d, r, releaseHubAPI); err == nil {
			t.Error(name, "accepted")
		}
	}
	settled := releaseRecordAt(t, true)
	if _, err := releaseOriginal(releaseDeployment(releaseV1, 2, "1"), settled, releaseHubAPI); err == nil {
		t.Error("previous image accepted after settling")
	}
	two := releaseDeployment(releaseV2, 3, "")
	two.Spec.Template.Spec.Containers = append(two.Spec.Template.Spec.Containers, core.Container{Name: "sidecar", Image: releaseV2})
	if _, err := releaseOriginal(two, r, releaseHubAPI); err == nil {
		t.Error("second container accepted")
	}
}

// During and after a rollout the existing template match accepts a Pod of the
// current or previous image under either Deployment template, and still
// rejects every other change.
func TestConnectorTemplateMatchDuringRollout(t *testing.T) {
	d, rs, pod, image := connectorAPITemplateFixture()
	digest, err := ConnectorAPITemplateDigest(d.Spec.Template)
	if err != nil {
		t.Fatal(err)
	}
	r := releaseRecordAt(t, false)
	with := func(dImage string, dGen int64, podImage string) (apps.Deployment, apps.ReplicaSet, core.Pod) {
		d2, rs2, p2 := *d.DeepCopy(), *rs.DeepCopy(), *pod.DeepCopy()
		d2.Generation = dGen
		d2.Spec.Template.Spec.Containers[0].Image = dImage
		rs2.Spec.Template.Spec.Containers[0].Image = podImage
		p2.Spec.Containers[0].Image = podImage
		return d2, rs2, p2
	}
	for _, c := range []struct {
		dImage   string
		dGen     int64
		podImage string
	}{{releaseV2, 3, releaseV1}, {releaseV2, 3, releaseV2}, {releaseV1, 2, releaseV1}} {
		d2, rs2, p2 := with(c.dImage, c.dGen, c.podImage)
		if err := connectorAPITemplateMatch(&d2, &rs2, &p2, digest, image, r, releaseHubAPI); err != nil {
			t.Fatal(c, err)
		}
		// A connector caller passes no record: unchanged behavior.
		if c.dImage != releaseV1 || c.podImage != releaseV1 {
			if err := connectorAPITemplateMatch(&d2, &rs2, &p2, digest, image, nil, 0); err == nil {
				t.Fatal("release image accepted without a record", c)
			}
		}
	}
	for name, change := range map[string]func(*apps.Deployment, *apps.ReplicaSet, *core.Pod){
		"foreign pod image": func(_ *apps.Deployment, rs *apps.ReplicaSet, p *core.Pod) {
			rs.Spec.Template.Spec.Containers[0].Image = releaseV3
			p.Spec.Containers[0].Image = releaseV3
		},
		"pod command": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.Containers[0].Command = []string{"/changed"}
		},
		"deployment command": func(d *apps.Deployment, _ *apps.ReplicaSet, _ *core.Pod) {
			d.Spec.Template.Spec.Containers[0].Command = []string{"/changed"}
		},
		"deployment generation": func(d *apps.Deployment, _ *apps.ReplicaSet, _ *core.Pod) { d.Generation++ },
		"template label": func(d *apps.Deployment, _ *apps.ReplicaSet, _ *core.Pod) {
			d.Spec.Template.Labels["extra"] = "x"
		},
	} {
		d2, rs2, p2 := with(releaseV2, 3, releaseV2)
		change(&d2, &rs2, &p2)
		if connectorAPITemplateMatch(&d2, &rs2, &p2, digest, image, r, releaseHubAPI) == nil {
			t.Error(name, "accepted")
		}
	}
}

func TestReleaseConfigMapDecodingIsStrict(t *testing.T) {
	r := releaseRecordAt(t, true)
	body, err := contracts.EncodeReleaseRecord(*r)
	if err != nil {
		t.Fatal(err)
	}
	base := core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: contracts.ReleaseRecordName(releaseInstallation), Namespace: "hub", UID: "u", ResourceVersion: "7"}, Data: map[string]string{contracts.ReleaseRecordFile: string(body)}}
	encode := func(m core.ConfigMap) []byte {
		raw, e := json.Marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	got, rv, err := decodeReleaseConfigMap(encode(base), "hub", releaseInstallation)
	if err != nil || rv != "7" || got.Revision != 2 {
		t.Fatal("valid record refused", err)
	}
	for name, change := range map[string]func(*core.ConfigMap){
		"label":       func(m *core.ConfigMap) { m.Labels = map[string]string{"a": "b"} },
		"annotation":  func(m *core.ConfigMap) { m.Annotations = map[string]string{"a": "b"} },
		"owner":       func(m *core.ConfigMap) { m.OwnerReferences = []meta.OwnerReference{{Name: "x"}} },
		"finalizer":   func(m *core.ConfigMap) { m.Finalizers = []string{"x"} },
		"extra key":   func(m *core.ConfigMap) { m.Data["other"] = "x" },
		"binary data": func(m *core.ConfigMap) { m.BinaryData = map[string][]byte{"x": nil} },
		"other name":  func(m *core.ConfigMap) { m.Name = "other" },
		"namespace":   func(m *core.ConfigMap) { m.Namespace = "other" },
		"unknown json": func(m *core.ConfigMap) {
			m.Data[contracts.ReleaseRecordFile] = strings.Replace(string(body), "{", `{"extra":1,`, 1)
		},
	} {
		m := *base.DeepCopy()
		change(&m)
		if _, _, err := decodeReleaseConfigMap(encode(m), "hub", releaseInstallation); err == nil {
			t.Error(name, "accepted")
		}
	}
	if _, _, err := decodeReleaseConfigMap(encode(base), "hub", "22222222-2222-4222-8222-222222222222"); err == nil {
		t.Error("other installation accepted")
	}
}
