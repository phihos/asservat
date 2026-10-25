package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

const releaseTestInstallation = "11111111-1111-4111-8111-111111111111"

func releaseTestImage(n int) string {
	return fmt.Sprintf("registry.example.test/asservat@sha256:%064x", n)
}

// fakeReleaseAPI is a minimal API server for the record ConfigMap and the two
// hub Deployments: resourceVersion preconditions, generation on spec change
// and an immediately settled rollout status.
type fakeReleaseAPI struct {
	mu          sync.Mutex
	rv          int
	record      *core.ConfigMap
	deployments map[string]*apps.Deployment
	// failDeployment fails the PUT of that Deployment; conflictRecord answers
	// the next record PUT with a conflict.
	failDeployment string
	conflictRecord bool
	writes         []string
}

func newFakeReleaseAPI(t *testing.T) (*fakeReleaseAPI, *rest.Config) {
	f := &fakeReleaseAPI{deployments: map[string]*apps.Deployment{}}
	apiName, workerName := kube.HubDeploymentNames(releaseTestInstallation)
	// Two of the three followers exist; the publisher is not enabled.
	followers := kube.ReleaseFollowerNames(releaseTestInstallation)
	for name, gen := range map[string]int64{apiName: 2, workerName: 3, followers[0]: 1, followers[2]: 1} {
		f.rv++
		f.deployments[name] = &apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "hub", UID: types.UID("uid-" + name), Generation: gen, ResourceVersion: strconv.Itoa(f.rv)},
			Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{{Name: "hub", Image: releaseTestImage(1)}}}}}}
		f.settle(f.deployments[name])
	}
	server := httptest.NewServer(f)
	t.Cleanup(server.Close)
	return f, &rest.Config{Host: server.URL}
}

func (f *fakeReleaseAPI) settle(d *apps.Deployment) {
	d.Status = apps.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
}

func (f *fakeReleaseAPI) reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeReleaseAPI) status(w http.ResponseWriter, code int, reason meta.StatusReason) {
	f.reply(w, code, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Code: int32(code), Reason: reason})
}

func (f *fakeReleaseAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	recordPath := "/api/v1/namespaces/hub/configmaps/" + contracts.ReleaseRecordName(releaseTestInstallation)
	switch {
	case r.URL.Path == recordPath && r.Method == http.MethodGet:
		if f.record == nil {
			f.status(w, 404, meta.StatusReasonNotFound)
			return
		}
		f.reply(w, 200, f.record)
	case r.URL.Path == "/api/v1/namespaces/hub/configmaps" && r.Method == http.MethodPost:
		if f.record != nil {
			f.status(w, 409, meta.StatusReasonAlreadyExists)
			return
		}
		var m core.ConfigMap
		_ = json.Unmarshal(body, &m)
		f.rv++
		m.TypeMeta, m.Namespace, m.UID, m.ResourceVersion = meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, "hub", "record-uid", strconv.Itoa(f.rv)
		f.record = &m
		f.writes = append(f.writes, "create record")
		f.reply(w, 201, f.record)
	case r.URL.Path == recordPath && r.Method == http.MethodPut:
		var m core.ConfigMap
		_ = json.Unmarshal(body, &m)
		if f.record == nil || f.conflictRecord || m.ResourceVersion != f.record.ResourceVersion {
			f.conflictRecord = false
			f.status(w, 409, meta.StatusReasonConflict)
			return
		}
		f.rv++
		m.TypeMeta, m.Namespace, m.UID, m.ResourceVersion = meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, "hub", "record-uid", strconv.Itoa(f.rv)
		f.record = &m
		f.writes = append(f.writes, "update record")
		f.reply(w, 200, f.record)
	case strings.HasPrefix(r.URL.Path, "/apis/apps/v1/namespaces/hub/deployments/"):
		name := strings.TrimPrefix(r.URL.Path, "/apis/apps/v1/namespaces/hub/deployments/")
		d, ok := f.deployments[name]
		if !ok {
			f.status(w, 404, meta.StatusReasonNotFound)
			return
		}
		if r.Method == http.MethodGet {
			f.reply(w, 200, d)
			return
		}
		if r.Method != http.MethodPut || name == f.failDeployment {
			f.status(w, 500, meta.StatusReasonInternalError)
			return
		}
		var next apps.Deployment
		_ = json.Unmarshal(body, &next)
		if next.ResourceVersion != d.ResourceVersion {
			f.status(w, 409, meta.StatusReasonConflict)
			return
		}
		f.rv++
		d.Spec, d.ResourceVersion = next.Spec, strconv.Itoa(f.rv)
		d.Generation++
		f.settle(d)
		f.writes = append(f.writes, "update "+name)
		f.reply(w, 200, d)
	default:
		f.status(w, 404, meta.StatusReasonNotFound)
	}
}

func (f *fakeReleaseAPI) current(t *testing.T) contracts.ReleaseRecord {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := contracts.DecodeReleaseRecord(bytes.NewBufferString(f.record.Data[contracts.ReleaseRecordFile]))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type fakeReleaseSchema struct {
	state       postgres.SchemaState
	planned     int64
	migrated    int
	failMigrate bool
}

func (s *fakeReleaseSchema) State(context.Context) (postgres.SchemaState, error) { return s.state, nil }
func (s *fakeReleaseSchema) PlannedFloor(postgres.SchemaState) (int64, error) {
	return s.planned, nil
}
func (s *fakeReleaseSchema) Run(context.Context) (int64, int64, error) {
	if s.failMigrate {
		return 0, 0, cfg.ErrUnavailable
	}
	s.migrated++
	from := s.state.Head
	s.state = postgres.SchemaState{Head: 82, Floor: s.planned}
	return from, 82, nil
}

func releaseTestChange(config *rest.Config, image int, compiled int64, schema releaseSchema) releaseChange {
	return releaseChange{config: config, namespace: "hub", installation: releaseTestInstallation, image: releaseTestImage(image), compiled: compiled, schema: schema, out: io.Discard, poll: time.Millisecond, settle: time.Second}
}

func createRevisionOne(t *testing.T, config *rest.Config) {
	t.Helper()
	r, err := contracts.NewReleaseRecord(releaseTestInstallation, releaseTestImage(1), 81)
	if err != nil {
		t.Fatal(err)
	}
	if err = kube.CreateReleaseRecord(context.Background(), config, "hub", r); err != nil {
		t.Fatal(err)
	}
}

// Revision 1 is created once; a replay looks it up and accepts only the same
// installation and original image.
func TestReleaseRecordRevisionOneCreatedOnce(t *testing.T) {
	f, config := newFakeReleaseAPI(t)
	createRevisionOne(t, config)
	createRevisionOne(t, config)
	other, _ := contracts.NewReleaseRecord(releaseTestInstallation, releaseTestImage(9), 81)
	if err := kube.CreateReleaseRecord(context.Background(), config, "hub", other); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("different original accepted", err)
	}
	if len(f.writes) != 1 {
		t.Fatal("writes", f.writes)
	}
	// After an upgrade a replayed continuation still finds its record.
	if err := releaseTestChange(config, 2, 82, &fakeReleaseSchema{state: postgres.SchemaState{Head: 81, Floor: 81}, planned: 81}).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	createRevisionOne(t, config)
}

func TestReleaseUpgradeAndRollback(t *testing.T) {
	f, config := newFakeReleaseAPI(t)
	createRevisionOne(t, config)
	schema := &fakeReleaseSchema{state: postgres.SchemaState{Head: 81, Floor: 81}, planned: 81}
	if err := releaseTestChange(config, 2, 82, schema).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := f.current(t)
	if r.Revision != 2 || r.Image != releaseTestImage(2) || r.Previous != "" || r.Schema != 82 || schema.migrated != 1 || r.Workloads.HubAPI != (contracts.ReleaseWorkload{Launch: 2, Generation: 3}) || r.Workloads.HubWorker != (contracts.ReleaseWorkload{Launch: 3, Generation: 4}) {
		t.Fatalf("after upgrade: %+v", r)
	}
	apiName, workerName := kube.HubDeploymentNames(releaseTestInstallation)
	followers := kube.ReleaseFollowerNames(releaseTestInstallation)
	if want := []string{"create record", "update record", "update " + workerName, "update " + apiName, "update " + followers[0], "update " + followers[2], "update record"}; !equalStrings(f.writes, want) {
		t.Fatal("order", f.writes)
	}
	for _, name := range []string{followers[0], followers[2]} {
		if f.deployments[name].Spec.Template.Spec.Containers[0].Image != releaseTestImage(2) {
			t.Fatal("follower not upgraded", name)
		}
	}
	// Rerunning the same image is a no-op.
	if err := releaseTestChange(config, 2, 82, schema).run(context.Background()); err != nil || len(f.writes) != 7 {
		t.Fatal("rerun", err, f.writes)
	}
	// Rollback to the original image: no migration while the floor admits 81.
	if err := releaseTestChange(config, 1, 81, schema).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r = f.current(t); r.Revision != 3 || r.Image != releaseTestImage(1) || r.Schema != 81 || schema.migrated != 1 || f.deployments[apiName].Spec.Template.Spec.Containers[0].Image != releaseTestImage(1) ||
		f.deployments[followers[2]].Spec.Template.Spec.Containers[0].Image != releaseTestImage(1) {
		t.Fatalf("after rollback: %+v", r)
	}
}

// Followers (phase 3): one left on the original image by a phase-2 runner is
// rolled forward; one on an image the record does not name is refused before
// anything changes, as is a settled record whose follower runs another image.
func TestReleaseFollowers(t *testing.T) {
	f, config := newFakeReleaseAPI(t)
	createRevisionOne(t, config)
	schema := &fakeReleaseSchema{state: postgres.SchemaState{Head: 81, Floor: 81}, planned: 81}
	followers := kube.ReleaseFollowerNames(releaseTestInstallation)
	// A phase-2 upgrade to image 2 moved only the hub Deployments.
	if err := releaseTestChange(config, 2, 82, schema).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.deployments[followers[0]].Spec.Template.Spec.Containers[0].Image = releaseTestImage(1)
	if err := releaseTestChange(config, 2, 82, schema).run(context.Background()); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("settled record with a follower on another image accepted", err)
	}
	if err := releaseTestChange(config, 3, 82, schema).run(context.Background()); err != nil {
		t.Fatal("follower left on the original image", err)
	}
	if f.deployments[followers[0]].Spec.Template.Spec.Containers[0].Image != releaseTestImage(3) {
		t.Fatal("follower not rolled forward")
	}
	before := len(f.writes)
	f.deployments[followers[2]].Spec.Template.Spec.Containers[0].Image = releaseTestImage(7)
	if err := releaseTestChange(config, 4, 82, schema).run(context.Background()); !errors.Is(err, cfg.ErrChanged) || len(f.writes) != before || f.current(t).Revision != 3 {
		t.Fatal("follower on a foreign image", err, f.writes)
	}
}

// A rollback is refused, with nothing changed, once the database floor
// exceeds the target release's schema.
func TestReleaseRollbackRefusedPastFloor(t *testing.T) {
	f, config := newFakeReleaseAPI(t)
	createRevisionOne(t, config)
	schema := &fakeReleaseSchema{state: postgres.SchemaState{Head: 81, Floor: 81}, planned: 81}
	if err := releaseTestChange(config, 2, 82, schema).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	schema.state.Floor = 82
	before := len(f.writes)
	err := releaseTestChange(config, 1, 81, schema).run(context.Background())
	if !errors.Is(err, ErrReleaseRefused) || !strings.Contains(err.Error(), "restore from backup") || len(f.writes) != before || f.current(t).Revision != 2 {
		t.Fatal("rollback past the floor", err, f.writes)
	}
	// So is an upgrade whose migrations would raise the floor past the
	// oldest retained release (phase 2 guard).
	schema.state.Floor, schema.planned = 81, 82
	if err = releaseTestChange(config, 3, 83, schema).run(context.Background()); !errors.Is(err, ErrReleaseRefused) || schema.migrated != 1 || len(f.writes) != before {
		t.Fatal("floor past history[0]", err)
	}
}

// A failure after the record update leaves both images verifying; a rerun
// with the same image resumes and settles.
func TestReleaseFailureAfterRecordResumes(t *testing.T) {
	f, config := newFakeReleaseAPI(t)
	createRevisionOne(t, config)
	apiName, workerName := kube.HubDeploymentNames(releaseTestInstallation)
	f.failDeployment = apiName
	schema := &fakeReleaseSchema{state: postgres.SchemaState{Head: 81, Floor: 81}, planned: 81}
	if err := releaseTestChange(config, 2, 82, schema).run(context.Background()); err == nil {
		t.Fatal("hub-api update failure ignored")
	}
	r := f.current(t)
	if r.Revision != 2 || r.Previous != releaseTestImage(1) {
		t.Fatalf("record %+v", r)
	}
	// hub-worker already runs the new image, hub-api still the old one: both
	// map to the original view.
	if !kube.ReleaseDeploymentMatches(*f.deployments[workerName], r, false) || !kube.ReleaseDeploymentMatches(*f.deployments[apiName], r, true) ||
		f.deployments[apiName].Spec.Template.Spec.Containers[0].Image != releaseTestImage(1) {
		t.Fatal("old and new Deployments do not both verify")
	}
	// Another image is refused until the change settles.
	if err := releaseTestChange(config, 3, 82, schema).run(context.Background()); !errors.Is(err, ErrReleaseRefused) {
		t.Fatal("second change accepted", err)
	}
	f.failDeployment = ""
	if err := releaseTestChange(config, 2, 82, schema).run(context.Background()); err != nil {
		t.Fatal("resume", err)
	}
	if r = f.current(t); r.Previous != "" || f.deployments[apiName].Spec.Template.Spec.Containers[0].Image != releaseTestImage(2) || schema.migrated != 1 {
		t.Fatalf("resumed %+v", r)
	}
}

// A conflicting record write and a failed migration both change nothing.
func TestReleaseRecordConflictChangesNothing(t *testing.T) {
	f, config := newFakeReleaseAPI(t)
	createRevisionOne(t, config)
	f.conflictRecord = true
	schema := &fakeReleaseSchema{state: postgres.SchemaState{Head: 81, Floor: 81}, planned: 81}
	if err := releaseTestChange(config, 2, 82, schema).run(context.Background()); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("conflict", err)
	}
	if r := f.current(t); r.Revision != 1 || len(f.writes) != 1 {
		t.Fatal("changed after conflict", f.writes)
	}
	schema = &fakeReleaseSchema{state: postgres.SchemaState{Head: 81, Floor: 81}, planned: 81, failMigrate: true}
	if err := releaseTestChange(config, 2, 82, schema).run(context.Background()); err == nil || len(f.writes) != 1 {
		t.Fatal("migration failure", err, f.writes)
	}
	// A Deployment running an image the record does not name is refused.
	apiName, _ := kube.HubDeploymentNames(releaseTestInstallation)
	f.deployments[apiName].Spec.Template.Spec.Containers[0].Image = releaseTestImage(7)
	schema.failMigrate = false
	if err := releaseTestChange(config, 2, 82, schema).run(context.Background()); !errors.Is(err, cfg.ErrChanged) || len(f.writes) != 1 {
		t.Fatal("foreign image", err)
	}
}

func equalStrings(a, b []string) bool {
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}
