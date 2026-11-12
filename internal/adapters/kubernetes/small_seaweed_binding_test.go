package kubernetes

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type seaweedBindingFixture struct {
	mu                           sync.Mutex
	plan                         contracts.SmallSeaweedPlan
	state, iam                   *core.Secret
	pvc                          *core.PersistentVolumeClaim
	binding                      *core.ConfigMap
	createUnknown, updateUnknown bool
	malformed                    bool
	afterUnknown                 func()
	gets, creates, updates       int
}

func (f *seaweedBindingFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	status := func(code int, reason string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Code: int32(code), Reason: meta.StatusReason(reason)})
	}
	if r.Method == http.MethodGet {
		f.gets++
		switch {
		case strings.HasSuffix(r.URL.Path, "/secrets/"+f.state.Name):
			_ = json.NewEncoder(w).Encode(f.state)
		case strings.HasSuffix(r.URL.Path, "/secrets/"+f.iam.Name):
			_ = json.NewEncoder(w).Encode(f.iam)
		case strings.HasSuffix(r.URL.Path, "/persistentvolumeclaims/"+f.pvc.Name):
			_ = json.NewEncoder(w).Encode(f.pvc)
		case strings.HasSuffix(r.URL.Path, "/configmaps/"+f.plan.ServiceName()+"-binding"):
			if f.binding == nil {
				status(404, "NotFound")
			} else {
				_ = json.NewEncoder(w).Encode(f.binding)
			}
		default:
			status(403, "Forbidden")
		}
		return
	}
	if !strings.Contains(r.URL.Path, "/configmaps") {
		status(403, "Forbidden")
		return
	}
	var cm core.ConfigMap
	if json.NewDecoder(r.Body).Decode(&cm) != nil {
		status(400, "BadRequest")
		return
	}
	if r.Method == http.MethodPost {
		f.creates++
		if f.binding != nil {
			status(409, "AlreadyExists")
			return
		}
		cm.UID = types.UID(swID("8"))
		cm.ResourceVersion = "1"
		f.binding = &cm
		if f.createUnknown {
			if f.afterUnknown != nil {
				f.afterUnknown()
			}
			if f.malformed {
				w.WriteHeader(200)
				_, _ = w.Write([]byte("{"))
			} else {
				status(500, "InternalError")
			}
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(f.binding)
		return
	}
	if r.Method == http.MethodPut {
		f.updates++
		if f.binding == nil || cm.UID != f.binding.UID || cm.ResourceVersion != f.binding.ResourceVersion {
			status(409, "Conflict")
			return
		}
		cm.ResourceVersion = "2"
		f.binding = &cm
		if f.updateUnknown {
			if f.afterUnknown != nil {
				f.afterUnknown()
			}
			if f.malformed {
				w.WriteHeader(200)
				_, _ = w.Write([]byte("{"))
			} else {
				status(500, "InternalError")
			}
			return
		}
		_ = json.NewEncoder(w).Encode(f.binding)
		return
	}
	status(403, "Forbidden")
}
func newSeaweedBindingFixture(t *testing.T) (*SmallSeaweedBinding, *seaweedBindingFixture, contracts.SmallSeaweedBindingRequest) {
	t.Helper()
	plan := smallSeaweedTestPlan()
	data, e := BuildSmallSeaweedMaterial(plan, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	admin, e := decodeSmallSeaweedAdmin(data[contracts.SmallSeaweedAdminKey])
	if e != nil {
		t.Fatal(e)
	}
	config, e := providerconfig.CompileSeaweedStorage(admin, nil)
	if e != nil {
		t.Fatal(e)
	}
	f := &seaweedBindingFixture{plan: plan, state: &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: plan.StateSecretName(), Namespace: plan.Namespace, UID: types.UID(swID("5")), ResourceVersion: "1", Labels: map[string]string{"asservat.io/private-role": "small-seaweed"}}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: data}}
	f.iam = &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: plan.IAMSecretName(), Namespace: plan.Namespace, UID: types.UID(swID("6")), ResourceVersion: "1", Labels: map[string]string{"asservat.io/private-role": "small-seaweed-iam"}, Annotations: map[string]string{smallSeaweedStateAnnotation: string(f.state.UID)}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{providerconfig.SeaweedConfigKey: config.Config}}
	f.pvc = &core.PersistentVolumeClaim{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"}, ObjectMeta: meta.ObjectMeta{Name: plan.DataPVCName(), Namespace: plan.Namespace, UID: types.UID(swID("7")), ResourceVersion: "1"}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		clearSmallSeaweedData(f.state.Data)
		clearSmallSeaweedData(f.iam.Data)
	})
	service, e := NewSmallSeaweedBinding(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, plan)
	if e != nil {
		t.Fatal(e)
	}
	return service, f, contracts.SmallSeaweedBindingRequest{InstallationID: swID("1"), RequestID: swID("2"), Bucket: "audit", StorageUseUntil: time.Now().UTC().Add(time.Minute)}
}
func expandSeaweedBindingIAM(t *testing.T, f *seaweedBindingFixture) {
	t.Helper()
	admin, e := decodeSmallSeaweedAdmin(f.state.Data[contracts.SmallSeaweedAdminKey])
	if e != nil {
		t.Fatal(e)
	}
	ordinary, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "initial-audit", ScopeID: swID("1")})
	if e != nil {
		t.Fatal(e)
	}
	next, e := providerconfig.CompileSeaweedStorage(admin, []contracts.SeaweedGrant{{Credential: ordinary, InstallationID: swID("1"), Bucket: "audit"}})
	if e != nil {
		t.Fatal(e)
	}
	clear(f.iam.Data[providerconfig.SeaweedConfigKey])
	f.iam.Data[providerconfig.SeaweedConfigKey] = next.Config
}
func TestSmallSeaweedBindingOriginalIntentReadyAndReplay(t *testing.T) {
	s, f, request := newSeaweedBindingFixture(t)
	pending, prepared, e := s.Begin(t.Context(), request)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(prepared.RootsPEM)
	if !pending.Binding.Initialization.Pending || pending.Binding.Initialization.PVCUID != string(f.pvc.UID) || pending.Binding.Initialization.StateSecretUID != string(f.state.UID) || pending.Binding.IAMSecretUID != string(f.iam.UID) || prepared.State.UID != string(f.state.UID) || prepared.Admin.Principal.ScopeID != pending.Binding.Initialization.BackendID || !pending.Binding.StorageUseUntil.Equal(request.StorageUseUntil) {
		t.Fatal("caller IDs replaced or native source not derived")
	}
	raw := f.binding.Data[contracts.SmallSeaweedBindingFile]
	if strings.Contains(raw, prepared.Admin.AccessKeyID) || strings.Contains(raw, prepared.Admin.SecretAccessKey) || strings.Contains(raw, "ca.crt") || strings.Contains(raw, "administrator.json") {
		t.Fatal("private provider material entered binding")
	}
	if f.gets != 4 || f.creates != 1 || f.updates != 0 {
		t.Fatal("fresh binding exceeded exact native read/create set")
	}
	// Equivalent time-zone serialization preserves the same original instant.
	zoned := request
	zoned.StorageUseUntil = request.StorageUseUntil.In(time.FixedZone("same-instant", 3600))
	replayed, p, e := s.Begin(t.Context(), zoned)
	clear(p.RootsPEM)
	if e != nil || !replayed.Binding.StorageUseUntil.Equal(request.StorageUseUntil) || f.creates != 1 {
		t.Fatal("same deadline instant treated as a renewed/different request", e)
	}
	ready, e := s.MarkReady(t.Context(), pending)
	if e != nil || ready.Binding.Initialization.Pending || ready.ConfigMap != pending.ConfigMap || !ready.Binding.StorageUseUntil.Equal(request.StorageUseUntil) {
		t.Fatal("ready CAS changed original binding", e)
	}
	f.mu.Lock()
	expandSeaweedBindingIAM(t, f)
	before := f.binding.DeepCopy()
	f.mu.Unlock()
	replay, p, e := s.Begin(t.Context(), request)
	clear(p.RootsPEM)
	if e != nil || replay.Binding.Initialization.Pending || replay.ConfigMap != ready.ConfigMap || replay.ResourceVersion != ready.ResourceVersion || f.creates != 1 || f.updates != 1 || !sameSmallSeaweedData(map[string][]byte{"binding": []byte(before.Data[contracts.SmallSeaweedBindingFile])}, map[string][]byte{"binding": []byte(f.binding.Data[contracts.SmallSeaweedBindingFile])}) {
		t.Fatal("ready replay rewrote state or renewed bounds", e)
	}
	replay, e = s.MarkReady(t.Context(), pending)
	if e != nil || replay.Binding.Initialization.Pending || f.updates != 1 {
		t.Fatal("stale pending receipt did not acknowledge exact known ready", e)
	}
}
func TestSmallSeaweedBindingUnknownEffectsExactReadback(t *testing.T) {
	for _, mode := range []string{"create", "ready", "create-malformed", "ready-malformed", "changed-create", "changed-source", "late-ready"} {
		t.Run(mode, func(t *testing.T) {
			s, f, request := newSeaweedBindingFixture(t)
			var late atomic.Bool
			s.now = func() time.Time {
				if late.Load() {
					return request.StorageUseUntil
				}
				return time.Now()
			}
			if mode == "create" || mode == "changed-create" || mode == "create-malformed" {
				f.createUnknown = true
			}
			if mode == "create-malformed" || mode == "ready-malformed" {
				f.malformed = true
			}
			if mode == "changed-create" {
				f.afterUnknown = func() { f.binding.UID = types.UID("not-a-uuid") }
			}
			pending, p, e := s.Begin(t.Context(), request)
			clear(p.RootsPEM)
			if mode == "changed-create" {
				if e == nil || f.creates != 1 {
					t.Fatal("unknown create accepted changed readback")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}

			expectedGets := 4
			if f.createUnknown {
				expectedGets = 8
			}
			if f.gets != expectedGets || f.creates != 1 || f.updates != 0 {
				t.Fatal("unknown create did not use exactly one readback/current source set")
			}
			beforeReadyGets := f.gets
			f.updateUnknown = true
			if mode == "changed-source" {
				f.afterUnknown = func() { f.pvc.UID = types.UID(swID("9")) }
			}
			if mode == "late-ready" {
				f.afterUnknown = func() { late.Store(true) }
			}
			ready, e := s.MarkReady(t.Context(), pending)
			if mode == "changed-source" || mode == "late-ready" {
				if e == nil {
					t.Fatal("uncertain/changed/late ready acknowledged")
				}
			} else if e != nil || ready.Binding.Initialization.Pending || ready.ConfigMap != pending.ConfigMap || !ready.Binding.StorageUseUntil.Equal(request.StorageUseUntil) {
				t.Fatal("exact ready readback did not acknowledge original completion", e)
			}
			if f.creates != 1 || f.updates != 1 {
				t.Fatal("unknown effect retried mutation")
			}
			if f.gets > beforeReadyGets+8 {
				t.Fatal("unknown ready reply exceeded one readback/current source set")
			}
			if e == nil && f.gets != beforeReadyGets+8 {
				t.Fatal("known ready readback omitted current source proof")
			}
		})
	}
}
func TestSmallSeaweedBindingRefusesChangedParentSourceAndEarlyWriters(t *testing.T) {
	for _, mode := range []string{"writers-first", "writers-pending", "request", "installation", "bucket", "deadline", "pvc", "state", "iam", "record", "version", "unknown-field"} {
		t.Run(mode, func(t *testing.T) {
			s, f, request := newSeaweedBindingFixture(t)
			if mode == "writers-first" {
				expandSeaweedBindingIAM(t, f)
				_, p, e := s.Begin(t.Context(), request)
				clear(p.RootsPEM)
				if e == nil || f.creates != 0 {
					t.Fatal("first binding accepted pre-enabled writers")
				}
				return
			}
			pending, p, e := s.Begin(t.Context(), request)
			clear(p.RootsPEM)
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "writers-pending":
				expandSeaweedBindingIAM(t, f)
			case "request":
				request.RequestID = swID("9")
			case "installation":
				request.InstallationID = swID("9")
			case "bucket":
				request.Bucket = "other-audit"
			case "deadline":
				request.StorageUseUntil = request.StorageUseUntil.Add(time.Second)
			case "pvc":
				f.pvc.UID = types.UID(swID("9"))
			case "state":
				f.state.UID = types.UID(swID("9"))
			case "iam":
				f.iam.UID = types.UID(swID("9"))
			case "record":
				f.binding.UID = types.UID(swID("9"))
			case "version":
				f.binding.ResourceVersion = "99"
			case "unknown-field":
				var value map[string]any
				_ = json.Unmarshal([]byte(f.binding.Data[contracts.SmallSeaweedBindingFile]), &value)
				value["unknown"] = true
				raw, _ := json.Marshal(value)
				f.binding.Data[contracts.SmallSeaweedBindingFile] = string(raw)
			}
			if mode == "record" || mode == "version" {
				if _, e = s.MarkReady(t.Context(), pending); e == nil {
					t.Fatal("original receipt accepted changed record/CAS")
				}
			} else {
				_, p, e = s.Begin(t.Context(), request)
				clear(p.RootsPEM)
				if e == nil {
					t.Fatalf("changed original %s accepted", mode)
				}
			}
			if f.creates != 1 || f.updates != 0 {
				t.Fatal("refusal mutated original binding")
			}
		})
	}
}
