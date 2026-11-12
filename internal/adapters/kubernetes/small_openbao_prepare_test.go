package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

const baoStateID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const baoPVCID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
const baoOtherID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

type smallBaoStateFixture struct {
	mu                                  sync.Mutex
	t                                   *testing.T
	plan                                contracts.SmallOpenBaoPlan
	state                               *core.Secret
	pvc                                 *meta.PartialObjectMetadata
	sts, pod                            bool
	unknownCreate, unknownPatch         bool
	malformedCreate, malformedPatch     bool
	gets, creates, patches, privateGets int
	after                               func(*http.Request)
}

func newSmallBaoStateFixture(t *testing.T) (*SmallOpenBaoPreparation, *smallBaoStateFixture) {
	t.Helper()
	f := &smallBaoStateFixture{t: t, plan: smallOpenBaoFixturePlan(t, time.Now())}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Finish fixture hooks before releasing the response to the client.
		response := httptest.NewRecorder()
		f.serve(response, r)
		for name, values := range response.Header() {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.Code)
		_, _ = w.Write(response.Body.Bytes())
	}))
	t.Cleanup(server.Close)
	s, err := NewSmallOpenBaoPreparation(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, f.plan)
	if err != nil {
		t.Fatal(err)
	}
	return s, f
}
func (f *smallBaoStateFixture) missing(w http.ResponseWriter) {
	http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`, 404)
}
func (f *smallBaoStateFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	defer func() {
		if f.after != nil {
			f.after(r)
		}
	}()
	metadata := func(m meta.ObjectMeta) {
		_ = json.NewEncoder(w).Encode(meta.PartialObjectMetadata{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: m})
	}
	if r.Method == http.MethodGet {
		f.gets++
		switch {
		case strings.Contains(r.URL.Path, "/persistentvolumeclaims/"):
			if f.pvc == nil {
				f.missing(w)
				return
			}
			_ = json.NewEncoder(w).Encode(f.pvc)
		case strings.Contains(r.URL.Path, "/statefulsets/"):
			if !f.sts {
				f.missing(w)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		case strings.Contains(r.URL.Path, "/pods/"):
			if !f.pod {
				f.missing(w)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			if f.state == nil {
				f.missing(w)
				return
			}
			if r.Header.Get("Accept") == capacityMetadataAccept {
				metadata(f.state.ObjectMeta)
			} else {
				f.privateGets++
				_ = json.NewEncoder(w).Encode(f.state)
			}
		}
		return
	}
	if r.Method == http.MethodPost {
		f.creates++
		if f.state != nil {
			f.t.Error("repeated create")
			w.WriteHeader(409)
			return
		}
		var v core.Secret
		if json.NewDecoder(r.Body).Decode(&v) != nil {
			f.t.Error("invalid secret create")
			w.WriteHeader(400)
			return
		}
		v.UID = types.UID(baoStateID)
		v.ResourceVersion = "1"
		f.state = v.DeepCopy()
		if f.unknownCreate {
			http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"InternalError","code":500}`, 500)
			return
		}
		w.WriteHeader(201)
		if f.malformedCreate {
			_, _ = w.Write([]byte(`{"kind":`))
			return
		}
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	if r.Method == http.MethodPatch {
		f.patches++
		var p struct {
			Metadata struct {
				UID             types.UID         `json:"uid"`
				ResourceVersion string            `json:"resourceVersion"`
				Annotations     map[string]string `json:"annotations"`
			} `json:"metadata"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&p) != nil || f.state == nil || p.Metadata.UID != f.state.UID || p.Metadata.ResourceVersion != f.state.ResourceVersion || len(p.Metadata.Annotations) != 1 || p.Metadata.Annotations[contracts.SmallOpenBaoReadyAnnotation] == "" || f.state.Annotations[contracts.SmallOpenBaoReadyAnnotation] != "" || r.Header.Get("Accept") != capacityMetadataAccept || r.Header.Get("Content-Type") != "application/merge-patch+json" {
			f.t.Error("non-metadata or non-CAS/monotonic patch")
			w.WriteHeader(409)
			return
		}
		f.state.Annotations[contracts.SmallOpenBaoReadyAnnotation] = p.Metadata.Annotations[contracts.SmallOpenBaoReadyAnnotation]
		f.state.ResourceVersion = "2"
		if f.unknownPatch {
			http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"InternalError","code":500}`, 500)
			return
		}
		if f.malformedPatch {
			_, _ = w.Write([]byte(`{"kind":`))
			return
		}
		metadata(f.state.ObjectMeta)
		return
	}
	f.t.Errorf("unexpected method %s", r.Method)
	w.WriteHeader(500)
}
func (f *smallBaoStateFixture) addPVC() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pvc = &meta.PartialObjectMetadata{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: meta.ObjectMeta{Name: f.plan.DataPVCName(), Namespace: f.plan.Namespace, UID: types.UID(baoPVCID), ResourceVersion: "pvc1"}}
}
func (f *smallBaoStateFixture) counts() (int, int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets, f.creates, f.patches, f.privateGets
}
func prepareSmallBao(t *testing.T, s *SmallOpenBaoPreparation) contracts.SmallOpenBaoPrepared {
	t.Helper()
	p, err := s.Prepare(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(p.RootsPEM) })
	return p
}
func readySmallBao(t *testing.T, s *SmallOpenBaoPreparation, f *smallBaoStateFixture, p contracts.SmallOpenBaoPrepared) {
	t.Helper()
	f.addPVC()
	ctx, end := context.WithTimeout(t.Context(), time.Minute)
	defer end()
	if _, err := s.MarkReady(ctx, p.State, p.BackendID); err != nil {
		t.Fatal(err)
	}
}

func TestSmallOpenBaoPrepareCreateReplayAndReadyLostReplies(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "acknowledged", true: "unknown"}[unknown], func(t *testing.T) {
			s, f := newSmallBaoStateFixture(t)
			f.unknownCreate = unknown
			f.unknownPatch = unknown
			first := prepareSmallBao(t, s)
			second := prepareSmallBao(t, s)
			if first.State != second.State || first.BackendID != second.BackendID || !bytes.Equal(first.RootsPEM, second.RootsPEM) || first.ReadyPVCUID != "" {
				t.Fatal("pending replay changed original public state")
			}
			f.mu.Lock()
			original := cloneSmallOpenBaoMaterial(f.state.Data)
			f.mu.Unlock()
			defer clearSmallOpenBaoMaterial(original)
			gets, creates, patches, private := f.counts()
			if creates != 1 || patches != 0 || gets != 8+map[bool]int{false: 0, true: 1}[unknown] {
				t.Fatalf("unexpected pending API counts: %d %d %d", gets, creates, patches)
			}
			readySmallBao(t, s, f, first)
			g2, _, p2, private2 := f.counts()
			if p2 != 1 || private2 != private || g2-gets != 3+map[bool]int{false: 0, true: 1}[unknown] {
				t.Fatal("ready did not use bounded metadata-only CAS")
			}
			readySmallBao(t, s, f, first)
			if _, _, p3, _ := f.counts(); p3 != 1 {
				t.Fatal("ready replay wrote again")
			}
			final := prepareSmallBao(t, s)
			if final.State != first.State || final.BackendID != first.BackendID || final.ReadyPVCUID != baoPVCID || !bytes.Equal(final.RootsPEM, first.RootsPEM) {
				t.Fatal("Ready changed original state")
			}
			f.mu.Lock()
			same := sameSmallSeaweedData(original, f.state.Data)
			f.mu.Unlock()
			if !same {
				t.Fatal("metadata acknowledgement changed private material")
			}
		})
	}
}
func TestSmallOpenBaoPrepareRefusesMissingOrSubstitutedRetainedState(t *testing.T) {
	for _, mode := range []string{"pvc", "statefulset", "pod", "ready-no-pvc", "ready-replaced-pvc", "foreign-state", "unknown-annotation", "unknown-material", "ready-marker", "backend-annotation"} {
		t.Run(mode, func(t *testing.T) {
			s, f := newSmallBaoStateFixture(t)
			p := prepareSmallBao(t, s)
			if strings.HasPrefix(mode, "ready-") {
				readySmallBao(t, s, f, p)
			}
			f.mu.Lock()
			switch mode {
			case "pvc":
				f.state = nil
				f.pvc = &meta.PartialObjectMetadata{}
			case "statefulset":
				f.state = nil
				f.sts = true
			case "pod":
				f.state = nil
				f.pod = true
			case "ready-no-pvc":
				f.pvc = nil
				f.sts = false
				f.pod = false
			case "ready-replaced-pvc":
				f.pvc.UID = types.UID(baoOtherID)
			case "foreign-state":
				f.state.Labels["asservat.io/private-role"] = "foreign"
			case "unknown-annotation":
				f.state.Annotations["foreign"] = "value"
			case "unknown-material":
				f.state.Data["unexpected"] = []byte("no")
			case "ready-marker":
				f.state.Annotations[contracts.SmallOpenBaoReadyAnnotation] = baoOtherID + "/" + baoPVCID
			case "backend-annotation":
				f.state.Annotations[contracts.SmallOpenBaoBackendAnnotation] = baoOtherID
			}
			f.mu.Unlock()
			_, c, pn, _ := f.counts()
			got, err := s.Prepare(t.Context())
			clear(got.RootsPEM)
			if err == nil {
				t.Fatal("retained loss/substitution accepted")
			}
			_, c2, p2, _ := f.counts()
			if c != c2 || pn != p2 {
				t.Fatal("refusal recreated/mutated state")
			}
		})
	}
}
func TestSmallOpenBaoReadyRefusesSubstitutionsAndPVCReplacementDuringCAS(t *testing.T) {
	for _, mode := range []string{"state-id", "backend-id", "pvc-absent", "pvc-after-patch", "pvc-after-unknown-patch", "ready-pvc"} {
		t.Run(mode, func(t *testing.T) {
			s, f := newSmallBaoStateFixture(t)
			p := prepareSmallBao(t, s)
			f.addPVC()
			switch mode {
			case "state-id":
				p.State.UID = baoOtherID
			case "backend-id":
				p.BackendID = baoOtherID
			case "pvc-absent":
				f.mu.Lock()
				f.pvc = nil
				f.mu.Unlock()
			case "pvc-after-patch", "pvc-after-unknown-patch":
				f.unknownPatch = mode == "pvc-after-unknown-patch"
				f.after = func(r *http.Request) {
					if r.Method == http.MethodPatch {
						f.pvc.UID = types.UID(baoOtherID)
					}
				}
			case "ready-pvc":
				readySmallBao(t, s, f, p)
				f.mu.Lock()
				f.pvc.UID = types.UID(baoOtherID)
				f.mu.Unlock()
			}
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			if _, err := s.MarkReady(ctx, p.State, p.BackendID); err == nil {
				t.Fatal("substituted state/PVC acknowledged")
			}
			if mode == "pvc-after-patch" || mode == "pvc-after-unknown-patch" {
				f.mu.Lock()
				original := f.state.Annotations[contracts.SmallOpenBaoReadyAnnotation]
				f.mu.Unlock()
				if original != p.BackendID+"/"+baoPVCID {
					t.Fatal("original Ready pin rewritten")
				}
				got, err := s.Prepare(t.Context())
				clear(got.RootsPEM)
				if err == nil {
					t.Fatal("replacement PVC escaped Ready refusal")
				}
			}
		})
	}
}
func TestSmallOpenBaoPreparationPreservesCancellationAndOriginalDeadline(t *testing.T) {
	for _, mode := range []string{"canceled", "late-state", "late-pvc", "late-sts", "late-create", "ready-unbounded", "ready-late-state", "ready-late-pvc", "ready-late-patch"} {
		t.Run(mode, func(t *testing.T) {
			s, f := newSmallBaoStateFixture(t)
			original := time.Now()
			var late atomic.Bool
			s.now = func() time.Time {
				if late.Load() {
					return original.Add(time.Minute)
				}
				return original
			}
			var p contracts.SmallOpenBaoPrepared
			if strings.HasPrefix(mode, "ready-") {
				p = prepareSmallBao(t, s)
				f.addPVC()
			}
			ctx, end := context.WithDeadline(t.Context(), original.Add(20*time.Second))
			defer end()
			if mode == "canceled" {
				end()
			}
			f.after = func(r *http.Request) {
				trigger := mode == "late-state" && strings.Contains(r.URL.Path, "/secrets/") || (mode == "late-pvc" || mode == "ready-late-pvc") && strings.Contains(r.URL.Path, "/persistentvolumeclaims/") || mode == "late-sts" && strings.Contains(r.URL.Path, "/statefulsets/") || mode == "late-create" && r.Method == http.MethodPost || mode == "ready-late-state" && strings.Contains(r.URL.Path, "/secrets/") || mode == "ready-late-patch" && r.Method == http.MethodPatch
				if trigger {
					late.Store(true)
				}
			}
			if mode == "late-create" {
				f.unknownCreate = true
			}
			if mode == "ready-late-patch" {
				f.unknownPatch = true
			}
			before, _, _, _ := f.counts()
			var err error
			if strings.HasPrefix(mode, "ready-") {
				if mode == "ready-unbounded" {
					ctx = t.Context()
				}
				_, err = s.MarkReady(ctx, p.State, p.BackendID)
			} else {
				got, e := s.Prepare(ctx)
				clear(got.RootsPEM)
				err = e
			}
			if err == nil {
				t.Fatal("expired/canceled preparation acknowledged")
			}
			gets, creates, patches, _ := f.counts()
			delta := gets - before
			want := map[string]int{"canceled": 0, "late-state": 1, "late-pvc": 2, "late-sts": 3, "late-create": 4, "ready-unbounded": 0, "ready-late-state": 1, "ready-late-pvc": 2, "ready-late-patch": 2}[mode]
			if delta != want {
				t.Fatalf("performed read after original bound: got %d want %d", delta, want)
			}
			if mode != "late-create" && !strings.HasPrefix(mode, "ready-") && creates != 0 || mode != "ready-late-patch" && patches != 0 {
				t.Fatal("unexpected late effect")
			}
		})
	}
}

// A successful HTTP status does not acknowledge an undecodable write result.
// One exact readback may recover only the original effect, never create again.
func TestSmallOpenBaoPrepareRecoversMalformedSuccessfulWriteOnce(t *testing.T) {
	for _, operation := range []string{"create", "ready"} {
		for _, changed := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/original", true: "/changed-readback"}[changed], func(t *testing.T) {
				s, f := newSmallBaoStateFixture(t)
				var prepared contracts.SmallOpenBaoPrepared
				if operation == "create" {
					f.malformedCreate = true
				} else {
					prepared = prepareSmallBao(t, s)
					f.addPVC()
					f.malformedPatch = true
				}
				if changed {
					f.after = func(r *http.Request) {
						if operation == "create" && r.Method == http.MethodPost {
							f.state.Data[contracts.SmallOpenBaoSealKey][0] ^= 1
						}
						if operation == "ready" && r.Method == http.MethodPatch {
							f.state.UID = types.UID(baoOtherID)
						}
					}
				}
				before, c, pn, private := f.counts()
				var err error
				if operation == "create" {
					var result contracts.SmallOpenBaoPrepared
					result, err = s.Prepare(t.Context())
					defer clear(result.RootsPEM)
					if !changed && (result.State.UID != baoStateID || result.BackendID == "" || len(result.RootsPEM) == 0) {
						t.Fatal("original state not recovered")
					}
				} else {
					ctx, end := context.WithTimeout(t.Context(), time.Minute)
					defer end()
					var result contracts.WorkerObjectReference
					result, err = s.MarkReady(ctx, prepared.State, prepared.BackendID)
					if !changed && result.UID != baoPVCID {
						t.Fatal("original Ready PVC not recovered")
					}
				}
				if (err != nil) != changed {
					t.Fatalf("malformed reply original recovery=%t, changed=%t", err == nil, changed)
				}
				gets, c2, p2, private2 := f.counts()
				wanted := 5
				if operation == "ready" {
					wanted = 4
					if changed {
						wanted = 3
					}
					if p2-pn != 1 || c2 != c || private2 != private {
						t.Fatal("Ready recovery reread private data or repeated mutation")
					}
				} else if c2-c != 1 || p2 != pn {
					t.Fatal("CREATE recovery repeated mutation")
				}
				if gets-before != wanted {
					t.Fatalf("readback was not exactly once: got %d GETs want %d", gets-before, wanted)
				}
			})
		}
	}
}
