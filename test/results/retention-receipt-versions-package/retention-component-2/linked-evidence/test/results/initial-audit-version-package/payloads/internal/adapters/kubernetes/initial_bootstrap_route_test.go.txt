package kubernetes

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	admission "k8s.io/api/admissionregistration/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func bootstrapRoutePreludeFixture(t *testing.T) *bootstrapObserverFixture {
	t.Helper()
	f := newBootstrapObserverFixtureVersion(t, context.Background(), contracts.InitialBootstrapPassiveFormat)
	n := bootstrapNames(f.desired)
	base := "/api/v1/namespaces/" + f.desired.BootstrapNamespace
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet {
			return false
		}
		absent := r.URL.Path == "/api/v1/namespaces/"+f.desired.TargetNamespace || r.URL.Path == base+"/secrets/"+n.seed || r.URL.Path == base+"/configmaps/"+n.root || r.URL.Path == base+"/configmaps/"+n.projection || r.URL.Path == base+"/configmaps/"+n.copyMarker
		for _, name := range []string{n.private, n.sqlMaterial, n.providerMaterial, n.passiveHistory} {
			absent = absent || r.URL.Path == base+"/secrets/"+name
		}
		if strings.Contains(r.URL.Path, "/admissionregistration.k8s.io/") && !strings.HasSuffix(r.URL.Path, "/"+n.guard) {
			absent = true
		}
		if absent {
			if strings.Contains(r.URL.Path, "/secrets/") && r.Header.Get("Accept") != bootstrapPartialMetadataAccept {
				t.Error("private routing received full Secret negotiation")
			}
			bootstrapPassiveNotFound(w)
			return true
		}
		return false
	}
	return f
}
func TestInitialBootstrapRouterRecoversProtectedPreSeedVersion(t *testing.T) {
	f := bootstrapRoutePreludeFixture(t)
	requested := f.desired
	requested.Format = contracts.InitialBootstrapFormat // normal operator input, no format chore
	got, err := OpenInitialBootstrap(context.Background(), f.apiConfig, requested)
	if err != nil {
		t.Fatal("original protected pre-seed retry", err)
	}
	defer got.Close()
	if got.desired.Format != contracts.InitialBootstrapPassiveFormat || got.routedPrelude == nil || !equalJSON(*got.routedPrelude, f.state.Prelude) || got.seedUID != "" {
		t.Fatal("original format or public pins changed")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issues != 1 {
		t.Fatal("pre-seed routing did not independently prove native denial", f.issues)
	}
	for _, path := range f.paths {
		if path == "/api/v1/namespaces/"+f.desired.BootstrapNamespace+"/secrets" {
			t.Fatal("routing created a private seed")
		}
	}
}
func TestInitialBootstrapRouterDoesNotUpgradePartialPrelude(t *testing.T) {
	for _, failure := range []string{"missing-binding", "changed-policy", "known-root", "old-v1", "unknown-read"} {
		t.Run(failure, func(t *testing.T) {
			f := bootstrapRoutePreludeFixture(t)
			prior := f.extra
			n := bootstrapNames(f.desired)
			f.extra = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodGet {
					switch {
					case failure == "missing-binding" && strings.Contains(r.URL.Path, "/validatingadmissionpolicybindings/"+n.guard):
						bootstrapPassiveNotFound(w)
						return true
					case (failure == "changed-policy" || failure == "old-v1") && strings.Contains(r.URL.Path, "/validatingadmissionpolicies/"+n.guard):
						d := f.desired
						if failure == "old-v1" {
							d.Format = contracts.InitialBootstrapFormat
						}
						p, _, err := InitialBootstrapAdmission(d)
						if err != nil {
							t.Fatal(err)
						}
						p.UID = types.UID(f.state.Prelude.Guard.PolicyUID)
						p.ResourceVersion = "1"
						p.Generation = 1
						p.Status = admission.ValidatingAdmissionPolicyStatus{ObservedGeneration: 1, TypeChecking: &admission.TypeChecking{}}
						if failure == "changed-policy" {
							p.Spec.Validations[0].Expression = "true"
						}
						permissionReply(w, p)
						return true
					case failure == "known-root" && strings.HasSuffix(r.URL.Path, "/configmaps/"+n.root):
						permissionReply(w, meta.PartialObjectMetadata{})
						return true
					case failure == "unknown-read" && strings.HasSuffix(r.URL.Path, "/secrets/"+n.seed):
						http.Error(w, "unknown", 503)
						return true
					}
				}
				return prior(w, r)
			}
			got, err := OpenInitialBootstrap(context.Background(), f.apiConfig, f.desired)
			if got != nil {
				got.Close()
			}
			if err == nil {
				t.Fatal("partial/contradictory original prelude accepted")
			}
		})
	}
}
func TestInitialBootstrapRouterFreshRequiresWholeFixedAbsence(t *testing.T) {
	for _, occupied := range []string{"", "account", "binding", "anchor", "copy-marker", "private-copy", "target"} {
		t.Run(occupied, func(t *testing.T) {
			f := bootstrapRoutePreludeFixture(t)
			n := bootstrapNames(f.desired)
			nsPath := "/api/v1/namespaces/" + f.desired.BootstrapNamespace
			f.extra = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method != http.MethodGet || r.URL.Path == nsPath {
					return false
				}
				exists := (occupied == "account" && strings.HasSuffix(r.URL.Path, "/serviceaccounts/"+n.account)) || (occupied == "binding" && strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings/"+n.guard)) || (occupied == "anchor" && strings.HasSuffix(r.URL.Path, "/secrets/"+n.anchor)) || (occupied == "copy-marker" && strings.HasSuffix(r.URL.Path, "/configmaps/"+n.copyMarker)) || (occupied == "private-copy" && strings.HasSuffix(r.URL.Path, "/secrets/"+n.sqlMaterial)) || (occupied == "target" && r.URL.Path == "/api/v1/namespaces/"+f.desired.TargetNamespace)
				if exists {
					permissionReply(w, meta.PartialObjectMetadata{})
				} else {
					bootstrapPassiveNotFound(w)
				}
				return true
			}
			got, err := OpenInitialBootstrap(context.Background(), f.apiConfig, f.desired)
			if got != nil {
				defer got.Close()
			}
			if occupied != "" {
				if err == nil {
					t.Fatal("occupied fixed name interpreted as fresh")
				}
				return
			}
			if err != nil || got.desired.Format != contracts.InitialBootstrapVersionedAuditFormat || got.routedPrelude != nil {
				t.Fatal("fresh selection", err)
			}
			if f.issues != 0 {
				t.Fatal("absence routing acquired a token")
			}
		})
	}
}
func TestInitialBootstrapRouterSeedMetadataCannotFallback(t *testing.T) {
	for _, failure := range []string{"", "wrong-uid", "full-secret", "unknown-digest", "unsupported"} {
		t.Run(failure, func(t *testing.T) {
			f := bootstrapRoutePreludeFixture(t)
			prior := f.extra
			n := bootstrapNames(f.desired)
			metadataReads := 0
			f.extra = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets/"+n.seed) {
					metadataReads++
					if r.Header.Get("Accept") != bootstrapPartialMetadataAccept {
						t.Error("broad seed routing")
					}
					if failure == "unsupported" {
						http.Error(w, "unsupported", 406)
						return true
					}
					m := meta.PartialObjectMetadata{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: meta.ObjectMeta{Name: n.seed, Namespace: f.desired.BootstrapNamespace, UID: types.UID(f.state.SeedUID), ResourceVersion: "1", Annotations: map[string]string{initialBootstrapAnnotation: bootstrapDigest(f.desired)}}}
					if failure == "wrong-uid" {
						m.UID = "invalid"
					}
					if failure == "full-secret" {
						m.Kind = "Secret"
						m.APIVersion = "v1"
					}
					if failure == "unknown-digest" {
						m.Annotations[initialBootstrapAnnotation] = strings.Repeat("f", 64)
					}
					permissionReply(w, m)
					return true
				}
				return prior(w, r)
			}
			got, err := OpenInitialBootstrap(context.Background(), f.apiConfig, f.desired)
			if got != nil {
				defer got.Close()
			}
			if failure != "" {
				if err == nil {
					t.Fatal("invalid seed routing accepted")
				}
				return
			}
			if err != nil || got.seedUID != f.state.SeedUID || got.desired.Format != f.desired.Format || metadataReads != 1 {
				t.Fatal("lost CREATE replay changed original seed", err)
			}
		})
	}
}
func TestInitialBootstrapRouterRetainsParentDeadline(t *testing.T) {
	f := bootstrapRoutePreludeFixture(t)
	ctx, end := context.WithTimeout(context.Background(), time.Nanosecond)
	defer end()
	<-ctx.Done()
	got, err := OpenInitialBootstrap(ctx, f.apiConfig, f.desired)
	if got != nil {
		got.Close()
	}
	if err == nil {
		t.Fatal("expired routing revived")
	}
}
