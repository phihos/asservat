package kubernetes

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	authn "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type regionalSeaweedFixture struct {
	t                                           *testing.T
	plan                                        RegionalInstallPlan
	config                                      *rest.Config
	namespace                                   *core.Namespace
	secret                                      *core.Secret
	username, mode                              string
	secretGets, secretCreates, namespaceCreates int
	paths                                       []string
	after                                       func(string)
}

func newRegionalSeaweedFixture(t *testing.T) *regionalSeaweedFixture {
	t.Helper()
	now := time.Now()
	offer := contracts.RegionalOffer{Format: contracts.RegionalOfferFormat, InstallationID: ownerID(1), PermissionRootID: ownerID(2), IssuerEpoch: ownerID(3), Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64), Federation: contracts.RegionalHubEndpoint{Endpoint: "https://federation.invalid:443", ServerName: "federation.invalid", Roots: [][]byte{{1}}}, ConnectorIssuerRoots: [][]byte{{2}}, ConnectorBacking: []byte(`{}`), Owners: &contracts.RegionalContextOwners{}, KeyService: &contracts.RegionalWrapService{KeyID: "artifact"}, WorkKey: &contracts.APIContextWorkPublicKey{ID: "work-v1"}, EvidenceStore: &contracts.RegionalEvidenceStore{StoreID: ownerID(7)}}
	envelope := value.BootstrapEnvelope{BootstrapID: ownerID(4), Binding: value.PeerBinding{InstallationID: offer.InstallationID, ClusterID: ownerID(5), PeerID: ownerID(6), IssuerEpoch: offer.IssuerEpoch, Role: value.ConnectorPeer}, DeliveryProfile: "regional-installer", RequestDigest: artifact.Digest{1}, NotBefore: now.Add(-time.Second), NotAfter: now.Add(time.Minute), Secret: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	f := &regionalSeaweedFixture{t: t, plan: RegionalInstallPlan{Offer: offer, Bootstrap: envelope, Namespace: "asservat-region"}, username: "operator@example.org"}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	f.config = &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pemCertificate(server.Certificate().Raw)}}
	return f
}
func (f *regionalSeaweedFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	if f.after != nil {
		defer f.after(r.Method + " " + r.URL.Path)
	}
	w.Header().Set("Content-Type", "application/json")
	reply := func(v any) {
		if json.NewEncoder(w).Encode(v) != nil {
			f.t.Error("fixture response")
		}
	}
	fail := func(code int, reason string) {
		w.WriteHeader(code)
		reply(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Reason: meta.StatusReason(reason), Code: int32(code)})
	}
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
		reply(authn.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}, Status: authn.SelfSubjectReviewStatus{UserInfo: authn.UserInfo{Username: f.username}}})
	case r.URL.Path == "/api/v1/namespaces" && r.Method == http.MethodPost:
		f.namespaceCreates++
		if f.namespace != nil {
			fail(409, "AlreadyExists")
			return
		}
		var ns core.Namespace
		if json.NewDecoder(r.Body).Decode(&ns) != nil {
			f.t.Error("namespace body")
			fail(400, "BadRequest")
			return
		}
		ns.APIVersion, ns.Kind, ns.UID, ns.ResourceVersion = "v1", "Namespace", types.UID(ownerID(8)), "1"
		f.namespace = &ns
		reply(ns)
	case r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace && r.Method == http.MethodGet:
		if f.namespace == nil {
			fail(404, "NotFound")
			return
		}
		reply(f.namespace)
	case r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace+"/secrets/"+RegionalEvidence && r.Method == http.MethodGet:
		f.secretGets++
		if f.mode == "late-read" {
			<-r.Context().Done()
			return
		}
		if f.secret == nil {
			fail(404, "NotFound")
			return
		}
		reply(f.secret)
	case r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace+"/secrets" && r.Method == http.MethodPost:
		f.secretCreates++
		if f.secret != nil {
			fail(409, "AlreadyExists")
			return
		}
		var s core.Secret
		if json.NewDecoder(r.Body).Decode(&s) != nil {
			f.t.Error("secret body")
			fail(400, "BadRequest")
			return
		}
		s.APIVersion, s.Kind, s.Namespace, s.UID, s.ResourceVersion = "v1", "Secret", f.plan.Namespace, types.UID(ownerID(9)), "1"
		f.secret = &s
		switch f.mode {
		case "unknown-create", "changed-readback":
			if f.mode == "changed-readback" {
				f.secret.Data["evidence-storage.json"] = []byte("different")
			}
			fail(500, "InternalError")
		case "retry-after-create":
			w.Header().Set("Retry-After", "1")
			fail(429, "TooManyRequests")
		case "malformed-success":
			_, _ = w.Write([]byte(`{}`))
		default:
			reply(s)
		}
	default:
		f.t.Errorf("unexpected API %s %s", r.Method, r.URL.Path)
		fail(400, "BadRequest")
	}
}
func TestRegionalSeaweedPreparationPersistsOriginalPairAndReopens(t *testing.T) {
	for _, mode := range []string{"normal", "unknown-create", "malformed-success", "retry-after-create"} {
		t.Run(mode, func(t *testing.T) {
			f := newRegionalSeaweedFixture(t)
			f.mode = mode
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			evidence, history, err := PrepareRegionalSeaweedStorage(ctx, f.config, f.plan)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(evidence)
			defer clear(history)
			if f.secretCreates != 1 || f.secret == nil || len(f.secret.Data) != 2 || !bytes.Equal(evidence, f.secret.Data["evidence-storage.json"]) || !bytes.Equal(history, f.secret.Data[contracts.RegionalHistoryCredentialFile]) {
				t.Fatal("keys returned before original pair was persisted")
			}
			if len(f.paths) < 2 || !strings.Contains(f.paths[1], "GET ") || !strings.HasSuffix(f.paths[1], "/secrets/"+RegionalEvidence) {
				t.Fatal("original keys not read before generation/effects")
			}
			p := f.plan
			p.Evidence, p.History = evidence, history
			if !regionalSeaweedPlanValid(p) || !regionalSeaweedSecretMatches(f.secret, p, f.plan.Offer.InstallationID+"/"+f.plan.Bootstrap.Binding.ClusterID) {
				t.Fatal("stored pair differs from ordinary regional installer template")
			}
			raw, _ := json.Marshal(f.secret)
			again, other, err := PrepareRegionalSeaweedStorage(ctx, f.config, f.plan)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(again)
			defer clear(other)
			after, _ := json.Marshal(f.secret)
			if !bytes.Equal(evidence, again) || !bytes.Equal(history, other) || !bytes.Equal(raw, after) || f.secretCreates != 1 {
				t.Fatal("replay replaced retained keys")
			}
			if mode != "normal" && f.secretGets != 3 {
				t.Fatal("uncertain write not resolved by one exact read", f.secretGets)
			}
			// Consume the same object through the existing installer's template
			// stamper, independently of this preparer's own comparison helper.
			api, err := installerAPI(f.config)
			if err != nil {
				t.Fatal(err)
			}
			installed, err := ensureRegional(ctx, api.CoreV1().Secrets(p.Namespace), &core.Secret{
				ObjectMeta: meta.ObjectMeta{Name: RegionalEvidence}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true),
				Data: map[string][]byte{"evidence-storage.json": evidence, contracts.RegionalHistoryCredentialFile: history},
			}, p.Offer.InstallationID+"/"+p.Bootstrap.Binding.ClusterID)
			if err != nil || installed.UID != f.secret.UID || !bytes.Equal(installed.Data["evidence-storage.json"], evidence) || !bytes.Equal(installed.Data[contracts.RegionalHistoryCredentialFile], history) {
				t.Fatal("actual regional installer refused the original prepared carrier", err)
			}
		})
	}
}
func TestRegionalSeaweedPreparationRefusesForeignOrIncompleteOriginal(t *testing.T) {
	for _, mode := range []string{"marker", "digest", "missing-history", "missing-evidence", "nonimmutable", "extra-key", "owner", "same-key", "namespace-marker", "bad-plan", "changed-readback"} {
		t.Run(mode, func(t *testing.T) {
			f := newRegionalSeaweedFixture(t)
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			if mode == "changed-readback" {
				f.mode = mode
				if a, b, err := PrepareRegionalSeaweedStorage(ctx, f.config, f.plan); err == nil || a != nil || b != nil || f.secretCreates != 1 || f.secretGets != 2 {
					t.Fatal("changed uncertain winner adopted", err)
				}
				return
			}
			a, b, err := PrepareRegionalSeaweedStorage(ctx, f.config, f.plan)
			clear(a)
			clear(b)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "marker":
				f.secret.Annotations[regionalInstall] = "foreign"
			case "digest":
				f.secret.Annotations[regionalTemplate] = strings.Repeat("b", 64)
			case "missing-history":
				delete(f.secret.Data, contracts.RegionalHistoryCredentialFile)
			case "missing-evidence":
				delete(f.secret.Data, "evidence-storage.json")
			case "nonimmutable":
				f.secret.Immutable = nil
			case "extra-key":
				f.secret.Data["unknown"] = []byte("foreign")
			case "owner":
				f.secret.OwnerReferences = []meta.OwnerReference{{Name: "foreign"}}
			case "same-key":
				f.secret.Data[contracts.RegionalHistoryCredentialFile] = bytes.Clone(f.secret.Data["evidence-storage.json"])
			case "namespace-marker":
				f.namespace.Annotations[regionalInstall] = "foreign"
			case "bad-plan":
				f.plan.Offer.IssuerEpoch = ownerID(9)
			}
			original, _ := json.Marshal(f.secret)
			a, b, err = PrepareRegionalSeaweedStorage(ctx, f.config, f.plan)
			after, _ := json.Marshal(f.secret)
			if err == nil || a != nil || b != nil || f.secretCreates != 1 || !bytes.Equal(original, after) {
				t.Fatal("retained original adopted/rotated", err)
			}
		})
	}
}
func TestRegionalSeaweedPreparationUsesOriginalTimeAndAdministrator(t *testing.T) {
	for _, mode := range []string{"expired", "future", "canceled", "late-read", "connector-account", "other-account", "installer-account"} {
		t.Run(mode, func(t *testing.T) {
			f := newRegionalSeaweedFixture(t)
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			switch mode {
			case "expired":
				f.plan.Bootstrap.NotAfter = time.Now().Add(-time.Second)
				f.plan.Bootstrap.NotBefore = f.plan.Bootstrap.NotAfter.Add(-time.Minute)
			case "future":
				f.plan.Bootstrap.NotBefore = time.Now().Add(time.Minute)
				f.plan.Bootstrap.NotAfter = f.plan.Bootstrap.NotBefore.Add(time.Minute)
			case "canceled":
				end()
			case "late-read":
				f.mode = mode
				f.plan.Bootstrap.NotAfter = time.Now().Add(100 * time.Millisecond)
			case "connector-account":
				f.plan.AccountAdministrator = true
				f.username = "system:serviceaccount:" + f.plan.Namespace + ":" + RegionalAccount
			case "other-account":
				f.username = "system:serviceaccount:release:installer"
			case "installer-account":
				f.plan.AccountAdministrator = true
				f.username = "system:serviceaccount:release:installer"
			}
			a, b, err := PrepareRegionalSeaweedStorage(ctx, f.config, f.plan)
			defer clear(a)
			defer clear(b)
			if mode == "installer-account" {
				if err != nil || f.secretCreates != 1 {
					t.Fatal("explicit original installer account refused", err)
				}
				return
			}
			if err == nil || a != nil || b != nil || f.secretCreates != 0 || f.namespaceCreates != 0 {
				t.Fatal("expired/unprivileged caller reached effects", err)
			}
			if mode == "connector-account" && !errors.Is(err, cfg.ErrInvalid) {
				t.Fatal("connector account admitted as administrator")
			}
		})
	}
}

// Keep this helper's output private; the fake API only uses the public CA.
func pemCertificate(raw []byte) []byte {
	return []byte("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(raw) + "\n-----END CERTIFICATE-----\n")
}
