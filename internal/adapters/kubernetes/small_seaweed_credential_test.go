package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

const credentialOriginalUID = "10000000-0000-4000-8000-000000000001"
const credentialOtherUID = "10000000-0000-4000-8000-000000000002"
const credentialFile = "audit-storage.json"

// The fixture owns one originally allocated Secret and enforces its RV CAS.
// It can lose a reply after storage, or make a different actor win the CAS.
type seaweedCredentialFixture struct {
	mu            sync.Mutex
	secret        core.Secret
	reads, writes int
	mode          string
	cancel        context.CancelFunc
}

func (f *seaweedCredentialFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	status := func(code int, reason string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Code: int32(code), Reason: meta.StatusReason(reason)})
	}
	if r.URL.Path != "/api/v1/namespaces/hub/secrets/audit" {
		status(403, "Forbidden")
		return
	}
	switch r.Method {
	case http.MethodGet:
		f.reads++
		if f.mode == "cancel-read" {
			f.cancel()
		}
		_ = json.NewEncoder(w).Encode(f.secret)
	case http.MethodPut:
		f.writes++
		var proposed core.Secret
		if json.NewDecoder(r.Body).Decode(&proposed) != nil || proposed.UID != f.secret.UID || proposed.ResourceVersion != f.secret.ResourceVersion {
			status(409, "Conflict")
			return
		}
		if f.mode == "throttled" {
			w.Header().Set("Retry-After", "0")
			status(429, "TooManyRequests")
			return
		}
		if f.mode == "conflict" {
			f.secret.Data = credentialTestPayload(tSyntheticCredential())
			f.secret.ResourceVersion = "2"
			status(409, "Conflict")
			return
		}
		proposed.ResourceVersion = "2"
		f.secret = proposed
		switch f.mode {
		case "unknown":
			status(500, "InternalError")
		case "malformed":
			_, _ = w.Write([]byte("{"))
		case "changed-uid":
			f.secret.UID = types.UID(credentialOtherUID)
			status(500, "InternalError")
		case "foreign-data":
			f.secret.Data["foreign"] = []byte("synthetic")
			status(500, "InternalError")
		case "cancel-write":
			f.cancel()
			status(500, "InternalError")
		default:
			_ = json.NewEncoder(w).Encode(f.secret)
		}
	default:
		status(403, "Forbidden")
	}
}
func tSyntheticCredential() contracts.SeaweedCredential {
	return contracts.SeaweedCredential{Principal: contracts.SeaweedPrincipalKey{Purpose: "owner-audit", ScopeID: credentialOriginalUID}, AccessKeyID: "ASV" + strings.Repeat("a", 40), SecretAccessKey: strings.Repeat("b", 64)}
}
func credentialTestPayload(c contracts.SeaweedCredential) map[string][]byte {
	runtime, err := providerconfig.SeaweedRuntimeCredential(c)
	if err != nil {
		panic("invalid synthetic credential")
	}
	b, err := json.Marshal(runtime)
	if err != nil {
		panic("invalid synthetic wire")
	}
	return map[string][]byte{credentialFile: b}
}
func newSeaweedCredentialFixture(t *testing.T) (*seaweedCredentialFixture, *rest.Config) {
	t.Helper()
	f := &seaweedCredentialFixture{secret: core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "audit", Namespace: "hub", UID: types.UID(credentialOriginalUID), ResourceVersion: "1"}, Type: core.SecretTypeOpaque}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	return f, &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
}
func invokeSeaweedCredential(ctx context.Context, config *rest.Config) (contracts.SeaweedCredential, error) {
	return ReadOrInitializeSeaweedCredential(ctx, config, "hub", contracts.WorkerObjectReference{Name: "audit", UID: credentialOriginalUID}, credentialFile, tSyntheticCredential().Principal)
}
func credentialTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func TestSmallSeaweedCredentialOriginalFillAndStableReplay(t *testing.T) {
	f, config := newSeaweedCredentialFixture(t)
	ctx := credentialTestContext(t)
	first, err := invokeSeaweedCredential(ctx, config)
	if err != nil || providerconfig.ValidateSeaweedCredential(first) != nil {
		t.Fatal("first fill refused")
	}
	replay, err := invokeSeaweedCredential(ctx, config)
	if err != nil || replay != first {
		t.Fatal("replay replaced original credential")
	}
	if f.reads != 2 || f.writes != 1 || f.secret.ResourceVersion != "2" {
		t.Fatalf("unexpected requests read=%d write=%d", f.reads, f.writes)
	}
}
func TestSmallSeaweedCredentialReorderedWireRecoversOriginal(t *testing.T) {
	f, config := newSeaweedCredentialFixture(t)
	original := tSyntheticCredential()
	// Closed decoding validates shape independently of whitespace/key order.
	f.secret.Data = map[string][]byte{credentialFile: []byte(`{
  "sessionToken": "", "secretAccessKey": "` + original.SecretAccessKey + `",
  "accessKeyID": "` + original.AccessKeyID + `"
 }`)}
	got, err := invokeSeaweedCredential(credentialTestContext(t), config)
	if err != nil || got != original || f.reads != 1 || f.writes != 0 {
		t.Fatal("valid reordered original refused or rewritten")
	}
}

func TestSmallSeaweedCredentialUnknownFillRecoversOnlyExactCandidate(t *testing.T) {
	for _, mode := range []string{"unknown", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			f, config := newSeaweedCredentialFixture(t)
			f.mode = mode
			got, err := invokeSeaweedCredential(credentialTestContext(t), config)
			if err != nil || providerconfig.ValidateSeaweedCredential(got) != nil {
				t.Fatal("exact unknown fill refused")
			}
			if f.reads != 2 || f.writes != 1 {
				t.Fatalf("mutation repeated read=%d write=%d", f.reads, f.writes)
			}
			if string(f.secret.Data[credentialFile]) != string(credentialTestPayload(got)[credentialFile]) {
				t.Fatal("returned a speculative replacement")
			}
		})
	}
}
func TestSmallSeaweedCredentialConflictingFillDoesNotAdoptWinner(t *testing.T) {
	f, config := newSeaweedCredentialFixture(t)
	f.mode = "conflict"
	got, err := invokeSeaweedCredential(credentialTestContext(t), config)
	if err == nil || got != (contracts.SeaweedCredential{}) || f.writes != 1 || f.reads != 2 {
		t.Fatal("rejected write adopted concurrent material or retried")
	}
	// A later explicit call reads the protected original, without another mutation.
	winner, err := invokeSeaweedCredential(credentialTestContext(t), config)
	if err != nil || winner != tSyntheticCredential() || f.writes != 1 {
		t.Fatal("explicit recovery failed")
	}
}
func TestSmallSeaweedCredentialRefusesChangedOrCanceledFill(t *testing.T) {
	for _, mode := range []string{"changed-uid", "foreign-data", "throttled", "cancel-read", "cancel-write"} {
		t.Run(mode, func(t *testing.T) {
			f, config := newSeaweedCredentialFixture(t)
			f.mode = mode
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			f.cancel = cancel
			got, err := invokeSeaweedCredential(ctx, config)
			if err == nil || got != (contracts.SeaweedCredential{}) {
				t.Fatal("changed/canceled credential accepted")
			}
			if f.writes > 1 || f.reads > 2 || mode == "cancel-read" && f.writes != 0 {
				t.Fatalf("unexpected requests read=%d write=%d", f.reads, f.writes)
			}
		})
	}
}
func TestSmallSeaweedCredentialRefusesForeignPopulatedMaterial(t *testing.T) {
	for _, mode := range []string{"unknown-field", "session-token", "missing-field", "duplicate-field", "other-file", "other-uid", "immutable", "deleting"} {
		t.Run(mode, func(t *testing.T) {
			f, config := newSeaweedCredentialFixture(t)
			f.secret.Data = credentialTestPayload(tSyntheticCredential())
			b := string(f.secret.Data[credentialFile])
			switch mode {
			case "unknown-field":
				b = strings.TrimSuffix(b, "}") + `,"foreign":true}`
			case "session-token":
				b = strings.Replace(b, `"sessionToken":""`, `"sessionToken":"synthetic"`, 1)
			case "missing-field":
				b = strings.Replace(b, `,"sessionToken":""`, "", 1)
			case "duplicate-field":
				b = strings.TrimSuffix(b, "}") + `,"sessionToken":""}`
			case "other-file":
				f.secret.Data["other.json"] = []byte("synthetic")
			case "other-uid":
				f.secret.UID = types.UID(credentialOtherUID)
			case "immutable":
				v := true
				f.secret.Immutable = &v
			case "deleting":
				v := meta.Now()
				f.secret.DeletionTimestamp = &v
			}
			f.secret.Data[credentialFile] = []byte(b)
			got, err := invokeSeaweedCredential(credentialTestContext(t), config)
			if err == nil || got != (contracts.SeaweedCredential{}) || f.writes != 0 {
				t.Fatal("foreign original material accepted or mutated")
			}
		})
	}
}
func TestSmallSeaweedCredentialOriginalDeadlineAndAdminRefusal(t *testing.T) {
	f, config := newSeaweedCredentialFixture(t)
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for _, ctx := range []context.Context{context.Background(), expired} {
		if _, err := invokeSeaweedCredential(ctx, config); err == nil {
			t.Fatal("unbounded or expired context accepted")
		}
	}
	p := tSyntheticCredential().Principal
	p.Purpose = "admin"
	if _, err := ReadOrInitializeSeaweedCredential(credentialTestContext(t), config, "hub", contracts.WorkerObjectReference{Name: "audit", UID: credentialOriginalUID}, credentialFile, p); err == nil {
		t.Fatal("provider admin accepted")
	}
	if f.reads != 0 || f.writes != 0 {
		t.Fatal("invalid input reached API")
	}
}
