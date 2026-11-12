package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

const bundledInboxID = "10000000-0000-4000-8000-000000000001"
const bundledInboxUID = "10000000-0000-4000-8000-000000000002"

var bundledInboxDigest = strings.Repeat("a", 64)

func bundledInboxCandidate(marker string) map[string][]byte {
	b, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: "ASV" + strings.Repeat(marker, 40), SecretAccessKey: strings.Repeat(marker, 64)})
	return map[string][]byte{contracts.InstallerInboxPhase: []byte("3"), contracts.InstallerInboxAuditCredential: b}
}

type bundledInboxFixture struct {
	mu                  sync.Mutex
	secret              *core.Secret
	mode                string
	gets, creates, puts int
	cancel              context.CancelFunc
}

func (f *bundledInboxFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	status := func(code int, reason string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Code: int32(code), Reason: meta.StatusReason(reason), Message: "synthetic-private-error-marker"})
	}
	base := "/api/v1/namespaces/hub/secrets"
	if r.URL.Path != base && r.URL.Path != base+"/"+contracts.InstallerInboxName(bundledInboxID) {
		status(403, "Forbidden")
		return
	}
	switch r.Method {
	case http.MethodGet:
		f.gets++
		switch f.mode {
		case "get-unknown":
			status(500, "InternalError")
			return
		case "get-malformed":
			_, _ = w.Write([]byte("{"))
			return
		case "get-throttled":
			w.Header().Set("Retry-After", "0")
			status(429, "TooManyRequests")
			return
		}
		if f.mode == "cancel-get" {
			f.cancel()
		}
		if f.secret == nil {
			status(404, "NotFound")
			return
		}
		_ = json.NewEncoder(w).Encode(f.secret)
	case http.MethodPost:
		f.creates++
		var s core.Secret
		if json.NewDecoder(r.Body).Decode(&s) != nil {
			status(400, "BadRequest")
			return
		}
		if f.secret != nil {
			status(409, "AlreadyExists")
			return
		}
		s.UID = types.UID(bundledInboxUID)
		s.ResourceVersion = "1"
		f.secret = &s
		switch f.mode {
		case "create-winner":
			f.secret.Data = bundledInboxCandidate("b")
			status(409, "AlreadyExists")
		case "create-unknown":
			status(500, "InternalError")
		case "create-malformed":
			_, _ = w.Write([]byte("{"))
		case "create-absent":
			f.secret = nil
			status(500, "InternalError")
		case "cancel-create":
			f.cancel()
			status(500, "InternalError")
		default:
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(f.secret)
		}
	case http.MethodPut:
		f.puts++
		var s core.Secret
		if f.secret == nil || json.NewDecoder(r.Body).Decode(&s) != nil || s.UID != f.secret.UID || s.ResourceVersion != f.secret.ResourceVersion {
			status(409, "Conflict")
			return
		}
		before, after := maps.Clone(f.secret.Data), maps.Clone(s.Data)
		delete(before, contracts.InstallerInboxInspectionToken)
		delete(after, contracts.InstallerInboxInspectionToken)
		if !maps.EqualFunc(before, after, bytes.Equal) {
			status(403, "Forbidden")
			return
		}
		if f.mode == "put-denied" {
			status(403, "Forbidden")
			return
		}
		s.ResourceVersion = "2"
		f.secret = &s
		switch f.mode {
		case "put-unknown":
			status(500, "InternalError")
		case "put-malformed":
			_, _ = w.Write([]byte("{"))
		case "put-replaced":
			f.secret.UID = types.UID(bundledInboxID)
			status(500, "InternalError")
		case "put-storage-changed":
			f.secret.Data[contracts.InstallerInboxAuditCredential] = bundledInboxCandidate("b")[contracts.InstallerInboxAuditCredential]
			status(500, "InternalError")
		case "cancel-put":
			f.cancel()
			status(500, "InternalError")
		default:
			_ = json.NewEncoder(w).Encode(f.secret)
		}
	default:
		status(403, "Forbidden")
	}
}
func newBundledInboxFixture(t *testing.T) (*bundledInboxFixture, *rest.Config, context.Context) {
	t.Helper()
	f := &bundledInboxFixture{}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	f.cancel = cancel
	return f, &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, ctx
}
func readOrCreateTestBundledInbox(ctx context.Context, c *rest.Config, candidate map[string][]byte) (*core.Secret, error) {
	return ReadOrCreateBundledInstallerInbox(ctx, c, "hub", bundledInboxID, bundledInboxDigest, candidate)
}
func completeTestBundledInbox(ctx context.Context, c *rest.Config, s *core.Secret, token string) (*core.Secret, error) {
	return CompleteBundledInstallerInbox(ctx, c, "hub", bundledInboxID, bundledInboxDigest, s, []byte(token))
}
func TestBundledInstallerInboxStableWinnerAndTokenOnlyRefresh(t *testing.T) {
	f, c, ctx := newBundledInboxFixture(t)
	original, err := readOrCreateTestBundledInbox(ctx, c, bundledInboxCandidate("a"))
	if err != nil {
		t.Fatal("original create failed")
	}
	if _, present := original.Data[contracts.InstallerInboxInspectionToken]; present {
		t.Fatal("invented placeholder token")
	}
	if _, err := ReadInstallerInbox(ctx, c, "hub", bundledInboxID, 3); err == nil {
		t.Fatal("pending carrier became an ordinary consumable inbox")
	}
	// A later speculative key must never replace the acknowledged original.
	winner, err := readOrCreateTestBundledInbox(ctx, c, bundledInboxCandidate("b"))
	if err != nil || !maps.EqualFunc(winner.Data, original.Data, bytes.Equal) || f.creates != 1 {
		t.Fatal("stable carrier changed on replay")
	}
	completed, err := completeTestBundledInbox(ctx, c, winner, "s.actual-component-token")
	if err != nil || !bytes.Equal(completed.Data[contracts.InstallerInboxAuditCredential], original.Data[contracts.InstallerInboxAuditCredential]) {
		t.Fatal("token fill changed original credentials")
	}
	same, err := completeTestBundledInbox(ctx, c, completed, "s.actual-component-token")
	if err != nil || same.ResourceVersion != completed.ResourceVersion || f.puts != 1 {
		t.Fatal("same token repeated mutation")
	}
	refreshed, err := completeTestBundledInbox(ctx, c, same, "s.actual-refreshed-token")
	if err != nil || string(refreshed.Data[contracts.InstallerInboxInspectionToken]) != "s.actual-refreshed-token" || f.puts != 2 {
		t.Fatal("real expired-token refresh refused")
	}
	// Ordinary consumer becomes available only with a real inspection token.
	inbox, err := ReadInstallerInbox(ctx, c, "hub", bundledInboxID, 3)
	if err != nil || string(inbox.InspectionToken) != "s.actual-refreshed-token" {
		t.Fatal("existing consumer did not read completed original")
	}
}
func TestBundledInstallerInboxUnknownCreateReturnsOriginalWinnerOnce(t *testing.T) {
	for _, mode := range []string{"create-unknown", "create-malformed", "create-winner", "create-absent", "cancel-create", "cancel-get", "get-unknown", "get-malformed", "get-throttled"} {
		t.Run(mode, func(t *testing.T) {
			f, c, ctx := newBundledInboxFixture(t)
			f.mode = mode
			got, err := readOrCreateTestBundledInbox(ctx, c, bundledInboxCandidate("a"))
			success := mode == "create-unknown" || mode == "create-malformed" || mode == "create-winner"
			if (err == nil) != success || !success && got != nil {
				t.Fatal("unknown create reported wrong outcome")
			}
			if f.creates > 1 || f.gets > 2 {
				t.Fatal("unknown mutation/read automatically replayed")
			}
			if strings.HasPrefix(mode, "get-") && (f.creates != 0 || f.gets != 1) {
				t.Fatal("unknown initial GET fell back to creation or repeated")
			}
			if success && (f.creates != 1 || f.gets != 2 || got.UID != types.UID(bundledInboxUID)) {
				t.Fatal("winner did not come from exact lookup")
			}
			if mode == "create-winner" && !maps.EqualFunc(got.Data, bundledInboxCandidate("b"), bytes.Equal) {
				t.Fatal("speculative candidate replaced actual racing winner")
			}
		})
	}
}
func TestBundledInstallerInboxUnknownTokenCASRequiresOriginalBytes(t *testing.T) {
	for _, mode := range []string{"put-unknown", "put-malformed", "put-replaced", "put-storage-changed", "put-denied", "cancel-put"} {
		t.Run(mode, func(t *testing.T) {
			f, c, ctx := newBundledInboxFixture(t)
			original, err := readOrCreateTestBundledInbox(ctx, c, bundledInboxCandidate("a"))
			if err != nil {
				t.Fatal(err)
			}
			f.mode = mode
			got, err := completeTestBundledInbox(ctx, c, original, "s.real-token")
			success := mode == "put-unknown" || mode == "put-malformed"
			if (err == nil) != success || !success && got != nil || f.puts != 1 || f.gets > 3 {
				t.Fatal("unknown CAS adopted changes or replayed")
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-private-error-marker") {
				t.Fatal("provider error leaked")
			}
		})
	}
}
func TestBundledInstallerInboxRefusesChangedOriginalSource(t *testing.T) {
	for _, mode := range []string{"uid", "rv", "data", "digest", "role", "immutable", "deleting", "owner", "foreign-key", "keyset"} {
		t.Run(mode, func(t *testing.T) {
			f, c, ctx := newBundledInboxFixture(t)
			original, err := readOrCreateTestBundledInbox(ctx, c, bundledInboxCandidate("a"))
			if err != nil {
				t.Fatal(err)
			}
			candidate := bundledInboxCandidate("b")
			switch mode {
			case "uid":
				f.secret.UID = types.UID(bundledInboxID)
			case "rv":
				f.secret.ResourceVersion = "changed"
			case "data":
				f.secret.Data[contracts.InstallerInboxAuditCredential] = candidate[contracts.InstallerInboxAuditCredential]
			case "digest":
				f.secret.Annotations[BundledInstallerInboxRecipeAnnotation] = strings.Repeat("b", 64)
			case "role":
				f.secret.Labels["asservat.io/private-role"] = "external"
			case "immutable":
				f.secret.Immutable = ptr.To(true)
			case "deleting":
				v := meta.Now()
				f.secret.DeletionTimestamp = &v
			case "owner":
				f.secret.OwnerReferences = []meta.OwnerReference{{UID: types.UID(bundledInboxUID)}}
			case "foreign-key":
				f.secret.Data["foreign"] = []byte("forbidden")
			case "keyset":
				candidate[contracts.InstallerInboxDownloadEvidenceCredential] = candidate[contracts.InstallerInboxAuditCredential]
			}
			if mode == "keyset" {
				if _, err = readOrCreateTestBundledInbox(ctx, c, candidate); err == nil {
					t.Fatal("changed optional selection accepted")
				}
			} else {
				if _, err = completeTestBundledInbox(ctx, c, original, "s.real-token"); err == nil {
					t.Fatal("changed original accepted")
				}
			}
			if f.puts != 0 || f.creates != 1 {
				t.Fatal("changed source caused mutation")
			}
		})
	}
}
func TestBundledInstallerInboxRejectsUnboundedOrMalformedCandidateBeforeIO(t *testing.T) {
	for _, mode := range []string{"unbounded", "expired", "token", "phase", "missing-owner", "unknown", "partial-public", "partial-tls", "partial-cleanup", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			f, c, ctx := newBundledInboxFixture(t)
			candidate := bundledInboxCandidate("a")
			switch mode {
			case "unbounded":
				ctx = context.Background()
			case "expired":
				expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
				ctx = expired
			case "token":
				candidate[contracts.InstallerInboxInspectionToken] = []byte("fake")
			case "phase":
				candidate[contracts.InstallerInboxPhase] = []byte("1")
			case "missing-owner":
				delete(candidate, contracts.InstallerInboxAuditCredential)
			case "unknown":
				candidate["seal.key"] = []byte("forbidden")
			case "partial-public":
				candidate[contracts.OwnerPublicTLSCertificate] = []byte("synthetic")
			case "partial-tls":
				candidate[contracts.InstallerInboxKeyServiceTLSKey] = []byte("synthetic")
			case "partial-cleanup":
				candidate[contracts.InstallerInboxCleanupAuditCredential] = candidate[contracts.InstallerInboxAuditCredential]
			case "oversize":
				for _, key := range contracts.InstallerInboxPublicFiles() {
					candidate[key] = bytes.Repeat([]byte("x"), 64<<10+1)
				}
			}
			if s, err := readOrCreateTestBundledInbox(ctx, c, candidate); err == nil || s != nil || f.gets != 0 || f.creates != 0 {
				t.Fatal("invalid input reached provider")
			}
		})
	}
}
