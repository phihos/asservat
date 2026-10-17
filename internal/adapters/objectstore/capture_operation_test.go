package objectstore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// The wrap port is explicitly synthetic; framing uses the actual Tink codec,
// and the producer performs its real conditional PUT/GET over loopback TLS.
func TestClosedCaptureWriterMaximumIdentityKeepsPositiveCompletion(t *testing.T) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	id := operationTestID
	actor := identity.Principal{Issuer: strings.Repeat("<", 2048), Subject: strings.Repeat("&", 256), ClientID: strings.Repeat("<", 256), Kind: identity.Human}
	c := value.CaptureIntent{RootID: id, CaptureID: id, CaseID: id, OccurrenceID: id, ArtifactID: id, AttemptID: id, Actor: actor, Target: authorization.Target{ClusterID: id, NamespaceUID: strings.Repeat("<", 64), WorkloadUID: strings.Repeat("&", 64), PodUID: strings.Repeat("<", 64)}, ScopeDigest: artifact.Digest{1}, SubmissionDigest: artifact.Digest{2}, ExpectationDigest: artifact.Digest{3}, PermissionEpoch: id, PermissionSequence: 1<<63 - 1, IdentityRevision: identity.Revision{UID: strings.Repeat("<", 64), Generation: 2147483647, Digest: artifact.Digest{4}}, CreatedAt: n, Deadline: n.Add(30 * time.Second), ExpiresAt: n.Add(time.Hour), DeleteBy: n.Add(2 * time.Hour), ReservedBytes: (16 << 20) - 1}
	p := value.OperationLifecyclePolicy{RootID: id, Lane: "capture", InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1 << 60, MetadataSlots: 1, BackupReservedBytes: 1<<63 - 1, WALReservedBytes: 1<<63 - 1, CleanupBudgetSeconds: 1, ProofWindowSeconds: 1, ValidUntil: n.Add(time.Hour), MaxPurgeLeases: 32, History: &value.OperationHistoryQualification{ID: id, Digest: artifact.Digest{3}, Layout: value.CaptureOperationHistoryLayout, MaximumRowFootprintBytes: 16 << 20, MaximumTransitionWALBytes: 64 << 20, BackupCopies: 64, WALCopies: 64}}
	in := value.OperationIntent{ID: id, RootID: id, TraceID: id, Name: value.CaptureOperationName, InputFormat: value.CaptureOperationInputFormat, MACVersion: strings.Repeat("<", 64), AccountVersion: strings.Repeat("&", 64), Actor: actor, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Hour), Capture: &c}
	var e error
	in, e = app.BindOperationLifecycle(in, p)
	if e != nil {
		t.Fatal(e)
	}
	expanded, e := json.Marshal(in)
	if e != nil || len(expanded) <= 32<<10 {
		t.Fatal("fixture does not reach legacy expansion cap", len(expanded), e)
	}
	var mu sync.Mutex
	stored := map[string][]byte{}
	puts, gets := 0, 0
	store := auditObjectStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("ETag", `"pinned"`)
		w.Header().Set("X-Amz-Version-Id", "v1")
		switch r.Method {
		case http.MethodPut:
			puts++
			if r.Header.Get("If-None-Match") != "*" {
				t.Error("missing immutable create condition")
			}
			if _, ok := stored[r.URL.Path]; ok {
				w.WriteHeader(412)
				return
			}
			b, e := io.ReadAll(io.LimitReader(r.Body, value.OperationCipherLimit+1))
			if e != nil || len(b) > value.OperationCipherLimit {
				t.Error("ciphertext backing exceeded", len(b), e)
				w.WriteHeader(400)
				return
			}
			stored[r.URL.Path] = b
		case http.MethodGet:
			gets++
			b, ok := stored[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.Write(b)
		default:
			t.Error("unexpected writer operation", r.Method)
			w.WriteHeader(400)
		}
	}))
	writer, e := NewClosedOperationAuditObjects(store, id, windowTestKeys{}, windowTestKeys{})
	if e != nil {
		t.Fatal(e)
	}
	intent, e := writer.CreateClosedOperationIntent(context.Background(), in)
	if e != nil || !intent.Valid(id, id, id, "intent", n, in.RequestUntil) || intent.RecordDigest == (artifact.Digest{}) {
		t.Fatal("max valid intent lost positive joined completion", e)
	}
	out := value.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", CaptureIDs: []string{id}, OutputDigest: artifact.Digest{1}, MetadataUntil: in.RequestUntil, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
	outcome, e := writer.CreateClosedOperationOutcome(context.Background(), out)
	if e != nil || !outcome.Valid(id, id, id, "outcome", n, in.WriteUntil) || outcome.RecordDigest == (artifact.Digest{}) || outcome.RecordDigest == intent.RecordDigest {
		t.Fatal("max valid outcome lost distinct positive completion", e)
	}
	mu.Lock()
	defer mu.Unlock()
	if puts != 2 || gets != 2 || len(stored) != 2 {
		t.Fatal("unexpected writer request ownership", puts, gets, len(stored))
	}
	var total int
	for _, b := range stored {
		total += len(b)
		if bytes.Contains(b, []byte(actor.Issuer)) {
			t.Fatal("unsealed actor in stored object")
		}
	}
	if total > 2*value.OperationCipherLimit {
		t.Fatal("pair exceeded original two-object backing", total)
	}
	t.Logf("maximum completed capture pair: legacy expansion=%d ciphertext total=%d bytes", len(expanded), total)
}
