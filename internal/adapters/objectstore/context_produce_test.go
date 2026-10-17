package objectstore

import (
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type contextWriterTestKeys struct{}

func (contextWriterTestKeys) Seal(_ context.Context, key, aad []byte) (artifact.SealedKey, error) {
	return artifact.SealedKey{Reference: "synthetic/wrap", Ciphertext: base64.StdEncoding.EncodeToString(key)}, nil
}
func writerFixture(t *testing.T, h http.Handler) (evidence.StoredContextCloser, artifact.ContextExpectation, []byte) {
	t.Helper()
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	store, err := New(server.URL, "us-east-1", "fixture", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	id := func(n int) string { return fmt.Sprintf("10000000-0000-4000-8000-%012d", n) }
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := artifact.Digest{1}
	e := artifact.ContextExpectation{ExecutionClass: artifact.ContextAPIExecution, Registration: artifact.Registration{Location: artifact.Location{ClusterID: id(1), ArtifactID: id(2), AttemptID: id(3)}, StoreID: id(4), AllocationID: id(5), PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: now.Add(-time.Second), WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(119 * time.Second), DeleteBy: now.Add(179 * time.Second)}, CaseID: id(6), OccurrenceID: id(7), PodUID: id(8), Namespace: "synthetic", NamespaceUID: id(9), WorkloadUID: id(10), CollectorVersion: "synthetic", CollectorImageDigest: d, RecipeDigest: d, PlanDigest: d, CaptureUID: id(11), ActionID: "pod-status", DataClass: "metadata", PurposeRef: "synthetic", Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.invalid", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: id(12), BasisDigest: d}}, RequestedAgeSeconds: 120, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 60, RetentionRules: []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: d}}, TriggeredAt: now.Add(-time.Second)}
	bound, err := store.ForCustody(e.Registration.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewContextProducer(bound, contextWriterTestKeys{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := producer.PrepareContext(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handle.Close)
	native, err := json.Marshal(map[string]any{"format": artifact.ContextFormat, "namespaceUID": e.NamespaceUID, "podUID": e.PodUID, "resourceVersion": "1", "observedAt": now, "phase": "Pending", "ready": "Unknown", "initialized": "Unknown", "scheduled": "False", "runtimeInstances": 0, "running": 0, "waiting": 0, "terminated": 0, "restarts": 0})
	if err != nil {
		t.Fatal(err)
	}
	return handle.(evidence.StoredContextCloser), e, native
}
func TestContextWriterCompletionRequiresEveryPositiveReceipt(t *testing.T) {
	for fail := 0; fail <= 4; fail++ {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			var writes atomic.Int32
			handle, e, native := writerFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := writes.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				if r.Method != http.MethodPut || r.Header.Get("If-None-Match") != "*" {
					t.Error("unbounded or nonconditional writer")
				}
				if n == int32(fail) {
					w.WriteHeader(503)
					_, _ = w.Write([]byte("<Error><Code>SlowDown</Code></Error>"))
					return
				}
				w.Header().Set("ETag", fmt.Sprintf("\"synthetic-%d\"", n))
				w.WriteHeader(200)
			}))
			var doc struct{ ObservedAt time.Time }
			_ = json.Unmarshal(native, &doc)
			copies, err := handle.StoreContext(context.Background(), native, doc.ObservedAt, doc.ObservedAt)
			completion, closedErr := handle.CompleteStored()
			if fail > 0 {
				if err == nil || closedErr == nil {
					t.Fatal("partial or failed writes certified complete")
				}
				if writes.Load() != int32(fail) {
					t.Fatal("failed write retried")
				}
				return
			}
			if err != nil || closedErr != nil || !completion.Valid(e.Registration) || completion.Copies != copies || completion.ExpectationDigest != evidence.ContextExpectationDigest(e) || completion.RegistrationDigest != privacyapp.RegistrationDigest(e.Registration) || writes.Load() != 4 {
				t.Fatal("missing exact positive completion", err, closedErr)
			}
			if again, err := handle.CompleteStored(); err != nil || again != completion {
				t.Fatal("completion replay renewed original time", err)
			}
			if _, err := handle.StoreContext(context.Background(), native, doc.ObservedAt, doc.ObservedAt); err == nil || writes.Load() != 4 {
				t.Fatal("closed producer wrote again")
			}
		})
	}
}
func TestContextWriterCloseJoinsInFlightWrites(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var writes atomic.Int32
	handle, _, native := writerFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := writes.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if n == 1 {
			close(entered)
			<-release
		}
		w.Header().Set("ETag", "\"positive\"")
		w.WriteHeader(200)
	}))
	var doc struct{ ObservedAt time.Time }
	_ = json.Unmarshal(native, &doc)
	stored := make(chan error, 1)
	go func() {
		_, err := handle.StoreContext(context.Background(), native, doc.ObservedAt, doc.ObservedAt)
		stored <- err
	}()
	select {
	case <-entered:
	case err := <-stored:
		t.Fatal("writer failed before first PUT", err)
	case <-time.After(5 * time.Second):
		t.Fatal("writer never reached first PUT")
	}
	closed := make(chan error, 1)
	go func() { _, err := handle.CompleteStored(); closed <- err }()
	select {
	case err := <-closed:
		unblock()
		t.Fatal("close returned before writer finished", err)
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	if err := <-stored; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 4 {
		t.Fatal("missing writes")
	}
}
func TestUnusedContextHandleCannotCertifyCompletion(t *testing.T) {
	var writes atomic.Int32
	handle, _, _ := writerFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { writes.Add(1) }))
	if _, err := handle.CompleteStored(); err == nil || writes.Load() != 0 {
		t.Fatal("unused handle produced completion")
	}
}

func TestContextWriterUnknownFinalPutCannotCertifyCompletion(t *testing.T) {
	var writes atomic.Int32
	handle, _, native := writerFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := writes.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if n == 4 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		w.Header().Set("ETag", "\"positive\"")
		w.WriteHeader(http.StatusOK)
	}))
	var doc struct{ ObservedAt time.Time }
	_ = json.Unmarshal(native, &doc)
	if _, err := handle.StoreContext(context.Background(), native, doc.ObservedAt, doc.ObservedAt); err == nil {
		t.Fatal("lost final PUT response became successful store")
	}
	if _, err := handle.CompleteStored(); err == nil || writes.Load() != 4 {
		t.Fatal("unknown write outcome created completion or retried", err, writes.Load())
	}
}
