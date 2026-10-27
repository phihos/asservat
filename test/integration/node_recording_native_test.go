package integration

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// syntheticRecordingExpectation is an accepted-looking pcapng expectation for
// the connector path only (no SQL here; the SQL path has its own component
// test). Every value is synthetic.
func syntheticRecordingExpectation(t *testing.T, storeID string, pod *core.Pod, namespaceUID string, program []planvalue.BPFInstruction, duration time.Duration) artifact.ContextExpectation {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := artifact.Registration{Location: artifact.Location{ClusterID: uuid.NewString(), ArtifactID: uuid.NewString(), AttemptID: uuid.NewString()}, StoreID: storeID, AllocationID: uuid.NewString(),
		PoolRevision: 1, AllocationRevision: 1, NativeLimit: artifact.RecordingNativeLimit, AnchorAt: now, WriteUntil: now.Add(5 * time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(time.Hour + 5*time.Minute)}
	rec := &artifact.Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: []byte(`{"synthetic":true}`), DurationMillis: duration.Milliseconds(), MaxBytes: artifact.RecordingNativeLimit, Snaplen: artifact.RecordingSnaplen}
	if len(program) > 0 {
		f := &artifact.RecordingFilter{Expression: "tcp port 8080"}
		for _, ins := range program {
			f.Program = append(f.Program, artifact.FilterInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K})
		}
		rec.Filter = f
	}
	e := artifact.ContextExpectation{ExecutionClass: artifact.ContextAPIExecution, NativeType: artifact.PCAPNGArtifact, Recording: rec, Registration: r, CaseID: uuid.NewString(), OccurrenceID: uuid.NewString(),
		PodUID: string(pod.UID), Namespace: pod.Namespace, NamespaceUID: namespaceUID, WorkloadUID: string(pod.UID), CollectorVersion: "synthetic", CollectorImageDigest: artifact.Digest{1}, RecipeDigest: artifact.Digest{2}, PlanDigest: artifact.Digest{3},
		CaptureUID: uuid.NewString(), ActionID: "a0123456789abcdef01234567", DataClass: "metadata", PurposeRef: "synthetic",
		Audience:            []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://id.example.test", SubjectID: "maintainers", Role: "evidence-owner", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{4}, AssignmentID: uuid.NewString()}},
		RequestedAgeSeconds: 3600, MaximumAgeSeconds: 86400, DeletionBudgetSeconds: 300, RetentionRules: []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{5}}}, TriggeredAt: now}
	if err := e.Validate(); err != nil {
		t.Fatal("synthetic expectation", err)
	}
	return e
}

type nativeRecordingJournal struct{}

func (nativeRecordingJournal) AdvanceStreaming(context.Context, artifact.StreamingPlan, artifact.StreamingStep) (artifact.StreamingState, bool, error) {
	return artifact.StreamingState{}, false, artifact.ErrInvalid
}

// recordingEncryptedNative runs the connector holder against the real node
// collector and a real S3 store (SeaweedFS on the runner).
func recordingEncryptedNative(t *testing.T, ctx context.Context, admin *rest.Config, ch *delivery.NodeChannel, _ delivery.PacketSink, web *core.Pod, program []planvalue.BPFInstruction, s3url, work string, results map[string]any) {
	t.Helper()
	bridge := tlsBridge(t, s3url)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	bucket := "recording-native"
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	store, err := objectstore.New(bridge.URL, "us-east-1", bucket, creds, bridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	storeID := uuid.NewString()
	bound, err := store.ForCustody(storeID)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(raw)
	clear(raw)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	keys := authorityTestKeys{aead}
	pods, err := kube.NewAPIContextClient(admin)
	if err != nil {
		t.Fatal(err)
	}
	holder := bootstrap.NewConnectorRecordings(ch, pods, time.Now, func(line string) { t.Log(line) })
	ch.SetPacketSink(holder)
	k, err := kubernetes.NewForConfig(admin)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := k.CoreV1().Namespaces().Get(ctx, web.Namespace, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e := syntheticRecordingExpectation(t, storeID, web, string(ns.UID), program, 5*time.Second)
	producer, err := objectstore.NewArtifactProducer(bound, keys, nativeRecordingJournal{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := producer.Prepare(ctx, e, "")
	if err != nil {
		t.Fatal(err)
	}
	pin := artifact.PinnedPod{Namespace: web.Namespace, NamespaceUID: e.NamespaceUID, Name: web.Name, UID: string(web.UID)}
	if owner := web.OwnerReferences; len(owner) > 0 {
		pin.ControllerUID = string(owner[0].UID)
	}
	start := time.Now()
	queuedAt, err := holder.Prepare(prepared, e).StartRecording(ctx, pin, start, start.Add(5*time.Second))
	if err != nil {
		t.Fatal("start recording on the real node", err)
	}
	signed := fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(e)}
	var c evidence.RecordingCollection
	deadline := time.Now().Add(90 * time.Second)
	for {
		if c, err = holder.Collect(signed); err != nil {
			t.Fatal(err)
		}
		if c.State != evidence.RecordingPending || time.Now().After(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if c.State != evidence.RecordingStored || !c.Valid(e.Registration) {
		t.Fatalf("connector outcome %+v", c)
	}
	storedAfter := time.Since(start)
	verifier, err := objectstore.NewContextVerifier(bound, keys)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	verifier.WithStreamCheck(artifact.PCAPNGArtifact, func() objectstore.StreamCheck { checked++; return packets.NewHeadersCheck() })
	if err = verifier.VerifyContext(ctx, e, c.Completion.Copies); err != nil || checked != 1 {
		t.Fatal("verification with the headers-only recheck", err, checked)
	}
	source, err := verifier.OpenNative(ctx, e, c.Completion.Copies, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	meta := source.Metadata()
	var native []byte
	for offset := int64(0); ; {
		chunk, verified, err := source.ReadNext(ctx, offset, min(int64(1<<20), source.Metadata().Size-offset))
		if err != nil || !verified {
			t.Fatal(err)
		}
		native = append(native, chunk...)
		offset += int64(len(chunk))
		if offset == source.Metadata().Size {
			break
		}
	}
	path := filepath.Join(work, "encrypted.pcapng")
	if err = os.WriteFile(path, native, 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := packets.CheckHeadersOnly(bytes.NewReader(native))
	if err != nil || n == 0 || bytes.Contains(native, []byte(packetMarker)) || !strings.HasSuffix(meta.Filename, ".pcapng") {
		t.Fatalf("downloaded recording: %d packets, %v, filename %q", n, err, meta.Filename)
	}
	out := map[string]any{"packets": n, "nativeBytes": len(native), "ciphertextBytes": c.Completion.Copies[0].Bytes, "queueToStoredSeconds": storedAfter.Seconds(), "queuedAt": queuedAt, "filename": meta.Filename, "format": meta.Format}
	if lines, err := exec.CommandContext(ctx, "tshark", "-r", path, "-T", "fields", "-e", "tcp.port").Output(); err == nil {
		got := strings.Split(strings.TrimSpace(string(lines)), "\n")
		out["tsharkPackets"] = len(got)
		for _, l := range got {
			if !strings.Contains(l, "8080") {
				t.Fatalf("tshark packet outside port 8080: %q", l)
			}
		}
		if len(got) != n {
			t.Fatalf("tshark read %d packets, the verifier %d", len(got), n)
		}
	}
	results["packetEncrypted"] = out
}
