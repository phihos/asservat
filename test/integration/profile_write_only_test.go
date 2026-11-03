package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/pprof/profile"
)

// Actual installed-style Write-only IAM, with an independent read-only
// publisher. Synthetic identity/keys; no admission or installed authority.
func TestCustodyProfileWriteOnlyWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run scripts/test-custody.py --run '^TestCustodyProfileWriteOnlyWithRealServices$'")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		S3        string `json:"s3"`
		Container string `json:"s3Container"`
	}
	if json.Unmarshal(raw, &f) != nil || f.S3 == "" || !strings.HasPrefix(f.Container, "asservat-custody-") || !strings.HasSuffix(f.Container, "-s3") {
		t.Fatal("owned S3 fixture unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	const bucket = "synthetic-profile-write-only"
	cluster := custodyID()
	shell := "s3.configure -user=administrator -access_key=synthetic-only -secret_key=synthetic-only-secret -actions=Admin,Read,Write,List -apply\n" +
		"s3.configure -user=profile-writer -access_key=profile-writer -secret_key=profile-writer-secret -actions=Write:" + bucket + "/v1/" + cluster + "/* -apply\n" +
		"s3.configure -user=profile-publisher -access_key=profile-publisher -secret_key=profile-publisher-secret -actions=Read:" + bucket + "/v1/" + cluster + "/* -apply\n"
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", f.Container, "/usr/bin/weed", "shell", "-master=localhost:9333", "-filer=localhost:8888")
	cmd.Stdin = strings.NewReader(shell)
	if out, err := cmd.CombinedOutput(); err != nil {
		clear(out)
		t.Fatal("owned IAM setup", err)
	}
	bridge := tlsBridge(t, f.S3)
	credential := func(role string) aws.CredentialsProvider {
		if role == "administrator" {
			return credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
		}
		return credentials.NewStaticCredentialsProvider(role, role+"-secret", "")
	}
	client := func(role string) *s3.Client {
		return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &bridge.URL, UsePathStyle: true, Credentials: credential(role), HTTPClient: bridge.Client(), RetryMaxAttempts: 1})
	}
	admin, writer := client("administrator"), client("profile-writer")
	if _, err = admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"DenyWriterDeletion","Effect":"Deny","Principal":{"AWS":"arn:aws:iam::000000000000:user/profile-writer"},"Action":["s3:DeleteObject","s3:DeleteObjectVersion"],"Resource":"arn:aws:s3:::` + bucket + `/*"}]}`
	if _, err = admin.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: aws.String(bucket), Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	store := func(role string) *objectstore.Store {
		s, err := objectstore.New(bridge.URL, "us-east-1", bucket, credential(role), bridge.Client())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	output, input := store("profile-writer"), store("profile-publisher")
	block, _ := aes.NewCipher(make([]byte, 32))
	aead, _ := cipher.NewGCM(block)
	keys := authorityTestKeys{aead}
	var native bytes.Buffer
	fn := &profile.Function{ID: 1, Name: "main.synthetic", Filename: "synthetic.go"}
	loc := &profile.Location{ID: 1, Line: []profile.Line{{Function: fn, Line: 3}}}
	sample := &profile.Profile{SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}}, PeriodType: &profile.ValueType{Type: "cpu", Unit: "nanoseconds"}, Period: 10000000, Sample: []*profile.Sample{{Location: []*profile.Location{loc}, Value: []int64{10000000}}}, Location: []*profile.Location{loc}, Function: []*profile.Function{fn}, DurationNanos: int64(10 * time.Second)}
	if err := sample.Write(&native); err != nil {
		t.Fatal(err)
	}
	check := diagnostics.NewPprofCheck()
	if err := check.Write(native.Bytes()); err != nil {
		t.Fatal("fixture profile", err)
	}
	if err := check.Close(); err != nil {
		t.Fatal("fixture profile", err)
	}
	var malformed bytes.Buffer
	gz := gzip.NewWriter(&malformed)
	_, _ = gz.Write([]byte{0x12, 0x02, 0x08, 0x07, 0x22, 0x02, 0x08, 0x00})
	_ = gz.Close()
	for _, mode := range []string{"generic-readback", "valid", "corrupt", "missing", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			e := writeOnlyProfileExpectation(cluster)
			bound, err := output.ForCustody(e.Registration.StoreID)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "generic-readback" {
				journal := &writeOnlyProfileJournal{}
				producer, err := objectstore.NewArtifactProducer(bound, keys, journal, time.Now)
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := producer.Prepare(ctx, e, custodyID())
				if err != nil {
					t.Fatal(err)
				}
				at := e.TriggeredAt.Add(time.Second)
				_, err = prepared.Store(ctx, bytes.NewReader(native.Bytes()), at, at.Add(time.Second))
				if !errors.Is(err, objectstore.ErrStorage) || journal.state.Receipt == nil || !journal.state.CompleteSpent || !journal.state.ReleasedAt.IsZero() {
					t.Fatal("generic readback or retained charge changed", err)
				}
				t.Log("generic producer still refuses write-only readback after acknowledged completion")
				return
			}
			prepared, err := objectstore.PrepareOneShotProfileArtifact(ctx, bound, keys, e, custodyID(), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			body := native.Bytes()
			if mode == "malformed" {
				body = malformed.Bytes()
			}
			at := e.TriggeredAt.Add(time.Second)
			copies, err := prepared.Store(ctx, bytes.NewReader(body), at, at.Add(time.Second))
			if err != nil {
				t.Fatal("default16MiB profile write-only Store", err)
			}
			if _, err = prepared.Store(ctx, bytes.NewReader(body), at, at.Add(time.Second)); err == nil {
				t.Fatal("one-use store repeated")
			}
			key := e.Registration.Location.Prefix() + artifact.Role(0)
			denied := func(err error) {
				var api smithy.APIError
				if !errors.As(err, &api) || api.ErrorCode() != "AccessDenied" {
					t.Fatal("expected real backend AccessDenied", err)
				}
			}
			got, err := writer.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: &key})
			if got != nil && got.Body != nil {
				got.Body.Close()
			}
			denied(err)
			_, err = writer.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: &key})
			denied(err)
			_, err = writer.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: &key})
			denied(err)

			if mode == "missing" {
				if _, err = admin.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: &key, VersionId: aws.String(copies[0].VersionID)}); err != nil {
					t.Fatal(err)
				}
			}
			read, err := input.ForCustody(e.Registration.StoreID)
			if err != nil {
				t.Fatal(err)
			}

			var damagedReads atomic.Int32
			if mode == "corrupt" {
				// Simulate a damaged pinned ciphertext response, retaining the actual
				// version/ETag/length. Publication must authenticate bytes, not trust IAM.
				upstream, _ := url.Parse(f.S3)
				proxy := httputil.NewSingleHostReverseProxy(upstream)
				proxy.Transport = &http.Transport{Proxy: nil}
				proxy.ModifyResponse = func(r *http.Response) error {
					if r.Request.Method == http.MethodGet && strings.HasSuffix(r.Request.URL.Path, "/"+key) && r.StatusCode == http.StatusPartialContent {
						data, err := io.ReadAll(r.Body)
						r.Body.Close()
						if err != nil {
							return err
						}
						if len(data) > 0 {
							data[len(data)/2] ^= 1
							damagedReads.Add(1)
						}
						r.Body = io.NopCloser(bytes.NewReader(data))
					}
					return nil
				}
				corrupt := httptest.NewTLSServer(proxy)
				defer corrupt.Close()
				damaged, err := objectstore.New(corrupt.URL, "us-east-1", bucket, credential("profile-publisher"), corrupt.Client())
				if err != nil {
					t.Fatal(err)
				}
				defer damaged.Close()
				read, err = damaged.ForCustody(e.Registration.StoreID)
				if err != nil {
					t.Fatal(err)
				}
			}
			verifier, err := objectstore.NewContextVerifier(read, keys)
			if err != nil {
				t.Fatal(err)
			}
			verifier.WithStreamCheck(artifact.PprofArtifact, func(artifact.ContextExpectation) objectstore.StreamCheck { return diagnostics.NewPprofCheck() })
			_, err = verifier.VerifyContext(ctx, e, copies)
			if (err == nil) != (mode == "valid") {
				t.Fatal("independent publisher verdict", mode, err)
			}
			if mode == "corrupt" && damagedReads.Load() != 1 {
				t.Fatal("ciphertext corruption was not exercised", damagedReads.Load())
			}
			if mode == "malformed" && !errors.Is(err, artifact.ErrIntegrity) {
				t.Fatal("profile semantic parser not reached", err)
			}
			t.Logf("default16MiB limit, %d native bytes: writer read/list/delete denied; publisher %s verdict accepted=%t", len(body), mode, err == nil)
		})
	}
}

func writeOnlyProfileExpectation(cluster string) artifact.ContextExpectation {
	now := time.Now().UTC().Truncate(time.Microsecond)
	at := now.Add(-20 * time.Second)
	d := artifact.Digest{1}
	return artifact.ContextExpectation{Profile: &artifact.GoProfileAcquisition{SourceRef: "synthetic-pprof", EndpointDigest: d, Type: "cpu", Mode: "interval", DurationMillis: 10000}, NativeType: artifact.PprofArtifact, ExecutionClass: artifact.ContextAPIExecution,
		Registration: artifact.Registration{Location: artifact.Location{ClusterID: cluster, ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: custodyID(), AllocationID: custodyID(), PoolRevision: 1, AllocationRevision: 1, NativeLimit: 16 << 20, AnchorAt: at, WriteUntil: now.Add(time.Minute), ExpiresAt: at.Add(1800 * time.Second), DeleteBy: at.Add(2400 * time.Second)},
		CaseID:       custodyID(), OccurrenceID: custodyID(), PodUID: "synthetic-pod", Namespace: "synthetic", NamespaceUID: "synthetic-namespace", WorkloadUID: "synthetic-workload", CollectorVersion: "synthetic", CollectorImageDigest: d, RecipeDigest: d, PlanDigest: d, CaptureUID: custodyID(), ActionID: "a0123456789abcdef01234567", DataClass: "raw", PurposeRef: "synthetic",
		Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.invalid", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: custodyID(), BasisDigest: d}}, RequestedAgeSeconds: 1800, MaximumAgeSeconds: 7200, DeletionBudgetSeconds: 600, RetentionRules: []artifact.RetentionRule{{UID: "retention", Generation: 1, Digest: d}}, TriggeredAt: at}
}

// The generic regression uses the durable transition contract in memory only;
// the production profile factory does not accept an injected journal.
type writeOnlyProfileJournal struct{ state artifact.StreamingState }

func (j *writeOnlyProfileJournal) AdvanceStreaming(_ context.Context, p artifact.StreamingPlan, s artifact.StreamingStep) (artifact.StreamingState, bool, error) {
	next, fresh, err := j.state.Advance(p, s)
	if err == nil {
		j.state = next
	}
	return next, fresh, err
}

var _ privacy.StreamingJournal = (*writeOnlyProfileJournal)(nil)
