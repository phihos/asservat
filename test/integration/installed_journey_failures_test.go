package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// The S-02 exit failure-state slices (docs/implementation-status.md), each
// against the installed product, as the owned Keycloak user over MCP:
//
// Focus journey-store-failure:
//   - an object-store failure during an accepted capture ends the capture
//     Indeterminate/StorageOutcomeUnconfirmed with its charges retained;
//   - an exhausted workload context reserve refuses request_capture with
//     CapacityUnavailable, including once no capture is in flight.
//
// Focus journey-start-failure:
//   - a lost completion after regional custody commit never repeats collection
//     (ADR-223): one admission/execution/custody attempt, replay names the
//     original capture and its original deadline ends it Indeterminate;
//   - a key-service failure before the start leaves the capture Pending until
//     its original deadline marks it Indeterminate/DeadlineOutcomeUnconfirmed;
//     it never starts afterwards either.
//
// Faults touch only owned fixtures: one scoped bucket-policy statement, one
// exact completion-transition trigger and a network disconnect of the owned
// OpenBao dev container (never a stop: dev mode keeps all keys in memory).
// Nothing weakens authorization, custody or deadlines.

const installedStoreFaultSID = "DenyInstalledJourneyAttemptStore"

// installedStoreFaultPolicy adds one fixture-only Put denial for the regional
// evidence writer of this cluster, scoped to the exact attempt prefix. Every
// existing statement is preserved; acceptance audit (capture-intent/v1/...),
// reads, other principals and other attempts are unchanged.
func installedStoreFaultPolicy(original, bucket, cluster string, loc artifact.Location) (string, error) {
	if loc.Validate() != nil || loc.ClusterID != cluster || len(original) > 64<<10 || bucket == "" {
		return "", errors.New("invalid store fault scope")
	}
	var policy map[string]json.RawMessage
	var statements []map[string]json.RawMessage
	if json.Unmarshal([]byte(original), &policy) != nil || json.Unmarshal(policy["Statement"], &statements) != nil || len(statements) == 0 {
		return "", errors.New("invalid original store policy")
	}
	for _, statement := range statements {
		var sid string
		if json.Unmarshal(statement["Sid"], &sid) == nil && sid == installedStoreFaultSID {
			return "", errors.New("store fault already present")
		}
	}
	raw, _ := json.Marshal(map[string]any{
		"Sid": installedStoreFaultSID, "Effect": "Deny",
		"Principal": map[string]string{"AWS": "arn:aws:iam::000000000000:user/regional-evidence-" + cluster[:8]},
		// Two actions: the fixture store normalizes a single-element Action
		// array into a plain string, which would break the exact arm/restore
		// readback. The writer's store path uses neither tagging nor this
		// prefix while the fault is armed.
		"Action":   []string{"s3:PutObject", "s3:PutObjectTagging"},
		"Resource": "arn:aws:s3:::" + bucket + "/" + loc.Prefix() + "*",
	})
	var deny map[string]json.RawMessage
	_ = json.Unmarshal(raw, &deny)
	statements = append(statements, deny)
	policy["Statement"], _ = json.Marshal(statements)
	out, err := json.Marshal(policy)
	return string(out), err
}

// installedStoreWriteAccess probes one actual PutObject of the regional
// evidence writer. AccessDenied is the sole tolerated transition response;
// another authentication, TLS or transport failure never establishes the
// fault. The probe key is inside the denied attempt prefix, so an armed
// fault writes nothing.
func installedStoreWriteAccess(ctx context.Context, store *s3.Client, bucket, key string, denied bool) (bool, error) {
	_, err := store.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: strings.NewReader("store-fault-probe")})
	var failure smithy.APIError
	accessDenied := errors.As(err, &failure) && failure.ErrorCode() == "AccessDenied"
	if err != nil && !accessDenied {
		return false, err
	}
	return accessDenied == denied, nil
}

// installedFailureKMSContainer derives the owned OpenBao dev container and its
// docker network from the fixture's recorded S3 container identity.
func installedFailureKMSContainer(s3Container string) (network, container string, err error) {
	if !strings.HasPrefix(s3Container, "asservat-context-") || !strings.HasSuffix(s3Container, "-s3") {
		return "", "", errors.New("owned S3 container identity missing")
	}
	network = strings.TrimSuffix(s3Container, "-s3")
	return network, network + "-kms", nil
}

// installedFailureRun carries one failure focus' MCP session and its bounded
// preview/request/resolve/progress exchanges with the installed product.
type installedFailureRun struct {
	t       *testing.T
	ctx     context.Context
	admin   *pgxpool.Pool
	root    string
	cluster string
	session *sdk.ClientSession
	wire    *contracts.InvestigationContracts
	target  map[string]string
	keys    string
}

// --- Unit tests for the pure fault helpers (no fixture needed). ---

func TestInstalledStoreFaultPolicyKeepsOriginalScope(t *testing.T) {
	cluster := "10000000-0000-4000-8000-000000000004"
	loc := artifact.Location{ClusterID: cluster, ArtifactID: "10000000-0000-4000-8000-000000000002", AttemptID: "10000000-0000-4000-8000-000000000003"}
	original := installerEvidenceBucketPolicy("evidence")
	fault, err := installedStoreFaultPolicy(original, "evidence", cluster, loc)
	if err != nil {
		t.Fatal(err)
	}
	var want, got struct{ Statement []map[string]any }
	_ = json.Unmarshal([]byte(original), &want)
	_ = json.Unmarshal([]byte(fault), &got)
	if len(got.Statement) != len(want.Statement)+1 || !reflect.DeepEqual(got.Statement[:len(want.Statement)], want.Statement) {
		t.Fatal("original grants or denials changed")
	}
	deny := got.Statement[len(want.Statement)]
	if deny["Sid"] != installedStoreFaultSID || deny["Effect"] != "Deny" ||
		deny["Resource"] != "arn:aws:s3:::evidence/"+loc.Prefix()+"*" ||
		!reflect.DeepEqual(deny["Principal"], map[string]any{"AWS": "arn:aws:iam::000000000000:user/regional-evidence-" + cluster[:8]}) ||
		!reflect.DeepEqual(deny["Action"], []any{"s3:PutObject", "s3:PutObjectTagging"}) {
		t.Fatal("fault escaped the exact regional writer store scope", deny)
	}
	if _, err := installedStoreFaultPolicy(fault, "evidence", cluster, loc); err == nil {
		t.Fatal("rearmed an existing fault")
	}
	if _, err := installedStoreFaultPolicy(original, "evidence", cluster, artifact.Location{ClusterID: "10000000-0000-4000-8000-000000000009", ArtifactID: loc.ArtifactID, AttemptID: loc.AttemptID}); err == nil {
		// A location without the request's cluster never scopes a denial.
		t.Fatal("accepted a foreign cluster scope")
	}
	if _, err := installedStoreFaultPolicy(original, "evidence", cluster, artifact.Location{}); err == nil {
		t.Fatal("accepted an invalid location")
	}
}

func TestInstalledStoreProbeRequiresActualAccessDenied(t *testing.T) {
	for _, tc := range []struct {
		code             string
		denied, ok, fail bool
	}{
		{"AccessDenied", true, true, false},
		{"AccessDenied", false, false, false},
		{"InvalidAccessKeyId", true, false, true},
		{"ServiceUnavailable", true, false, true},
		{"", true, false, false}, // a successful Put never proves the denial
		{"", false, true, false},
	} {
		t.Run(fmt.Sprintf("%s/%s", map[bool]string{true: "denied", false: "allowed"}[tc.denied], tc.code), func(t *testing.T) {
			h := &http.Client{Transport: installedDeletionProbeTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPut || r.URL.Path != "/evidence/v1/exact-attempt/store-fault-probe" {
					t.Fatal("permission probe escaped the exact attempt store scope", r.Method, r.URL.Path)
				}
				if tc.code == "" {
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"ETag": {`"synthetic"`}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				}
				body := "<Error><Code>" + tc.code + "</Code><Message>synthetic</Message></Error>"
				return &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{"Content-Type": {"application/xml"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			store := s3.New(s3.Options{Region: "synthetic", BaseEndpoint: aws.String("https://synthetic.invalid"), UsePathStyle: true,
				Credentials: credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), HTTPClient: h, RetryMaxAttempts: 1})
			ok, err := installedStoreWriteAccess(t.Context(), store, "evidence", "v1/exact-attempt/store-fault-probe", tc.denied)
			if ok != tc.ok || (err != nil) != tc.fail {
				t.Fatal("wrong store denial qualification", ok, err)
			}
		})
	}
}

func TestInstalledFailureKMSContainerRequiresOwnedIdentity(t *testing.T) {
	network, container, err := installedFailureKMSContainer("asservat-context-abc123-s3")
	if err != nil || network != "asservat-context-abc123" || container != "asservat-context-abc123-kms" {
		t.Fatal("wrong fixture derivation", network, container, err)
	}
	for _, name := range []string{"", "asservat-context-abc123-kms", "other-context-abc-s3", "asservat-context-abc123", "asservat-context-abc123-s3-extra"} {
		if _, _, err := installedFailureKMSContainer(name); err == nil {
			t.Fatal("accepted an unowned fixture identity", name)
		}
	}
}
