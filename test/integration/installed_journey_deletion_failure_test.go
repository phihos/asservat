package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const installedDeletionFaultSID = "DenyInstalledJourneyAttemptInventory"

// Add one fixture-only denial without replacing any existing statement. Only
// inventory for this cleaner and this exact attempt is denied; public reads,
// the writer, audit, other attempts and the immutable credential are unchanged.
func installedDeletionFaultPolicy(original, bucket string, loc artifact.Location) (string, error) {
	if loc.Validate() != nil || len(original) > 64<<10 || bucket == "" {
		return "", errors.New("invalid deletion fault scope")
	}
	var policy map[string]json.RawMessage
	var statements []map[string]json.RawMessage
	if json.Unmarshal([]byte(original), &policy) != nil || json.Unmarshal(policy["Statement"], &statements) != nil || len(statements) == 0 {
		return "", errors.New("invalid original deletion policy")
	}
	for _, statement := range statements {
		var sid string
		if json.Unmarshal(statement["Sid"], &sid) == nil && sid == installedDeletionFaultSID {
			return "", errors.New("deletion fault already present")
		}
	}
	raw, _ := json.Marshal(map[string]any{
		"Sid": installedDeletionFaultSID, "Effect": "Deny",
		"Principal": map[string]string{"AWS": "arn:aws:iam::000000000000:user/evidence-delete"},
		"Action":    []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"},
		"Resource":  "arn:aws:s3:::" + bucket,
		"Condition": map[string]any{"StringLike": map[string]string{"s3:prefix": loc.Prefix()}},
	})
	var deny map[string]json.RawMessage
	_ = json.Unmarshal(raw, &deny)
	statements = append(statements, deny)
	policy["Statement"], _ = json.Marshal(statements)
	out, err := json.Marshal(policy)
	return string(out), err
}

func installedDeletionSamePolicy(a, b string) bool {
	var x, y any
	return json.Unmarshal([]byte(a), &x) == nil && json.Unmarshal([]byte(b), &y) == nil && reflect.DeepEqual(x, y)
}

type installedDeletionPolicyStore interface {
	GetBucketPolicy(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	PutBucketPolicy(context.Context, *s3.PutBucketPolicyInput, ...func(*s3.Options)) (*s3.PutBucketPolicyOutput, error)
}

type installedDeletionFault struct {
	store                    installedDeletionPolicyStore
	bucket, original, denied string
	attempted, restored      bool
}

func (f *installedDeletionFault) read(ctx context.Context) (string, error) {
	r, err := f.store.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &f.bucket})
	if err != nil {
		return "", err
	}
	if r == nil || r.Policy == nil || len(*r.Policy) > 64<<10 {
		return "", errors.New("deletion policy unavailable")
	}
	return *r.Policy, nil
}

func (f *installedDeletionFault) arm(ctx context.Context) error {
	f.attempted = true // An unknown reply still requires joined restoration.
	if _, err := f.store.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &f.bucket, Policy: &f.denied}); err != nil {
		return err
	}
	got, err := f.read(ctx)
	if err != nil || !installedDeletionSamePolicy(got, f.denied) {
		return errors.New("deletion fault policy was not observed")
	}
	return nil
}

func (f *installedDeletionFault) restore(ctx context.Context) error {
	if !f.attempted || f.restored {
		return nil
	}
	got, err := f.read(ctx)
	if err != nil {
		return err
	}
	if installedDeletionSamePolicy(got, f.original) {
		f.restored = true
		return nil
	}
	if !installedDeletionSamePolicy(got, f.denied) {
		return errors.New("refuse to overwrite an unrelated deletion policy change")
	}
	// This is a single exact restoration, not a retry of an uncertain mutation.
	// An uncertain reply is resolved by readback of the original policy.
	_, writeErr := f.store.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &f.bucket, Policy: &f.original})
	got, err = f.read(ctx)
	if err != nil || !installedDeletionSamePolicy(got, f.original) {
		return errors.Join(errors.New("original deletion policy restoration unconfirmed"), writeErr, err)
	}
	f.restored = true
	return nil
}

// Probe only reads. AccessDenied is the sole tolerated transition response;
// another authentication, TLS or transport failure never establishes the fault.
func installedDeletionInventoryAccess(ctx context.Context, store *s3.Client, bucket, prefix string, denied bool) (bool, error) {
	checks := []func() error{
		func() error {
			_, err := store.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &bucket, Prefix: &prefix, MaxKeys: aws.Int32(1)})
			return err
		},
		func() error {
			_, err := store.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &prefix, MaxKeys: aws.Int32(1)})
			return err
		},
		func() error {
			_, err := store.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket, Prefix: &prefix, MaxUploads: aws.Int32(1)})
			return err
		},
	}
	matched := true
	for _, check := range checks {
		err := check()
		var failure smithy.APIError
		accessDenied := errors.As(err, &failure) && failure.ErrorCode() == "AccessDenied"
		if err != nil && !accessDenied {
			return false, err
		}
		matched = matched && accessDenied == denied
	}
	return matched, nil
}

func installedDeletionWaitAccess(ctx context.Context, store *s3.Client, bucket, prefix string, denied bool) error {
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	for {
		ok, err := installedDeletionInventoryAccess(call, store, bucket, prefix, denied)
		if err != nil || ok {
			return err
		}
		if err := installedJourneyPause(call, 100*time.Millisecond); err != nil {
			return err
		}
	}
}

type installedDeletionState struct {
	Now, ExpiresAt, DeleteBy                    time.Time
	State, Allocation                           string
	Fence, Bytes, Objects, Full, Replay, Copies int64
	Lease                                       pgtype.Timestamptz
	Deleted, Checkpoint                         bool
	Receipts, Writer                            []byte
}

func readInstalledDeletionState(ctx context.Context, pool *pgxpool.Pool, root string, loc artifact.Location) (installedDeletionState, error) {
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var s installedDeletionState
	err := pool.QueryRow(call, `
SELECT clock_timestamp(), a.state, a.allocation_id::text, a.deletion_fence, a.lease_until,
       a.effective_expires_at, a.effective_delete_by, a.deleted_at IS NOT NULL, d.attempt_id IS NOT NULL,
       ca.charged_bytes-(SELECT coalesce(sum(x.reserved_bytes),0) FROM custody_attempt x WHERE x.allocation_id=a.allocation_id AND x.id<>a.id AND x.state<>'deleted'), ca.charged_objects-4*(SELECT count(*) FROM custody_attempt x WHERE x.allocation_id=a.allocation_id AND x.id<>a.id AND x.state<>'deleted'), cc.charged_full, cc.charged_replay,
       (SELECT count(*) FROM custody_copy cp WHERE cp.attempt_id=a.id AND cp.ciphertext_bytes IS NOT NULL),
       (SELECT jsonb_agg(jsonb_build_array(cp.role, cp.ciphertext_bytes, cp.ciphertext_sha256, cp.etag, cp.version_id) ORDER BY cp.role)
        FROM custody_copy cp WHERE cp.attempt_id=a.id), w.completion_digest
FROM custody_attempt a
JOIN context_writer_completion w ON w.attempt_id=a.id AND w.root_id=$1
JOIN custody_allocation ca ON ca.id=a.allocation_id
JOIN context_control_account cc ON cc.allocation_id=ca.id
LEFT JOIN context_deletion_checkpoint d ON d.attempt_id=a.id AND d.root_id=$1
WHERE a.id=$2 AND a.artifact_id=$3 AND a.cluster_id=$4`, root, loc.AttemptID, loc.ArtifactID, loc.ClusterID).Scan(
		&s.Now, &s.State, &s.Allocation, &s.Fence, &s.Lease, &s.ExpiresAt, &s.DeleteBy, &s.Deleted, &s.Checkpoint,
		&s.Bytes, &s.Objects, &s.Full, &s.Replay, &s.Copies, &s.Receipts, &s.Writer)
	return s, err
}

// Retain the first observed installed lease. A later retry may already exist
// when we observe its expiry; it must not reset the failed-lease checkpoint.
type installedDeletionFailure struct {
	Fence int64
	Until time.Time
}

func (f *installedDeletionFailure) observe(before, current installedDeletionState) (bool, error) {
	if current.Deleted || current.Checkpoint || current.Allocation != before.Allocation ||
		!current.ExpiresAt.Equal(before.ExpiresAt) || !current.DeleteBy.Equal(before.DeleteBy) ||
		current.Bytes != before.Bytes || current.Objects != before.Objects || current.Full != before.Full || current.Replay != before.Replay ||
		current.Copies != 4 || !bytes.Equal(current.Receipts, before.Receipts) || !bytes.Equal(current.Writer, before.Writer) ||
		current.State != "stored_unpublished" && current.State != "deleting" {
		return false, errors.New("failed cleanup changed the original obligation or released charges")
	}
	if current.State == "deleting" {
		if current.Now.Before(before.ExpiresAt) || current.Fence <= before.Fence || !current.Lease.Valid || current.Lease.InfinityModifier != pgtype.Finite || !current.Lease.Time.After(before.ExpiresAt) {
			return false, errors.New("installed cleanup lacks a finite post-expiry claim")
		}
		if f.Fence == 0 {
			f.Fence, f.Until = current.Fence, current.Lease.Time
		}
		if current.Fence < f.Fence || current.Fence == f.Fence && !current.Lease.Time.Equal(f.Until) {
			return false, errors.New("installed cleanup rewrote its original lease")
		}
	} else if f.Fence != 0 || current.Fence != before.Fence || current.Lease.Valid {
		return false, errors.New("installed cleanup lost its failed claim")
	}
	return f.Fence != 0 && !current.Now.Before(f.Until), nil
}

func TestInstalledDeletionFaultPolicyKeepsOriginalScope(t *testing.T) {
	loc := artifact.Location{ClusterID: "10000000-0000-4000-8000-000000000001", ArtifactID: "10000000-0000-4000-8000-000000000002", AttemptID: "10000000-0000-4000-8000-000000000003"}
	original := installerEvidenceBucketPolicy("evidence")
	fault, err := installedDeletionFaultPolicy(original, "evidence", loc)
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
	if deny["Effect"] != "Deny" || deny["Resource"] != "arn:aws:s3:::evidence" ||
		!reflect.DeepEqual(deny["Principal"], map[string]any{"AWS": "arn:aws:iam::000000000000:user/evidence-delete"}) ||
		!reflect.DeepEqual(deny["Condition"], map[string]any{"StringLike": map[string]any{"s3:prefix": loc.Prefix()}}) ||
		!reflect.DeepEqual(deny["Action"], []any{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"}) {
		t.Fatal("fault escaped the exact cleaner inventory scope")
	}
	if _, err := installedDeletionFaultPolicy(fault, "evidence", loc); err == nil {
		t.Fatal("rearmed an existing fault")
	}
}

type installedDeletionPolicyFake struct {
	policy  string
	unknown bool
	writes  int
}

func (s *installedDeletionPolicyFake) GetBucketPolicy(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	return &s3.GetBucketPolicyOutput{Policy: aws.String(s.policy)}, nil
}
func (s *installedDeletionPolicyFake) PutBucketPolicy(_ context.Context, in *s3.PutBucketPolicyInput, _ ...func(*s3.Options)) (*s3.PutBucketPolicyOutput, error) {
	s.policy, s.writes = *in.Policy, s.writes+1
	if s.unknown {
		return nil, errors.New("synthetic lost policy reply")
	}
	return &s3.PutBucketPolicyOutput{}, nil
}

func TestInstalledDeletionFaultRestoresUnknownMutation(t *testing.T) {
	s := &installedDeletionPolicyFake{policy: `{"original":true}`, unknown: true}
	f := installedDeletionFault{store: s, bucket: "evidence", original: s.policy, denied: `{"denied":true}`}
	if f.arm(t.Context()) == nil || !f.attempted {
		t.Fatal("unknown mutation lost restoration obligation")
	}
	if err := f.restore(t.Context()); err != nil || !f.restored || s.policy != f.original || s.writes != 2 {
		t.Fatal("exact restoration was not independently observed", err)
	}
	if err := f.restore(t.Context()); err != nil || s.writes != 2 {
		t.Fatal("replayed completed restoration", err)
	}
	f.restored, s.policy = false, `{"unrelated":true}`
	if err := f.restore(t.Context()); err == nil || s.writes != 2 {
		t.Fatal("overwrote an unrelated policy change")
	}
}

type installedDeletionProbeTransport func(*http.Request) (*http.Response, error)

func (f installedDeletionProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestInstalledDeletionProbeRequiresActualAccessDenied(t *testing.T) {
	for _, tc := range []struct {
		code             string
		denied, ok, fail bool
		calls, allowAt   int
	}{
		{"AccessDenied", true, true, false, 3, 0},
		{"AccessDenied", false, false, false, 3, 0},
		{"InvalidAccessKeyId", true, false, true, 1, 0},
		{"ServiceUnavailable", true, false, true, 1, 0},
		// Any one successful inventory operation invalidates the denial proof,
		// even when the other two return the expected AccessDenied response.
		{"AccessDenied", true, false, false, 3, 1},
		{"AccessDenied", true, false, false, 3, 2},
		{"AccessDenied", true, false, false, 3, 3},
	} {
		t.Run(fmt.Sprintf("%s/%s/allow%d", tc.code, map[bool]string{true: "denied", false: "restored"}[tc.denied], tc.allowAt), func(t *testing.T) {
			calls := 0
			h := &http.Client{Transport: installedDeletionProbeTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet || r.URL.Query().Get("prefix") != "v1/exact-attempt/" {
					t.Fatal("permission probe escaped the exact read-only prefix")
				}
				status := http.StatusForbidden
				body := "<Error><Code>" + tc.code + "</Code><Message>synthetic</Message></Error>"
				if calls == tc.allowAt {
					status = http.StatusOK
					root := "ListBucketResult"
					if r.URL.Query().Has("versions") {
						root = "ListVersionsResult"
					} else if r.URL.Query().Has("uploads") {
						root = "ListMultipartUploadsResult"
					}
					body = "<" + root + "><IsTruncated>false</IsTruncated></" + root + ">"
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/xml"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			store := s3.New(s3.Options{Region: "synthetic", BaseEndpoint: aws.String("https://synthetic.invalid"), UsePathStyle: true,
				Credentials: credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), HTTPClient: h, RetryMaxAttempts: 1})
			ok, err := installedDeletionInventoryAccess(t.Context(), store, "evidence", "v1/exact-attempt/", tc.denied)
			if ok != tc.ok || (err != nil) != tc.fail || calls != tc.calls {
				t.Fatal("wrong denial qualification", ok, err, calls)
			}
		})
	}
}

func TestInstalledDeletionFailureRequiresClaimAndOriginalLease(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	before := installedDeletionState{Now: now.Add(-time.Minute), ExpiresAt: now, DeleteBy: now.Add(time.Hour), State: "stored_unpublished", Allocation: "original", Bytes: 64, Objects: 4, Full: 1, Replay: 1, Copies: 4, Receipts: []byte("original receipts"), Writer: []byte("original completion")}
	f := installedDeletionFailure{}
	current := before
	current.Now = now.Add(time.Second)
	if done, err := f.observe(before, current); done || err != nil {
		t.Fatal("expiry alone proved a failed deletion", err)
	}
	current.State, current.Fence, current.Lease = "deleting", 1, pgtype.Timestamptz{Time: now.Add(30 * time.Second), Valid: true}
	if done, err := f.observe(before, current); done || err != nil {
		t.Fatal("live cleanup lease proved failure", err)
	}
	for _, change := range []func(*installedDeletionState){
		func(s *installedDeletionState) { s.Bytes-- }, func(s *installedDeletionState) { s.Checkpoint = true },
		func(s *installedDeletionState) { s.DeleteBy = s.DeleteBy.Add(time.Second) }, func(s *installedDeletionState) { s.Lease.Time = s.Lease.Time.Add(time.Second) },
		func(s *installedDeletionState) { s.Receipts = []byte("replacement") }, func(s *installedDeletionState) { s.Writer = []byte("replacement") },
	} {
		next := current
		change(&next)
		if _, err := f.observe(before, next); err == nil {
			t.Fatal("accepted a changed obligation")
		}
	}
	current.Now = f.Until
	current.Fence, current.Lease.Time = 2, now.Add(time.Minute)
	if done, err := f.observe(before, current); !done || err != nil || f.Fence != 1 || !f.Until.Equal(now.Add(30*time.Second)) {
		t.Fatal("a later retry reset the failed lease observation", err)
	}
}
