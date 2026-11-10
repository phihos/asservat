package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	wire "asservat.local/asservat/api/v1alpha1"
	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type installedRetentionRead func(context.Context, string, any) (installedJourneyEnvelope, error)
type installedRetentionShorteningCheck func(cluster, caseID, artifactID string, expires time.Time, read installedRetentionRead)

type installedRetentionShortening struct {
	admin                                     *pgxpool.Pool
	hub, runner                               kubernetes.Interface
	providers                                 *initialRuntimeNativeProviders
	installation, root, hubCluster, namespace string
	diagnose                                  func()
}

// This starts after the real user has downloaded the artifact successfully.
// The sole input is a scoped administrator policy through the shipped CRD.
func (s installedRetentionShortening) qualify(t *testing.T, parent context.Context, cluster, caseID, artifactID string, expires time.Time, read installedRetentionRead) {
	t.Helper()
	ctx, cancel := context.WithDeadline(parent, installedJourneyEarlier(expires, time.Now().Add(90*time.Second)))
	defer cancel()
	defer func() {
		if t.Failed() {
			s.diagnose()
		}
	}()
	location := artifact.Location{ClusterID: cluster, ArtifactID: artifactID}
	var original, before value.Deadlines
	var sequence, checkpointBefore int64
	installedJourneyReadOnly(t, ctx, s.admin, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
SELECT a.id::text, a.anchor_at, a.expires_at, a.delete_by,
       a.effective_expires_at, a.effective_delete_by, a.retention_sequence
FROM context_case_locator l
JOIN custody_attempt a ON a.artifact_id=l.artifact_id AND a.cluster_id=l.cluster_id
JOIN context_writer_completion w ON w.attempt_id=a.id AND w.root_id=l.root_id AND w.capture_id=l.capture_id
WHERE l.root_id=$1 AND l.case_id=$2 AND l.artifact_id=$3 AND l.cluster_id=$4 AND a.state='stored_unpublished'`,
			s.root, caseID, artifactID, cluster).Scan(&location.AttemptID, &original.AnchorAt, &original.ExpiresAt, &original.DeleteBy, &before.ExpiresAt, &before.DeleteBy, &sequence); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT sequence FROM retention_source WHERE root_id=$1 AND cluster_id=$2 AND hub`, s.root, s.hubCluster).Scan(&checkpointBefore)
	})
	if location.Validate() != nil || !original.ValidRetained() || !original.ExpiresAt.Equal(expires) || !time.Now().Before(expires) ||
		!original.ExpiresAt.Equal(before.ExpiresAt) || !original.DeleteBy.Equal(before.DeleteBy) || sequence != 0 || checkpointBefore < 2 {
		t.Fatal("installed shortening: original published attempt is unavailable")
	}

	policy, budget := s.installPolicy(t, ctx, cluster)
	want := value.Deadlines{AnchorAt: original.AnchorAt, ExpiresAt: original.AnchorAt.Add(time.Second), DeleteBy: original.AnchorAt.Add(budget + time.Second)}
	if !want.ExpiresAt.Before(expires) || !want.DeleteBy.Before(original.DeleteBy) {
		t.Fatal("installed shortening: scoped fixture policy does not shorten both cutoffs")
	}
	checkpoint, decision, receipt := s.awaitDecision(t, ctx, location, original, want, policy)
	if checkpoint != checkpointBefore+1 {
		t.Fatal("installed shortening: expected the next hub checkpoint", checkpointBefore, checkpoint)
	}
	s.verifyReceipt(t, ctx, decision, receipt)
	ready, _ := installerHubRetentionReadyPolicyCount(t, ctx, s.hub, s.admin, s.namespace, s.installation, s.root, s.hubCluster, checkpoint, "", 2)
	if ready != checkpoint {
		t.Fatal("installed shortening: Ready projected a different checkpoint", ready, checkpoint)
	}
	reply, err := read(ctx, "get_case", map[string]string{"case_id": caseID})
	var refusal struct {
		Code string `json:"code"`
	}
	if err != nil || reply.Status != "error" || json.Unmarshal(reply.Data, &refusal) != nil || refusal.Code != "NotAvailable" || !time.Now().Before(expires) {
		t.Fatal("installed shortening: original case did not receive the expected refusal before its old cutoff", err, reply.Status, refusal.Code)
	}
	t.Log("installed shortening: policy lowered both effective cutoffs on the original anchor; the signed versioned lifecycle record was acknowledged, the source returned to Ready, and the case became unavailable before original expiry")
}

func (s installedRetentionShortening) installPolicy(t *testing.T, ctx context.Context, cluster string) (meta.ObjectMeta, time.Duration) {
	t.Helper()
	const name = "retention-shortening-qualification"
	path := "/apis/asservat.io/v1alpha1/namespaces/" + s.namespace + "/evidenceretentionpolicies"
	client := s.runner.CoreV1().RESTClient()
	baseline, err := client.Get().AbsPath(path + "/" + contracts.RetentionBaselineName(s.installation)).DoRaw(ctx)
	var policy struct {
		meta.TypeMeta `json:",inline"`
		Metadata      meta.ObjectMeta          `json:"metadata"`
		Spec          wire.RetentionPolicySpec `json:"spec"`
	}
	if err != nil || json.Unmarshal(baseline, &policy) != nil || policy.Spec.DeletionBudgetSeconds < 1 || len(policy.Spec.Rules) != 0 {
		t.Fatal("installed shortening: read protected baseline policy", err)
	}
	policy.Metadata = meta.ObjectMeta{Name: name, Namespace: s.namespace}
	policy.Spec.Scope = wire.RetentionScope{ClusterIDs: []string{cluster}}
	policy.Spec.Defaults.EvidenceSeconds = 1
	policy.Spec.Maxima.EvidenceSeconds = policy.Spec.DeletionBudgetSeconds + 1
	body, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.Post().AbsPath(path).Body(body).MaxRetries(0).DoRaw(ctx)
	var accepted struct {
		Metadata meta.ObjectMeta `json:"metadata"`
	}
	if err != nil || json.Unmarshal(created, &accepted) != nil || accepted.Metadata.Name != name || accepted.Metadata.UID == "" || accepted.Metadata.Generation < 1 {
		t.Fatal("installed shortening: administrator create of scoped retention policy", err)
	}
	return accepted.Metadata, time.Duration(policy.Spec.DeletionBudgetSeconds) * time.Second
}

func (s installedRetentionShortening) awaitDecision(t *testing.T, ctx context.Context, location artifact.Location, original, want value.Deadlines, policy meta.ObjectMeta) (int64, value.LifecycleDecision, audit.Receipt) {
	t.Helper()
	for {
		var id, checkpoint string
		var checkpointSequence int64
		var raw, digest, receiptRaw []byte
		var acknowledged, completed pgtype.Timestamptz
		var receiptCurrent bool
		var retained, effective value.Deadlines
		var sequence int64
		installedJourneyReadOnly(t, ctx, s.admin, func(tx pgx.Tx) error {
			err := tx.QueryRow(ctx, `
SELECT d.id::text, d.decision_json, d.decision_digest, d.audit_receipt_json, d.audit_acknowledged_at,
       c.id::text, c.sequence, j.completed_at,
       a.anchor_at, a.expires_at, a.delete_by, a.effective_expires_at, a.effective_delete_by, a.retention_sequence,
       coalesce(public.retention_lifecycle_receipt_current(d.root_id,d.id,d.audit_receipt_json),false)
FROM retention_decision d
JOIN retention_catchup_effect e ON e.decision_id=d.id AND e.attempt_id=d.attempt_id
JOIN retention_checkpoint c ON c.id=e.checkpoint_id AND c.root_id=d.root_id
JOIN retention_catchup j ON j.checkpoint_id=c.id
JOIN custody_attempt a ON a.id=d.attempt_id
WHERE d.root_id=$1 AND d.attempt_id=$2 AND d.sequence=1 AND c.cluster_id=$3`, s.root, location.AttemptID, s.hubCluster).
				Scan(&id, &raw, &digest, &receiptRaw, &acknowledged, &checkpoint, &checkpointSequence, &completed,
					&retained.AnchorAt, &retained.ExpiresAt, &retained.DeleteBy, &effective.ExpiresAt, &effective.DeleteBy, &sequence, &receiptCurrent)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		})
		if id != "" {
			effective.AnchorAt = retained.AnchorAt
			var decision value.LifecycleDecision
			if err := json.Unmarshal(raw, &decision); err != nil {
				t.Fatal("installed shortening: invalid retained lifecycle decision", err)
			}
			encoded, err := json.Marshal(decision)
			sum := sha256.Sum256(encoded)
			if sequence != 1 || !sameRetentionDeadlines(retained, original) || !sameRetentionDeadlines(effective, want) ||
				err != nil || !bytes.Equal(digest, sum[:]) || !decision.Valid() ||
				decision.ID != id || decision.RootID != s.root || decision.Location != location || decision.Sequence != sequence ||
				decision.PolicyRevision.UID != checkpoint || decision.PolicyRevision.Generation != checkpointSequence ||
				!sameRetentionDeadlines(decision.Previous, original) || !sameRetentionDeadlines(decision.Effective, want) ||
				!slices.ContainsFunc(decision.Policies, func(rule artifact.RetentionRule) bool {
					return rule.UID == string(policy.UID) && rule.Generation == policy.Generation
				}) {
				t.Fatal("installed shortening: retained effect or lifecycle decision differs from original attempt and exact policy cutoff")
			}
			if completed.Valid && acknowledged.Valid {
				var receipt audit.Receipt
				if !receiptCurrent || json.Unmarshal(receiptRaw, &receipt) != nil || !receipt.ValidLifecycle(s.root, id) {
					t.Fatal("installed shortening: missing exact versioned receipt after acknowledgement")
				}
				return checkpointSequence, decision, receipt
			}
		}
		if err := installedJourneyPause(ctx, time.Second); err != nil {
			t.Fatalf("installed shortening: lifecycle catch-up did not finish (effect=%t completed=%t acknowledged=%t): %v", id != "", completed.Valid, acknowledged.Valid, err)
		}
	}
}

func sameRetentionDeadlines(a, b value.Deadlines) bool {
	return a.AnchorAt.Equal(b.AnchorAt) && a.ExpiresAt.Equal(b.ExpiresAt) && a.DeleteBy.Equal(b.DeleteBy)
}

func (s installedRetentionShortening) verifyReceipt(t *testing.T, ctx context.Context, decision value.LifecycleDecision, receipt audit.Receipt) {
	t.Helper()
	projection, err := s.hub.CoreV1().Secrets(s.namespace).Get(ctx, contracts.CapacityRuntimeProjectionName(s.installation), meta.GetOptions{})
	if err != nil {
		t.Fatal("installed shortening: protected signing pins unavailable", err)
	}
	deployment, err := contracts.DecodeCapacityDeployment(bytes.NewReader(projection.Data[contracts.CapacityDeploymentFile]))
	if err != nil || deployment.InstallationID != s.installation || deployment.PermissionRootID != s.root || deployment.ContextDeletion == nil {
		t.Fatal("installed shortening: protected signer does not bind the installation", err)
	}
	pin := deployment.ContextDeletion.Signing
	public := map[string]ed25519.PublicKey{pin.KeyID: pin.PublicKeys[pin.KeyID]}
	verifier, err := jose.NewLifecycleSignatures(s.root, "", nil, public)
	if err != nil {
		t.Fatal("installed shortening: pinned public signature verifier", err)
	}
	p := s.providers
	store := s3.New(s3.Options{Region: p.desired.AuditStore.Region, BaseEndpoint: aws.String(p.desired.AuditStore.Endpoint), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: p.client, RetryMaxAttempts: 1})
	object, err := store.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(p.desired.AuditStore.Bucket), Key: &receipt.Key, VersionId: &receipt.Version, IfMatch: &receipt.ETag})
	if err != nil {
		t.Fatal("installed shortening: acknowledged lifecycle version unavailable", err)
	}
	defer object.Body.Close()
	ciphertext, err := io.ReadAll(io.LimitReader(object.Body, receipt.Bytes+1))
	if err != nil || int64(len(ciphertext)) != receipt.Bytes || aws.ToString(object.VersionId) != receipt.Version ||
		aws.ToString(object.ETag) != receipt.ETag || sha256.Sum256(ciphertext) != receipt.SHA256 {
		t.Fatal("installed shortening: lifecycle ciphertext differs from its acknowledged version", err)
	}
	key := p.desired.KeyService
	const policyName = "fixture-retention-lifecycle-decrypt"
	acl := fmt.Sprintf("path %q { capabilities = [\"update\"] }", key.AuditMount+"/decrypt/"+key.AuditKey)
	p.admin(t, ctx, http.MethodPost, "sys/policies/acl/"+policyName, map[string]string{"policy": acl}, http.StatusNoContent)
	raw := p.admin(t, ctx, http.MethodPost, "auth/token/create", map[string]any{"policies": []string{policyName}, "no_default_policy": true, "renewable": false, "ttl": "1m", "explicit_max_ttl": "1m"}, http.StatusOK)
	defer clear(raw)
	var token struct {
		Auth struct {
			Value string `json:"client_token"`
		} `json:"auth"`
	}
	if json.Unmarshal(raw, &token) != nil || token.Auth.Value == "" {
		t.Fatal("installed shortening: independent decrypt-only fixture credential unavailable")
	}
	opener, err := kms.NewOpener(p.endpoint, token.Auth.Value, key.AuditMount, key.AuditKey, p.client)
	if err != nil {
		t.Fatal("installed shortening: independent decrypt-only audit client", err)
	}
	defer opener.Close()
	if err := framed.VerifyLifecycle(ctx, opener, verifier, decision, ciphertext); err != nil {
		t.Fatal("installed shortening: acknowledged lifecycle record does not verify with the protected signing pin", err)
	}
}
